"""
response.py — Layer 5: Block IP, Email Alert, Auto-Unblock
============================================================
Thực thi các hành động từ Layer 4 (Decision):

1. BLOCK IP trên Ubuntu:   iptables -A INPUT -s IP -j DROP
2. BLOCK IP trên Windows:  SSH → netsh advfirewall firewall add rule ...
3. EMAIL ALERT:            Gmail SMTP (TLS)
4. AUTO-UNBLOCK:           Sau 1 giờ → gỡ block + ghi log

v2.0 Improvements:
  - SSH Key-based authentication (thay vì hardcoded password)
  - Retry logic với exponential backoff
  - Critical email alert khi SSH fail
"""

import smtplib
import subprocess
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import (
    DRY_RUN,
    UNBLOCK_AFTER_SECONDS,
    WIN_SSH_HOST, WIN_SSH_PORT, WIN_SSH_USER, WIN_SSH_PASS, WIN_SSH_KEY_PATH,
    SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_RECIPIENTS,
)
from decision import ACTION_BLOCK, ACTION_BLOCK_EMAIL, ACTION_EMAIL_ONLY, ACTION_KILL_PROCESS
from logger_setup import setup_logger
from ssh_manager import SSHManager
from process_containment import ProcessContainment

logger = setup_logger("response")


class ResponseEngine:
    """Thực thi block/unblock/email actions."""

    def __init__(self):
        # Centralized SSH Manager với retry + error handling
        self._ssh_manager = SSHManager(
            host=WIN_SSH_HOST,
            port=WIN_SSH_PORT,
            username=WIN_SSH_USER,
            ssh_key_path=WIN_SSH_KEY_PATH,
            password=WIN_SSH_PASS,  # Fallback nếu key auth fail
            max_retries=3
        )
        
        # EDR: Process Containment module
        self._edr = ProcessContainment(self._ssh_manager)
        
        logger.info("ResponseEngine initialized with SSHManager (key-based auth) + EDR module")

    # ==============================================================
    # ENABLE WINDOWS FIREWALL
    # ==============================================================

    def enable_windows_firewall(self):
        """
        Public method: Bật Windows Firewall.
        Gọi từ bên ngoài để kích hoạt firewall Windows.
        """
        logger.info("Enabling Windows Firewall...")
        self._enable_windows_firewall()

    # ==============================================================
    # EXECUTE ACTIONS (từ Decision Engine)
    # ==============================================================

    def execute(self, actions, ip_state):
        """
        Thực thi danh sách actions.
        Cập nhật ip_state khi block thành công.
        """
        logger.info(f"[DEBUG] Response engine received {len(actions)} actions")
        
        for i, action in enumerate(actions):
            ip = action.target_ip
            logger.info(f"[DEBUG] Processing action {i+1}/{len(actions)}: {action.action_type} for {ip}")

            try:
                if action.action_type == ACTION_BLOCK:
                    logger.info(f"[DEBUG] Executing BLOCK action for {ip}")
                    self._do_block(ip, ip_state)

                elif action.action_type == ACTION_BLOCK_EMAIL:
                    logger.info(f"[DEBUG] Executing BLOCK_EMAIL action for {ip}")
                    self._do_block(ip, ip_state)
                    # EDR: Khi block IP, cũng kill processes liên quan
                    edr_result = self._do_process_containment(
                        ip, action.events, score=action.score
                    )
                    reason_with_edr = action.reason
                    if edr_result and edr_result["processes_killed"] > 0:
                        reason_with_edr += (
                            f" | EDR: Killed {edr_result['processes_killed']} "
                            f"malicious process(es)"
                        )
                    if edr_result and edr_result.get("processes_suspended", 0) > 0:
                        reason_with_edr += (
                            f" | EDR: Suspended {edr_result['processes_suspended']} "
                            f"process(es)"
                        )
                    if edr_result and edr_result.get("logoff_triggered"):
                        reason_with_edr += " | EDR: User logoff triggered"
                    if edr_result and edr_result.get("needs_manual"):
                        reason_with_edr += " | EDR: Manual escalation required"
                    if edr_result and edr_result.get("suspend_failed"):
                        reason_with_edr += " | EDR: Suspend failed -> fallback kill"
                    self._send_alert_email(ip, action.score, reason_with_edr)
                elif action.action_type == ACTION_KILL_PROCESS:
                    logger.info(f"[DEBUG] Executing KILL_PROCESS (EDR) action for {ip}")
                    edr_result = self._do_process_containment(
                        ip, action.events, score=action.score
                    )
                    if edr_result and (edr_result.get("needs_manual") or edr_result.get("suspend_failed")):
                        reason = "EDR escalation: manual intervention required"
                        if edr_result.get("manual_reason"):
                            reason += f" | {edr_result['manual_reason']}"
                        if edr_result.get("suspend_failed"):
                            reason += " | suspend failed -> fallback kill"
                        self._send_alert_email(ip, action.score, reason)

                elif action.action_type == ACTION_EMAIL_ONLY:
                    logger.info(f"[DEBUG] Executing EMAIL_ONLY action for {ip}")
                    self._send_alert_email(ip, action.score, action.reason)

            except Exception as e:
                logger.error(
                    f"Lỗi thực thi action {action.action_type}"
                    f" cho {ip}: {e}"
                )
                logger.error(f"[DEBUG] Exception details: {type(e).__name__}: {str(e)}", exc_info=True)

    # ==============================================================
    # PROCESS CONTAINMENT (EDR)
    # ==============================================================

    def _do_process_containment(self, ip, events=None, score=0):
        """
        EDR: Kill malicious processes trên Windows victim liên quan đến attacker IP.
        
        Workflow:
          1. Liệt kê processes đang chạy trên victim
          2. Cross-reference với Sysmon IoC (PID từ events)
          3. Pattern matching (PowerShell bypass, wsmprovhost, etc.)
          4. Suspend/kill processes tùy theo evidence + score
          5. User notify + logoff nếu critical
        
        Args:
            ip: Attacker IP
            events: Events liên quan đến IP này (từ SOAR pipeline)
            score: Risk score hiện tại của IP
            
        Returns:
            dict: Containment result {success, processes_killed, ...}
        """
        logger.critical(f"[EDR] ═══ PROCESS CONTAINMENT triggered for {ip} ═══")
        
        try:
            result = self._edr.contain_by_ip(ip, events, score=score)
            
            if result["processes_killed"] > 0:
                logger.critical(
                    f"[EDR] ✅ Killed {result['processes_killed']} malicious process(es) "
                    f"on victim (attacker={ip})"
                )
                # Log chi tiết từng process đã kill
                for detail in result.get("kill_details", []):
                    if detail["killed"]:
                        logger.info(
                            f"[EDR]   ├── PID={detail['pid']} "
                            f"name='{detail['name']}' "
                            f"severity={detail['severity']}"
                        )
            elif result["failures"] > 0:
                logger.error(
                    f"[EDR] ⚠️ Process containment had {result['failures']} failure(s) "
                    f"for IP {ip}"
                )
            else:
                logger.info(f"[EDR] No malicious processes found for IP {ip}")
            
            return result
            
        except Exception as e:
            logger.error(f"[EDR] Process containment failed for {ip}: {e}", exc_info=True)
            return {"success": False, "processes_killed": 0, "failures": 1}

    # ==============================================================
    # BLOCK IP
    # ==============================================================

    def _do_block(self, ip, ip_state):
        """Block IP sử dụng multiple layers defense."""
        logger.critical(f">>> BLOCKING IP: {ip} <<<")
        logger.info(f"[DEBUG] Starting comprehensive block process for {ip}")

        # Đánh dấu blocked trong state
        if ip in ip_state:
            ip_state[ip]["blocked"] = True
            ip_state[ip]["blocked_at"] = time.time()

        if DRY_RUN:
            logger.info(f"[DRY_RUN] Giả lập block IP {ip}")
            return

        # Layer 1: Firewall rules (existing)
        logger.info(f"[DEBUG] Layer 1: Firewall blocking {ip}")
        self._block_ubuntu_firewall(ip)
        # Bật Windows Firewall trước khi thêm rules (để rules có tác dụng)
        self._enable_windows_firewall()
        self._block_windows_firewall(ip)

        # Layer 2: Network routing (null route)
        logger.info(f"[DEBUG] Layer 2: Network routing blocking {ip}")
        self._block_ubuntu_routing(ip)
        self._block_windows_routing(ip)

        # Layer 3: TCP Wrappers & fail2ban
        logger.info(f"[DEBUG] Layer 3: Service-level blocking {ip}")
        self._block_ubuntu_services(ip)
        logger.info(f"[DEBUG] Comprehensive block completed for {ip}")

    def _block_ubuntu_firewall(self, ip):
        """Thêm rules iptables để block IP toàn diện."""
        rule_name = f"SOAR_BLOCK_{ip.replace('.', '_')}"
        
        commands = [
            # Block INPUT (traffic đến Ubuntu)
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP", 
             "-m", "comment", "--comment", rule_name + "_INPUT"],
            # Block OUTPUT (traffic từ Ubuntu đến attacker)  
            ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP",
             "-m", "comment", "--comment", rule_name + "_OUTPUT"],
            # Block FORWARD (traffic qua Ubuntu - nếu làm gateway)
            ["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP",
             "-m", "comment", "--comment", rule_name + "_FORWARD_SRC"],
            ["sudo", "iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP", 
             "-m", "comment", "--comment", rule_name + "_FORWARD_DST"]
        ]
        
        for i, cmd in enumerate(commands, 1):
            logger.info(f"[DEBUG] Ubuntu iptables command {i}/4: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                
                logger.info(f"[DEBUG] Command {i} return code: {result.returncode}")
                if result.returncode != 0:
                    logger.warning(f"[DEBUG] Command {i} stderr: '{result.stderr.strip()}'")
                    
            except Exception as e:
                logger.error(f"[Ubuntu] iptables command {i} failed: {e}")
        
        logger.info(f"[Ubuntu] Firewall block for {ip} — Completed")

    def _block_ubuntu_routing(self, ip):
        """Thêm null routes để block IP network-level.""" 
        commands = [
            # Null route method 1: Route to nowhere
            ["sudo", "ip", "route", "add", f"{ip}/32", "via", "127.0.0.1"],
            # Null route method 2: Reject route
            ["sudo", "route", "add", "-host", ip, "reject"]
        ]
        
        for i, cmd in enumerate(commands, 1):
            logger.info(f"[DEBUG] Ubuntu routing command {i}/2: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    logger.info(f"[DEBUG] Routing command {i} — OK")
                else:
                    logger.warning(f"[DEBUG] Routing command {i} failed: {result.stderr.strip()}")
                    
            except Exception as e:
                logger.warning(f"[Ubuntu] Routing command {i} failed: {e}")
        
        logger.info(f"[Ubuntu] Routing block for {ip} — Completed")

    def _block_ubuntu_services(self, ip):
        """Block IP ở service level: hosts.deny, fail2ban."""
        
        # 1. TCP Wrappers - hosts.deny
        try:
            hosts_deny_line = f"ALL: {ip} : deny  # SOAR block\n"
            with open("/etc/hosts.deny", "a") as f:
                f.write(hosts_deny_line)
            logger.info(f"[Ubuntu] Added {ip} to /etc/hosts.deny")
        except Exception as e:
            logger.warning(f"[Ubuntu] hosts.deny write failed: {e}")
        
        # 2. fail2ban (if available)
        fail2ban_commands = [
            ["sudo", "fail2ban-client", "set", "sshd", "banip", ip],
            ["sudo", "fail2ban-client", "set", "apache", "banip", ip]
        ]
        
        for i, cmd in enumerate(fail2ban_commands, 1):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    logger.info(f"[Ubuntu] fail2ban jail {i} banned {ip}")
                else:
                    logger.debug(f"[Ubuntu] fail2ban jail {i} not available or failed")
                    
            except Exception as e:
                logger.debug(f"[Ubuntu] fail2ban command {i} failed: {e}")
        
        logger.info(f"[Ubuntu] Service-level block for {ip} — Completed")

    def _block_windows_firewall(self, ip):
        """
        SSH vào Windows victim, thêm firewall rules block IP toàn diện.
        
        Sử dụng SSHManager với retry logic + error alerting.
        """
        rule_name = f"SOAR_BLOCK_{ip.replace('.', '_')}"
        
        # Tạo 4 rules: inbound + outbound (all traffic + ICMP)
        commands = [
            f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip} enable=yes',
            f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip} enable=yes',
            f'netsh advfirewall firewall add rule name="{rule_name}_ICMP_IN" dir=in action=block protocol=icmpv4 remoteip={ip} enable=yes',
            f'netsh advfirewall firewall add rule name="{rule_name}_ICMP_OUT" dir=out action=block protocol=icmpv4 remoteip={ip} enable=yes'
        ]

        logger.info(f"[Windows] Adding firewall rules to block {ip}")
        
        success_count = 0
        for i, cmd in enumerate(commands, 1):
            success, output = self._ssh_manager.execute_command(cmd, timeout=20)
            
            if success:
                success_count += 1
                logger.info(f"[Windows] Firewall rule {i}/4 added successfully")
            else:
                logger.error(f"[Windows] Firewall rule {i}/4 failed: {output}")
        
        if success_count == len(commands):
            logger.info(f"✅ [Windows] Firewall block for {ip} — Completed ({success_count}/4)")
        elif success_count > 0:
            logger.warning(f"⚠️ [Windows] Firewall block partial success: {success_count}/4 rules")
        else:
            logger.critical(f"❌ [Windows] Firewall block FAILED for {ip} (0/4 rules)")
            # SSHManager đã gửi email alert nếu fail 3 lần

    def _block_windows_routing(self, ip):
        """
        SSH vào Windows, thêm null routes (fallback layer).
        
        Sử dụng SSHManager với retry logic.
        """
        commands = [
            f'route add {ip} mask 255.255.255.255 127.0.0.1 metric 1',
            f'route add {ip} mask 255.255.255.255 0.0.0.0 metric 1'
        ]

        logger.info(f"[Windows] Adding null routes for {ip}")
        
        success_count = 0
        for i, cmd in enumerate(commands, 1):
            success, output = self._ssh_manager.execute_command(cmd, timeout=15)
            
            if success:
                success_count += 1
                logger.info(f"[Windows] Routing rule {i}/2 added successfully")
            else:
                # Routing commands thường fail nếu rule đã tồn tại → không phải critical
                logger.debug(f"[Windows] Routing rule {i}/2 failed (might already exist): {output}")
        
        if success_count > 0:
            logger.info(f"[Windows] Routing block for {ip} — Completed ({success_count}/2)")
        else:
            logger.warning(f"[Windows] Routing block failed (routes might already exist)")

    def _enable_windows_firewall(self):
        """
        SSH vào Windows và bật firewall cho tất cả profiles.
        
        Sử dụng SSHManager với retry logic.
        """
        commands = [
            'netsh advfirewall set domainprofile state on',
            'netsh advfirewall set publicprofile state on',
            'netsh advfirewall set privateprofile state on'
        ]

        logger.info(f"[Windows] Enabling Windows Firewall on {WIN_SSH_HOST}")
        
        success_count = 0
        for i, cmd in enumerate(commands, 1):
            success, output = self._ssh_manager.execute_command(cmd, timeout=15)
            
            if success:
                success_count += 1
                logger.info(f"[Windows] Firewall profile {i}/3 enabled")
            else:
                logger.warning(f"[Windows] Firewall profile {i}/3 failed: {output}")
        
        if success_count == len(commands):
            logger.info("✅ [Windows] Firewall enabled for all profiles")
        elif success_count > 0:
            logger.warning(f"⚠️ [Windows] Firewall enable partial: {success_count}/3 profiles")
        else:
            logger.error("❌ [Windows] Firewall enable FAILED")

    # ==============================================================
    # AUTO-UNBLOCK
    # ==============================================================

    def check_auto_unblock(self, ip_state):
        """Kiểm tra và tự động unblock IP đã block quá lâu."""
        now = time.time()
        for ip, data in list(ip_state.items()):
            if not data.get("blocked", False):
                continue
            blocked_at = data.get("blocked_at", 0)
            if blocked_at and (now - blocked_at) >= UNBLOCK_AFTER_SECONDS:
                logger.info(
                    f"Auto-unblock {ip} (blocked"
                    f" {int(now - blocked_at)}s ago)"
                )
                self._do_unblock(ip, ip_state)

    def _do_unblock(self, ip, ip_state):
        """Gỡ block IP trên cả Ubuntu và Windows."""
        logger.info(f">>> UNBLOCKING IP: {ip} <<<")

        if ip in ip_state:
            ip_state[ip]["blocked"] = False
            ip_state[ip]["blocked_at"] = None
            # Reset score để tránh block lại ngay
            ip_state[ip]["total_score"] = 0
            ip_state[ip]["scan_count"] = 0
            ip_state[ip]["scan_batches_scored"] = 0
            ip_state[ip]["fail_count"] = 0
            ip_state[ip]["fail_batches_scored"] = 0
            ip_state[ip]["winrm_session_times"] = []

        if DRY_RUN:
            logger.info(f"[DRY_RUN] Giả lập unblock IP {ip}")
            return

        self._unblock_ubuntu_comprehensive(ip)
        self._unblock_windows_comprehensive(ip)

    def _unblock_ubuntu_comprehensive(self, ip):
        """Xóa tất cả các layers blocking cho IP."""
        rule_name = f"SOAR_BLOCK_{ip.replace('.', '_')}"
        
        logger.info(f"[Ubuntu] Comprehensive unblock for {ip} started")
        
        # Layer 1: Xóa iptables rules
        iptables_commands = [
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
            ["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"]
        ]
        
        for i, cmd in enumerate(iptables_commands, 1):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"[Ubuntu] iptables unblock rule {i} — OK")
                else:
                    logger.warning(f"[Ubuntu] iptables unblock rule {i}: {result.stderr.strip()}")
            except Exception as e:
                logger.warning(f"[Ubuntu] iptables unblock rule {i} failed: {e}")
        
        # Layer 2: Xóa routing rules 
        routing_commands = [
            ["sudo", "ip", "route", "del", f"{ip}/32"],
            ["sudo", "route", "del", "-host", ip]
        ]
        
        for i, cmd in enumerate(routing_commands, 1):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"[Ubuntu] routing unblock rule {i} — OK")
                else:
                    logger.debug(f"[Ubuntu] routing unblock rule {i}: {result.stderr.strip()}")
            except Exception as e:
                logger.debug(f"[Ubuntu] routing unblock rule {i} failed: {e}")
        
        # Layer 3: Xóa từ hosts.deny
        try:
            with open("/etc/hosts.deny", "r") as f:
                lines = f.readlines()

            with open("/etc/hosts.deny", "w") as f:
                for line in lines:
                    if f"ALL: {ip}" not in line:
                        f.write(line)

            logger.info(f"[Ubuntu] Removed {ip} from /etc/hosts.deny")
        except FileNotFoundError:
            logger.debug("[Ubuntu] hosts.deny not found, skipping")
        except Exception as e:
            logger.debug(f"[Ubuntu] hosts.deny cleanup failed: {e}")
        
        # Layer 4: Xóa từ fail2ban
        fail2ban_commands = [
            ["sudo", "fail2ban-client", "set", "sshd", "unbanip", ip],
            ["sudo", "fail2ban-client", "set", "apache", "unbanip", ip]
        ]
        
        for i, cmd in enumerate(fail2ban_commands, 1):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"[Ubuntu] fail2ban unban jail {i} — OK")
                else:
                    logger.debug(f"[Ubuntu] fail2ban unban jail {i}: not available")
            except Exception as e:
                logger.debug(f"[Ubuntu] fail2ban unban jail {i} failed: {e}")
                
        logger.info(f"[Ubuntu] Comprehensive unblock for {ip} — Completed")

    def _unblock_windows_comprehensive(self, ip):
        """
        SSH vào Windows, xóa tất cả blocking layers.
        
        Sử dụng SSHManager với retry logic.
        """
        rule_name = f"SOAR_BLOCK_{ip.replace('.', '_')}"
        
        logger.info(f"[Windows] Comprehensive unblock for {ip} started")
        
        # Commands tổng hợp: firewall rules + routing
        commands = [
            f'netsh advfirewall firewall delete rule name="{rule_name}_IN"',
            f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"',
            f'netsh advfirewall firewall delete rule name="{rule_name}_ICMP_IN"',
            f'netsh advfirewall firewall delete rule name="{rule_name}_ICMP_OUT"',
            f'route delete {ip}',
            f'route delete {ip} mask 255.255.255.255'
        ]
        
        success_count = 0
        for i, cmd in enumerate(commands, 1):
            success, output = self._ssh_manager.execute_command(cmd, timeout=15)
            
            if success:
                success_count += 1
                logger.info(f"[Windows] Unblock command {i}/6 — OK")
            else:
                # Unblock commands thường fail nếu rule không tồn tại → không phải critical
                logger.debug(f"[Windows] Unblock command {i}/6 failed (might not exist): {output}")
        
        logger.info(f"[Windows] Comprehensive unblock for {ip} — Completed ({success_count}/6)")

    # ==============================================================
    # EMAIL ALERT
    # ==============================================================

    def _send_alert_email(self, ip, score, reason):
        """Gửi email cảnh báo qua Gmail SMTP."""
        if DRY_RUN:
            logger.info(
                f"[DRY_RUN] Giả lập gửi email: IP={ip},"
                f" score={score}, reason={reason[:100]}"
            )
            return

        if SMTP_USER == "your_email@gmail.com":
            logger.warning(
                "Email chưa cấu hình (SMTP_USER = placeholder). "
                "Bỏ qua gửi email."
            )
            return

        subject = f"[SOAR ALERT] IP {ip} — Score: {score}"
        body = _build_email_body(ip, score, reason)

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = SMTP_USER
            msg["To"] = ", ".join(ALERT_RECIPIENTS)
            msg.attach(MIMEText(body, "html", "utf-8"))

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, ALERT_RECIPIENTS, msg.as_string())

            logger.info(f"Email alert gửi thành công cho IP {ip}")
        except Exception as e:
            logger.error(f"Email alert thất bại: {e}")


# ==============================================================
# EMAIL TEMPLATE
# ==============================================================

def _build_email_body(ip, score, reason):
    """Tạo HTML body cho email cảnh báo."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #d32f2f;">
            ⚠️ SOAR Alert — Suspicious Activity Detected
        </h2>
        <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
            <tr style="background: #f5f5f5;">
                <td style="padding: 10px; font-weight: bold;">IP Address</td>
                <td style="padding: 10px; color: #d32f2f; font-weight: bold;">
                    {ip}
                </td>
            </tr>
            <tr>
                <td style="padding: 10px; font-weight: bold;">Risk Score</td>
                <td style="padding: 10px;">
                    <span style="background: #d32f2f; color: white;
                                 padding: 4px 12px; border-radius: 4px;">
                        {score}
                    </span>
                </td>
            </tr>
            <tr style="background: #f5f5f5;">
                <td style="padding: 10px; font-weight: bold;">Reason</td>
                <td style="padding: 10px;">{reason}</td>
            </tr>
            <tr>
                <td style="padding: 10px; font-weight: bold;">Timestamp</td>
                <td style="padding: 10px;">{timestamp}</td>
            </tr>
            <tr style="background: #f5f5f5;">
                <td style="padding: 10px; font-weight: bold;">Action Taken</td>
                <td style="padding: 10px; color: #d32f2f;">
                    <strong>Network Containment:</strong> IP đã bị block trên Ubuntu (iptables) + Windows (netsh).<br/>
                    <strong>Process Containment (EDR):</strong> Malicious processes đã bị kill trên endpoint.<br/>
                    Tự động unblock sau 1 giờ.
                </td>
            </tr>
        </table>
        <p style="color: #666; margin-top: 20px; font-size: 12px;">
            — SOAR Mini Engine v1.0 | SOC Lab
        </p>
    </body>
    </html>
    """
