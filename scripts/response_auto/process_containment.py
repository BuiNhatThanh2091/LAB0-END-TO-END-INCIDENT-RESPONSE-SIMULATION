"""
process_containment.py — EDR Module: Process Detection & Kill
===============================================================
Containment ở mức Process — bổ sung cho Network Containment (response.py).

Vấn đề mà module này giải quyết:
  - Network blocking (iptables/netsh) chỉ cắt kênh C2 (Command & Control)
  - Nếu malware/ransomware đã được nạp vào RAM → nó tiếp tục chạy
  - Module này SSH vào Windows victim, xác định PID độc hại, rồi KILL ngay

Workflow:
  1. Thu thập danh sách processes đang chạy trên Windows victim (qua SSH)
  2. So khớp với IoC (Indicator of Compromise) từ Sysmon logs
  3. Kill process bằng taskkill /PID /F hoặc Stop-Process -Force
  4. Verify process đã chết
  5. Log toàn bộ forensic evidence

Sử dụng:
    edr = ProcessContainment(ssh_manager)
    result = edr.contain_by_ip(attacker_ip, events)
    # hoặc
    result = edr.kill_process_by_name("powershell.exe")
    result = edr.kill_process_by_pid(1234)
"""

import re
import time
from logger_setup import setup_logger
from config import (
    DRY_RUN,
    VICTIM_IP,
    EDR_LOGOFF_SCORE_THRESHOLD,
    EDR_REQUIRE_CRITICAL_EVIDENCE,
    EDR_USER_MSG_TIMEOUT_SECONDS,
    EDR_USER_MSG_TEXT,
    EDR_SUSPEND_FALLBACK_TO_KILL,
)

logger = setup_logger("process_containment")


# ==============================================================
# MALICIOUS PROCESS SIGNATURES
# ==============================================================
# Patterns để identify processes cần kill
# Format: (pattern_name, regex_pattern, severity, description)

MALICIOUS_PROCESS_PATTERNS = [
    # PowerShell executing suspicious scripts
    ("ps_bypass", r"powershell.*-executionpolicy\s+bypass", "critical",
     "PowerShell running with ExecutionPolicy Bypass"),
    
    # PowerShell encoding/exfiltration
    ("ps_encoded", r"powershell.*-enc(odedcommand)?", "critical",
     "PowerShell running encoded command (possible obfuscation)"),
    
    # Base64 exfiltration scripts
    ("ps_base64", r"powershell.*tobase64string", "high",
     "PowerShell performing Base64 encoding (possible exfiltration)"),
    
    # WinRM remote shell spawned by attacker
    ("winrm_shell", r"wsmprovhost\.exe", "high",
     "WinRM Provider Host (remote shell from attacker)"),
    
    # Common attack tools
    ("mimikatz", r"mimikatz", "critical",
     "Mimikatz credential dumping tool detected"),
    
    # Certutil abuse (download/decode payloads)
    ("certutil_abuse", r"certutil.*(-urlcache|-decode)", "high",
     "Certutil being abused for download/decode"),
    
    # Suspicious cmd.exe spawned by WinRM
    ("cmd_remote", r"cmd\.exe.*/c.*powershell", "medium",
     "CMD spawning PowerShell (possible lateral movement)"),
    
    # Netcat / reverse shell
    ("netcat", r"(nc|ncat|nc64)\.exe", "critical",
     "Netcat detected (possible reverse shell)"),
    
    # Python http.server (hosting malware)
    ("python_http", r"python.*http\.server", "medium",
     "Python HTTP server (possible malware staging)"),
]

# Process names luôn cần kill nếu liên quan đến attacker IP
ALWAYS_KILL_PROCESSES = {
    "wsmprovhost.exe",   # WinRM remote shell
}

# Process names KHÔNG BAO GIỜ kill (system critical)
PROTECTED_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe",
    "winlogon.exe", "dwm.exe", "explorer.exe", "conhost.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "spoolsv.exe", "searchindexer.exe",
    "sshd.exe",  # Không kill SSH daemon (mất kết nối quản trị)
}

# Monitoring/Lab tools KHÔNG BAO GIỜ kill (tránh mất log)
MONITORING_PROCESSES = {
    "sysmon.exe", "sysmon64.exe",
    "winlogbeat.exe", "splunkd.exe", "splunk-admon.exe",
    "vmtoolsd.exe", "vmwaretools.exe",
}

# Defender process chỉ whitelist khi path hợp lệ (hardened path)
DEFENDER_ALLOWED_PATH_PREFIXES = (
    "c:\\programdata\\microsoft\\windows defender\\platform\\",
    "c:\\program files\\windows defender\\",
    "c:\\windows\\system32\\",
)


class ProcessContainment:
    """
    EDR-like Process Containment Engine.
    
    Kết nối qua SSH tới Windows victim để:
      1. Liệt kê processes đang chạy
      2. Identify malicious processes dựa trên IoC
      3. Kill processes nguy hiểm
      4. Verify containment thành công
    """
    
    def __init__(self, ssh_manager):
        """
        Args:
            ssh_manager: SSHManager instance (đã kết nối tới Windows victim)
        """
        self._ssh = ssh_manager
        self._kill_history = []  # Lịch sử processes đã kill
        self._stats = {
            "processes_scanned": 0,
            "processes_killed": 0,
            "kill_failures": 0,
            "containments_performed": 0,
        }
        logger.info("ProcessContainment (EDR module) initialized")
    
    # ==============================================================
    # 1. LIỆT KÊ PROCESSES ĐANG CHẠY
    # ==============================================================
    
    def get_running_processes(self):
        """
        Lấy danh sách tất cả processes đang chạy trên Windows victim.
        
        Returns:
            list[dict]: Mỗi dict = {pid, name, command_line, user, memory_kb}
            Hoặc [] nếu thất bại
        """
        if DRY_RUN:
            logger.info("[DRY_RUN] Giả lập get_running_processes")
            return self._mock_process_list()
        
        # Dùng WMIC để lấy đầy đủ thông tin (bao gồm CommandLine)
        cmd = (
            'wmic process get ProcessId,Name,CommandLine,ExecutablePath '
            '/format:csv'
        )
        
        success, output = self._ssh.execute_command(cmd, timeout=30)
        if not success:
            logger.error(f"[EDR] Failed to list processes: {output}")
            # Fallback: dùng tasklist
            return self._get_processes_tasklist()
        
        processes = self._parse_wmic_csv(output)
        self._stats["processes_scanned"] += len(processes)
        logger.info(f"[EDR] Retrieved {len(processes)} running processes")
        return processes
    
    def _get_processes_tasklist(self):
        """Fallback: dùng tasklist nếu WMIC fail."""
        cmd = 'tasklist /V /FO CSV'
        success, output = self._ssh.execute_command(cmd, timeout=30)
        if not success:
            logger.error(f"[EDR] tasklist also failed: {output}")
            return []
        
        return self._parse_tasklist_csv(output)
    
    def _parse_wmic_csv(self, raw_output):
        """Parse output từ wmic process get ... /format:csv"""
        processes = []
        lines = raw_output.strip().split('\n')
        
        # Tìm header line
        header_idx = -1
        for i, line in enumerate(lines):
            if 'ProcessId' in line and 'Name' in line:
                header_idx = i
                break
        
        if header_idx < 0:
            logger.warning("[EDR] Cannot find WMIC CSV header")
            return processes
        
        headers = [h.strip().lower() for h in lines[header_idx].split(',')]
        
        for line in lines[header_idx + 1:]:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(',')
            if len(parts) < len(headers):
                continue
            
            row = {}
            for j, header in enumerate(headers):
                row[header] = parts[j].strip() if j < len(parts) else ""
            
            pid_str = row.get('processid', '0')
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            
            if pid == 0:
                continue
            
            processes.append({
                "pid": pid,
                "name": row.get('name', ''),
                "command_line": row.get('commandline', ''),
                "executable_path": row.get('executablepath', ''),
            })
        
        return processes
    
    def _parse_tasklist_csv(self, raw_output):
        """Parse output từ tasklist /V /FO CSV"""
        processes = []
        lines = raw_output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            line = line.strip().strip('"')
            if not line:
                continue
            
            # CSV format: "Image Name","PID","Session Name","Session#","Mem Usage",...
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 2:
                continue
            
            try:
                pid = int(parts[1])
            except (ValueError, IndexError):
                continue
            
            processes.append({
                "pid": pid,
                "name": parts[0] if parts else "",
                "command_line": "",  # tasklist không có command line
                "executable_path": "",
            })
        
        return processes
    
    # ==============================================================
    # 2. IDENTIFY MALICIOUS PROCESSES
    # ==============================================================
    
    def identify_malicious(self, processes, events=None):
        """
        So khớp processes đang chạy với IoC patterns.
        
        Args:
            processes: list[dict] từ get_running_processes()
            events: list[dict] events từ SOAR pipeline (optional)
                    Dùng để cross-reference PID từ Sysmon Event 1
        
        Returns:
            tuple[list[dict], list[dict]]:
                - malicious: Processes cần xử lý
                - protected_hits: Processes thuộc whitelist nhưng match IoC/pattern
        """
        malicious = []
        protected_hits = []
        ioc_pids = self._extract_pids_from_events(events) if events else set()
        
        for proc in processes:
            name = proc.get("name", "").lower()
            cmd_line = proc.get("command_line", "").lower()
            pid = proc.get("pid", 0)
            
            # Skip protected processes (but record if matched)
            is_protected = self._is_protected_process(proc)
            
            # Check 1: Khớp PID từ Sysmon events (cross-reference)
            if pid in ioc_pids:
                if is_protected:
                    protected_hits.append({
                        **proc,
                        "pattern": "sysmon_ioc",
                        "severity": "critical",
                        "reason": f"PID {pid} matched Sysmon IoC (protected)",
                    })
                    continue
                malicious.append({
                    **proc,
                    "pattern": "sysmon_ioc",
                    "severity": "critical",
                    "reason": f"PID {pid} matched Sysmon IoC from events",
                })
                continue
            
            # Check 2: Always-kill processes (wsmprovhost.exe, etc.)
            if name in ALWAYS_KILL_PROCESSES:
                if is_protected:
                    protected_hits.append({
                        **proc,
                        "pattern": "always_kill",
                        "severity": "high",
                        "reason": f"Process '{name}' in always-kill list (protected)",
                    })
                    continue
                malicious.append({
                    **proc,
                    "pattern": "always_kill",
                    "severity": "high",
                    "reason": f"Process '{name}' in always-kill list",
                })
                continue
            
            # Check 3: Regex pattern matching trên command line
            search_text = f"{name} {cmd_line}"
            for pattern_name, regex, severity, description in MALICIOUS_PROCESS_PATTERNS:
                if re.search(regex, search_text, re.IGNORECASE):
                    if is_protected:
                        protected_hits.append({
                            **proc,
                            "pattern": pattern_name,
                            "severity": severity,
                            "reason": f"{description} (protected)",
                        })
                        break
                    malicious.append({
                        **proc,
                        "pattern": pattern_name,
                        "severity": severity,
                        "reason": description,
                    })
                    break  # 1 process chỉ match 1 pattern (ưu tiên đầu tiên)
        
        if malicious:
            logger.warning(
                f"[EDR] Identified {len(malicious)} malicious process(es):"
            )
            for m in malicious:
                logger.warning(
                    f"  - PID={m['pid']} name='{m['name']}' "
                    f"severity={m['severity']} pattern={m['pattern']}"
                )
        
        return malicious, protected_hits
    
    def _extract_pids_from_events(self, events):
        """
        Trích xuất PIDs từ Sysmon events (Event Code 1 = Process Create).
        
        Dùng để cross-reference: nếu Sysmon log ghi nhận process nghi vấn,
        ta dùng PID đó để kill chính xác.
        """
        pids = set()
        if not events:
            return pids
        
        for event in events:
            event_type = event.get("event_type", "")
            details = event.get("details", {})
            
            # Chỉ quan tâm process-related events
            if event_type in ("ps_bypass", "exfil_base64", "winrm_process",
                              "process_create"):
                # Sysmon Event 1 thường có ProcessId trong raw data
                raw = event.get("raw", {})
                event_data = raw.get("winlog", {}).get("event_data", {})
                
                pid_str = event_data.get("ProcessId", "")
                if pid_str:
                    try:
                        pids.add(int(pid_str))
                    except ValueError:
                        pass
                
                # Cũng lấy ParentProcessId (parent chain)
                parent_pid = event_data.get("ParentProcessId", "")
                if parent_pid:
                    try:
                        pids.add(int(parent_pid))
                    except ValueError:
                        pass
        
        if pids:
            logger.info(f"[EDR] Extracted {len(pids)} PIDs from Sysmon events: {pids}")
        
        return pids
    
    # ==============================================================
    # 3. KILL PROCESS
    # ==============================================================
    
    def kill_process_by_pid(self, pid, process_name="unknown"):
        """
        Kill 1 process theo PID trên Windows victim.
        
        Args:
            pid: Process ID cần kill
            process_name: Tên process (để logging)
            
        Returns:
            (success: bool, message: str)
        """
        if DRY_RUN:
            msg = f"[DRY_RUN] Giả lập kill PID {pid} ({process_name})"
            logger.info(msg)
            self._record_kill(pid, process_name, True, "dry_run")
            return True, msg
        
        logger.critical(f"[EDR] >>> KILLING PROCESS: PID={pid} name='{process_name}' <<<")
        
        # Phương pháp 1: taskkill /PID (nhanh nhất, native Windows)
        cmd1 = f'taskkill /PID {pid} /F'
        success, output = self._ssh.execute_command(cmd1, timeout=15)
        
        if success and ("success" in output.lower() or "terminated" in output.lower()):
            logger.info(f"[EDR] taskkill succeeded for PID {pid}")
            self._record_kill(pid, process_name, True, "taskkill")
            return True, f"Process PID={pid} killed via taskkill"
        
        # Phương pháp 2: PowerShell Stop-Process (mạnh hơn)
        cmd2 = f'powershell -Command "Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"'
        success, output = self._ssh.execute_command(cmd2, timeout=15)
        
        if success:
            # Verify process đã chết
            verified = self._verify_kill(pid)
            if verified:
                logger.info(f"[EDR] Stop-Process succeeded for PID {pid}")
                self._record_kill(pid, process_name, True, "stop_process")
                return True, f"Process PID={pid} killed via Stop-Process"
        
        # Phương pháp 3: WMIC (last resort)
        cmd3 = f'wmic process where ProcessId={pid} delete'
        success, output = self._ssh.execute_command(cmd3, timeout=15)
        
        if success:
            verified = self._verify_kill(pid)
            if verified:
                logger.info(f"[EDR] WMIC delete succeeded for PID {pid}")
                self._record_kill(pid, process_name, True, "wmic_delete")
                return True, f"Process PID={pid} killed via WMIC"
        
        # Tất cả methods fail
        logger.error(f"[EDR] FAILED to kill PID {pid} ({process_name}) after 3 methods")
        self._record_kill(pid, process_name, False, "all_failed")
        self._stats["kill_failures"] += 1
        return False, f"Failed to kill PID={pid} after 3 attempts"
    
    def kill_process_by_name(self, process_name):
        """
        Kill TẤT CẢ instances của 1 process name.
        
        Args:
            process_name: Tên process (vd: "powershell.exe")
            
        Returns:
            (success: bool, message: str)
        """
        pname = process_name.lower()
        if pname in PROTECTED_PROCESSES or pname in MONITORING_PROCESSES or pname == "msmpeng.exe":
            msg = f"[EDR] REFUSED: '{process_name}' is protected (system/monitoring)"
            logger.warning(msg)
            return False, msg
        
        if DRY_RUN:
            msg = f"[DRY_RUN] Giả lập kill all '{process_name}'"
            logger.info(msg)
            return True, msg
        
        logger.critical(f"[EDR] >>> KILLING ALL: '{process_name}' <<<")
        
        cmd = f'taskkill /IM "{process_name}" /F'
        success, output = self._ssh.execute_command(cmd, timeout=15)
        
        if success and ("success" in output.lower() or "terminated" in output.lower()):
            logger.info(f"[EDR] Killed all instances of '{process_name}'")
            self._record_kill(0, process_name, True, "taskkill_name")
            return True, f"All '{process_name}' instances killed"
        
        # Fallback: PowerShell
        safe_name = process_name.replace('.exe', '')
        cmd2 = (
            f'powershell -Command "Get-Process -Name \'{safe_name}\' '
            f'-ErrorAction SilentlyContinue | Stop-Process -Force"'
        )
        success, output = self._ssh.execute_command(cmd2, timeout=15)
        
        if success:
            logger.info(f"[EDR] Stop-Process killed '{process_name}'")
            self._record_kill(0, process_name, True, "stop_process_name")
            return True, f"All '{process_name}' instances killed via PowerShell"
        
        logger.error(f"[EDR] Failed to kill '{process_name}'")
        self._stats["kill_failures"] += 1
        return False, f"Failed to kill '{process_name}'"
    
    # ==============================================================
    # 4. CONTAINMENT WORKFLOW (Main Entry Point)
    # ==============================================================
    
    def contain_by_ip(self, attacker_ip, events=None, score=0):
        """
        Full containment workflow cho 1 attacker IP:
          1. Lấy danh sách processes
          2. Identify malicious processes (qua patterns + Sysmon IoC)
          3. Kill tất cả malicious processes
          4. Kill WinRM sessions (ngắt remote shell)
          5. Verify & report
        
        Args:
            attacker_ip: IP của attacker (để log & cross-reference)
            events: SOAR events liên quan đến IP này
            
        Returns:
            dict: {
                "success": bool,
                "processes_killed": int,
                "kill_details": list[dict],
                "failures": int,
            }
        """
        logger.critical(
            f"[EDR] ╔══════════════════════════════════════════════╗\n"
            f"[EDR] ║  PROCESS CONTAINMENT — IP: {attacker_ip:<17s} ║\n"
            f"[EDR] ╚══════════════════════════════════════════════╝"
        )
        
        self._stats["containments_performed"] += 1
        result = {
            "success": True,
            "attacker_ip": attacker_ip,
            "processes_killed": 0,
            "processes_suspended": 0,
            "kill_details": [],
            "failures": 0,
            "timestamp": time.time(),
            "needs_manual": False,
            "manual_reason": "",
            "suspend_failed": False,
            "logoff_triggered": False,
            "user_notified": False,
        }
        
        # Step 1: Lấy danh sách processes
        logger.info("[EDR] Step 1: Enumerating running processes...")
        processes = self.get_running_processes()
        
        if not processes:
            logger.warning("[EDR] No processes retrieved — cannot perform containment")
            result["success"] = False
            return result
        
        logger.info(f"[EDR] Found {len(processes)} running processes")
        
        # Step 2: Filter suspicious events cho IP này
        ip_events = []
        if events:
            ip_events = [
                e for e in events
                if e.get("src_ip") == attacker_ip
                or e.get("details", {}).get("ip_address") == attacker_ip
            ]
        
        # Step 3: Evaluate Winlogbeat-only critical evidence
        critical_evidence, evidence_reason = self._has_critical_evidence(ip_events, attacker_ip)
        logoff_ready = score >= EDR_LOGOFF_SCORE_THRESHOLD
        if EDR_REQUIRE_CRITICAL_EVIDENCE:
            logoff_ready = logoff_ready and critical_evidence

        # Step 4: Identify malicious processes
        logger.info("[EDR] Step 2: Identifying malicious processes...")
        malicious, protected_hits = self.identify_malicious(processes, ip_events)
        
        if protected_hits:
            result["needs_manual"] = True
            result["manual_reason"] = (
                f"Protected process matched IoC/pattern: {len(protected_hits)} item(s)"
            )
            for hit in protected_hits[:5]:
                logger.warning(
                    f"[EDR] Protected hit: PID={hit['pid']} name='{hit['name']}' "
                    f"pattern={hit['pattern']} reason='{hit['reason']}'"
                )

        if not malicious:
            logger.info("[EDR] No malicious processes found — containment not needed")
            if logoff_ready:
                user_name = self._extract_user_from_events(ip_events)
                if self._send_user_message(user_name):
                    result["user_notified"] = True
                if self._logoff_user():
                    result["logoff_triggered"] = True
                logger.critical(
                    f"[EDR] Logoff triggered (score={score}, evidence='{evidence_reason}')"
                )
            return result
        
        # Step 5: Kill/Suspend processes
        action_label = "Killing" if logoff_ready else "Suspending"
        logger.info(
            f"[EDR] Step 3: {action_label} {len(malicious)} malicious process(es)..."
        )
        
        for proc in malicious:
            pid = proc["pid"]
            name = proc["name"]
            severity = proc["severity"]
            reason = proc["reason"]
            
            logger.warning(
                f"[EDR] Killing: PID={pid} name='{name}' "
                f"severity={severity} reason='{reason}'"
            )
            
            if logoff_ready:
                success, msg = self.kill_process_by_pid(pid, name)
            else:
                success, msg = self.suspend_process_by_pid(pid, name)
                if not success and EDR_SUSPEND_FALLBACK_TO_KILL:
                    result["suspend_failed"] = True
                    logger.warning(
                        f"[EDR] Suspend failed for PID={pid}, fallback to kill"
                    )
                    success, msg = self.kill_process_by_pid(pid, name)
            
            kill_detail = {
                "pid": pid,
                "name": name,
                "severity": severity,
                "reason": reason,
                "killed": success,
                "method": msg,
                "timestamp": time.time(),
            }
            result["kill_details"].append(kill_detail)
            
            if success:
                if logoff_ready:
                    result["processes_killed"] += 1
                else:
                    result["processes_suspended"] += 1
            else:
                result["failures"] += 1
                result["success"] = False

        # Step 6: Kill tất cả WinRM shells (defensive measure)
        logger.info("[EDR] Step 4: Terminating WinRM remote shells...")
        self._kill_winrm_shells()

        # Step 7: User notification + logoff (critical only)
        if logoff_ready:
            user_name = self._extract_user_from_events(ip_events)
            if self._send_user_message(user_name):
                result["user_notified"] = True
            if self._logoff_user():
                result["logoff_triggered"] = True
            logger.critical(
                f"[EDR] Logoff triggered (score={score}, evidence='{evidence_reason}')"
            )

        # Step 8: Summary
        logger.critical(
            f"[EDR] Containment complete for {attacker_ip}: "
            f"killed={result['processes_killed']}, "
            f"suspended={result['processes_suspended']}, "
            f"failures={result['failures']}"
        )
        
        return result
    
    def _kill_winrm_shells(self):
        """
        Kill tất cả wsmprovhost.exe (WinRM remote shell processes).
        Đây là defensive measure — ngắt TOÀN BỘ remote shell sessions.
        """
        success, msg = self.kill_process_by_name("wsmprovhost.exe")
        if success:
            logger.info("[EDR] All WinRM remote shells terminated")
        else:
            logger.debug("[EDR] No WinRM shells found or kill failed")
    
    # ==============================================================
    # 5. VERIFY KILL
    # ==============================================================
    
    def _verify_kill(self, pid):
        """
        Verify rằng process đã thực sự bị terminate.
        
        Returns:
            True nếu process không còn tồn tại (kill thành công)
        """
        if DRY_RUN:
            return True
        
        cmd = f'tasklist /FI "PID eq {pid}" /NH'
        success, output = self._ssh.execute_command(cmd, timeout=10)
        
        if not success:
            # Không verify được — assume killed
            return True
        
        # Nếu output chứa "No tasks" hoặc không có PID → process đã chết
        if "no tasks" in output.lower() or "info:" in output.lower():
            return True
        
        # Nếu output vẫn chứa PID → process vẫn sống
        if str(pid) in output:
            logger.warning(f"[EDR] Verify: PID {pid} still running!")
            return False
        
        return True

    # ============================================================== 
    # 5B. SUSPEND PROCESS (LOLBins via P/Invoke)
    # ============================================================== 
    def suspend_process_by_pid(self, pid, process_name="unknown"):
        """
        Suspend 1 process theo PID (P/Invoke NtSuspendProcess).

        Returns:
            (success: bool, message: str)
        """
        if DRY_RUN:
            msg = f"[DRY_RUN] Giả lập suspend PID {pid} ({process_name})"
            logger.info(msg)
            return True, msg

        pname = process_name.lower()
        if pname in PROTECTED_PROCESSES or pname in MONITORING_PROCESSES or pname == "msmpeng.exe":
            msg = f"[EDR] REFUSED: '{process_name}' is protected (suspend blocked)"
            logger.warning(msg)
            return False, msg

        ps_script = (
            "$code=@'\n"
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public static class NtSuspend {\n"
            "  [DllImport(\"ntdll.dll\")]\n"
            "  public static extern int NtSuspendProcess(IntPtr processHandle);\n"
            "  [DllImport(\"kernel32.dll\")]\n"
            "  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);\n"
            "  [DllImport(\"kernel32.dll\")]\n"
            "  public static extern bool CloseHandle(IntPtr hObject);\n"
            "}\n'@;"
            "Add-Type $code -ErrorAction Stop;"
            f"$pid={pid};"
            "$h=[NtSuspend]::OpenProcess(0x1F0FFF,$false,$pid);"
            "if ($h -eq [IntPtr]::Zero) { Write-Output 'SUSPEND_FAIL_OPEN'; exit 1 };"
            "$r=[NtSuspend]::NtSuspendProcess($h);"
            "[NtSuspend]::CloseHandle($h) | Out-Null;"
            "if ($r -eq 0) { Write-Output 'SUSPEND_OK' } else { Write-Output ('SUSPEND_FAIL_' + $r) }"
        )

        cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"{ps_script}\""
        success, output = self._ssh.execute_command(cmd, timeout=20)
        if success and "SUSPEND_OK" in output:
            logger.info(f"[EDR] Suspended PID {pid} via NtSuspendProcess")
            return True, "Suspended via NtSuspendProcess"

        logger.error(f"[EDR] Failed to suspend PID {pid}: {output}")
        return False, f"Suspend failed: {output.strip()}"

    # ============================================================== 
    # 5C. USER MESSAGE + LOGOFF
    # ============================================================== 
    def _send_user_message(self, user_name=None):
        if DRY_RUN:
            logger.info("[DRY_RUN] Giả lập msg.exe notification")
            return True

        target = user_name or "*"
        msg_text = EDR_USER_MSG_TEXT.replace('"', "'")
        cmd = f'msg {target} /time:{EDR_USER_MSG_TIMEOUT_SECONDS} "{msg_text}"'
        success, output = self._ssh.execute_command(cmd, timeout=10)
        if not success:
            logger.warning(f"[EDR] msg.exe failed: {output}")
        return success

    def _logoff_user(self):
        if DRY_RUN:
            logger.info("[DRY_RUN] Giả lập logoff user")
            return True

        cmd = "shutdown /l /f"
        success, output = self._ssh.execute_command(cmd, timeout=10)
        if not success:
            logger.warning(f"[EDR] Logoff failed: {output}")
        return success

    # ============================================================== 
    # 5D. EVIDENCE HELPERS
    # ============================================================== 
    def _has_critical_evidence(self, events, attacker_ip):
        if not events:
            return False, "no_events"

        has_logon = False
        has_winrm = False
        has_temp_ps = False
        has_ps_exfil = False
        has_ps_bypass = False

        for event in events:
            etype = event.get("event_type", "")
            details = event.get("details", {})
            src_ip = event.get("src_ip") or details.get("ip_address")

            if etype == "logon_success" and src_ip == attacker_ip:
                has_logon = True
            elif etype == "winrm_process":
                has_winrm = True
            elif etype == "file_create":
                target = (details.get("target_filename") or "").lower()
                if "__psscriptpolicytest_" in target and target.endswith(".ps1"):
                    has_temp_ps = True
            elif etype == "exfil_base64":
                has_ps_exfil = True
            elif etype == "ps_bypass":
                has_ps_bypass = True

        critical = has_logon and has_winrm and (has_ps_exfil or has_ps_bypass) and has_temp_ps
        reason = (
            f"logon={has_logon}, winrm={has_winrm}, temp_ps={has_temp_ps}, "
            f"exfil={has_ps_exfil}, bypass={has_ps_bypass}"
        )
        return critical, reason

    def _extract_user_from_events(self, events):
        for event in events or []:
            user_name = event.get("details", {}).get("user_name")
            if user_name:
                return user_name
        return None

    def _is_protected_process(self, proc):
        name = proc.get("name", "").lower()
        path = (proc.get("executable_path") or "").lower()

        if name in PROTECTED_PROCESSES:
            return True
        if name in MONITORING_PROCESSES:
            return True
        if name == "msmpeng.exe" and path:
            return any(path.startswith(prefix) for prefix in DEFENDER_ALLOWED_PATH_PREFIXES)
        return False
    
    # ==============================================================
    # 6. FORENSIC LOGGING
    # ==============================================================
    
    def _record_kill(self, pid, name, success, method):
        """Ghi lại lịch sử kill process cho forensic/audit."""
        record = {
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": pid,
            "process_name": name,
            "success": success,
            "method": method,
        }
        self._kill_history.append(record)
        
        if success:
            self._stats["processes_killed"] += 1
        
        logger.info(
            f"[EDR] Kill record: PID={pid} name='{name}' "
            f"success={success} method={method}"
        )
    
    def get_kill_history(self):
        """Trả về toàn bộ lịch sử kill (cho audit/report)."""
        return self._kill_history.copy()
    
    def get_stats(self):
        """Trả về thống kê EDR module."""
        return self._stats.copy()
    
    # ==============================================================
    # 7. DRY_RUN MOCK DATA
    # ==============================================================
    
    def _mock_process_list(self):
        """Mock process list cho DRY_RUN mode (testing trên Windows dev)."""
        return [
            {"pid": 1234, "name": "powershell.exe",
             "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\encrypt.ps1",
             "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"pid": 2345, "name": "wsmprovhost.exe",
             "command_line": "C:\\Windows\\System32\\wsmprovhost.exe -Embedding",
             "executable_path": "C:\\Windows\\System32\\wsmprovhost.exe"},
            {"pid": 3456, "name": "cmd.exe",
             "command_line": "cmd.exe /c powershell -enc aQBlAHgA",
             "executable_path": "C:\\Windows\\System32\\cmd.exe"},
            {"pid": 4567, "name": "svchost.exe",
             "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
             "executable_path": "C:\\Windows\\System32\\svchost.exe"},
            {"pid": 5678, "name": "explorer.exe",
             "command_line": "C:\\Windows\\explorer.exe",
             "executable_path": "C:\\Windows\\explorer.exe"},
            {"pid": 6789, "name": "notepad.exe",
             "command_line": "notepad.exe C:\\data\\data_important.txt",
             "executable_path": "C:\\Windows\\System32\\notepad.exe"},
        ]
