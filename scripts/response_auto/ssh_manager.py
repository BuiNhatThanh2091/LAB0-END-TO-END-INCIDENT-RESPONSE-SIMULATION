"""
ssh_manager.py — Centralized SSH Connection Manager
====================================================
Quản lý SSH connections tới Windows victim với các tính năng:
  1. SSH Key-based authentication (ưu tiên) + Password fallback
  2. Retry với exponential backoff: 2s → 4s → 8s
  3. Critical email alert khi fail 3 lần liên tiếp
  4. Connection pooling để tránh tạo connection mới liên tục
  5. Comprehensive error logging cho audit trail

Usage:
    ssh_mgr = SSHManager()
    success, output = ssh_mgr.execute_command("hostname")
    if not success:
        logger.error(f"SSH command failed: {output}")
"""

import os
import time
import paramiko
from logger_setup import setup_logger

logger = setup_logger("ssh_manager")


class SSHManager:
    """
    Centralized SSH Manager với retry logic và error alerting.
    
    Ưu điểm so với cách cũ (hardcoded password):
      - Bảo mật: Dùng SSH key thay vì plaintext password
      - Resilience: Retry tự động khi network hiccup
      - Observability: Log chi tiết mọi attempt
      - Alerting: Email khi SSH infrastructure down
    """
    
    def __init__(self, host, port=22, username=None, 
                 ssh_key_path=None, password=None,
                 max_retries=3, base_timeout=2):
        """
        Args:
            host: Target hostname/IP (Windows victim)
            port: SSH port (default 22)
            username: SSH username (hoặc lấy từ env)
            ssh_key_path: Path to private key (~/.ssh/id_rsa)
            password: Fallback password (nếu key auth fail)
            max_retries: Số lần retry (default 3)
            base_timeout: Base timeout cho exponential backoff (seconds)
        """
        self.host = host
        self.port = port
        self.username = username or os.getenv("SSH_USER", "thanh")
        self.ssh_key_path = ssh_key_path or os.path.expanduser("~/.ssh/id_rsa")
        self.password = password or os.getenv("SSH_PASS")
        self.max_retries = max_retries
        self.base_timeout = base_timeout
        
        # Connection state
        self._ssh_client = None
        self._connection_failures = 0  # Counter for consecutive failures
        self._last_failure_time = 0
        self._alert_sent = False  # Đã gửi email alert chưa
        
        logger.info(
            f"SSHManager initialized: {self.username}@{self.host}:{self.port}, "
            f"key={self.ssh_key_path}, retry={self.max_retries}"
        )
    
    def execute_command(self, command, timeout=30):
        """
        Execute command trên remote host với retry logic.
        
        Args:
            command: Shell command to execute
            timeout: Command execution timeout (seconds)
            
        Returns:
            (success: bool, output: str) - Tuple (thành công?, kết quả)
            
        Example:
            success, output = ssh_mgr.execute_command("ipconfig")
            if success:
                print(f"Output: {output}")
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                # Kết nối (hoặc reuse connection hiện tại)
                if not self._ensure_connected():
                    raise Exception("Failed to establish SSH connection")
                
                # Execute command
                logger.debug(f"Executing command (attempt {attempt}/{self.max_retries}): {command}")
                stdin, stdout, stderr = self._ssh_client.exec_command(
                    command, timeout=timeout
                )
                
                # Đọc output
                exit_code = stdout.channel.recv_exit_status()
                stdout_text = stdout.read().decode('utf-8', errors='ignore').strip()
                stderr_text = stderr.read().decode('utf-8', errors='ignore').strip()
                
                if exit_code == 0:
                    # Success → Reset failure counter
                    self._connection_failures = 0
                    self._alert_sent = False
                    logger.info(f"✅ SSH command succeeded: {command[:50]}...")
                    return True, stdout_text
                else:
                    # Command failed (non-zero exit code)
                    error_msg = f"Command exit code {exit_code}: {stderr_text}"
                    logger.warning(f"❌ SSH command failed: {error_msg}")
                    return False, error_msg
                    
            except paramiko.AuthenticationException as e:
                logger.error(f"🔐 SSH Authentication failed (attempt {attempt}): {e}")
                self._handle_connection_failure("Authentication failed")
                if attempt < self.max_retries:
                    self._backoff_sleep(attempt)
                    
            except paramiko.SSHException as e:
                logger.error(f"🔌 SSH Protocol error (attempt {attempt}): {e}")
                self._handle_connection_failure(f"SSH Protocol error: {e}")
                if attempt < self.max_retries:
                    self._backoff_sleep(attempt)
                    
            except Exception as e:
                logger.error(f"💥 Unexpected SSH error (attempt {attempt}): {e}")
                self._handle_connection_failure(f"Unexpected error: {e}")
                if attempt < self.max_retries:
                    self._backoff_sleep(attempt)
        
        # Tất cả retry đều fail → Gửi critical alert
        self._send_critical_alert(command)
        return False, f"SSH command failed after {self.max_retries} retries"
    
    def _ensure_connected(self):
        """
        Đảm bảo SSH connection đang active. Tạo mới nếu cần.
        
        Returns:
            bool - True nếu connection OK
        """
        try:
            # Check xem connection cũ còn sống không
            if self._ssh_client is not None:
                transport = self._ssh_client.get_transport()
                if transport is not None and transport.is_active():
                    return True
                else:
                    logger.debug("Existing SSH connection is dead, reconnecting...")
                    self._ssh_client.close()
                    self._ssh_client = None
            
            # Tạo connection mới
            logger.debug(f"Creating new SSH connection to {self.host}:{self.port}")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Ưu tiên dùng SSH key
            if os.path.exists(self.ssh_key_path):
                try:
                    logger.debug(f"Attempting key-based auth: {self.ssh_key_path}")
                    ssh.connect(
                        hostname=self.host,
                        port=self.port,
                        username=self.username,
                        key_filename=self.ssh_key_path,
                        timeout=10,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    logger.info("✅ SSH connected via key-based authentication")
                    self._ssh_client = ssh
                    return True
                except Exception as key_err:
                    logger.warning(f"Key auth failed: {key_err}, falling back to password")
            
            # Fallback: Password authentication
            if self.password:
                logger.debug("Attempting password-based auth")
                ssh.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=10,
                    look_for_keys=False,
                    allow_agent=False
                )
                logger.info("✅ SSH connected via password authentication")
                self._ssh_client = ssh
                return True
            else:
                logger.error("❌ No SSH key and no password available")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to establish SSH connection: {e}")
            return False
    
    def _handle_connection_failure(self, reason):
        """
        Xử lý khi connection fail: Increment counter, log timestamp.
        
        Args:
            reason: Mô tả lý do fail
        """
        self._connection_failures += 1
        self._last_failure_time = time.time()
        
        logger.warning(
            f"⚠️ SSH connection failure #{self._connection_failures}: {reason}"
        )
        
        # Close connection cũ để tránh leak
        if self._ssh_client:
            try:
                self._ssh_client.close()
            except:
                pass
            self._ssh_client = None
    
    def _backoff_sleep(self, attempt):
        """
        Exponential backoff: 2s → 4s → 8s
        
        Args:
            attempt: Lần thử thứ mấy (1, 2, 3...)
        """
        sleep_time = self.base_timeout * (2 ** (attempt - 1))
        logger.debug(f"Sleeping {sleep_time}s before retry...")
        time.sleep(sleep_time)
    
    def _send_critical_alert(self, failed_command):
        """
        Gửi email critical alert khi SSH fail 3 lần liên tiếp.
        
        Chỉ gửi 1 lần cho mỗi batch failures để tránh spam.
        
        Args:
            failed_command: Command bị fail
        """
        # Tránh spam: chỉ gửi 1 email per failure batch
        if self._alert_sent:
            logger.debug("Critical alert already sent for this failure batch")
            return
        
        logger.critical(
            f"🚨 CRITICAL: SSH to {self.host} failed {self.max_retries} times! "
            f"Command: {failed_command}"
        )
        
        try:
            # Import ở đây để tránh circular dependency
            from config import (
                SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_RECIPIENTS
            )
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            
            subject = f"🚨 [CRITICAL] SOAR SSH Failure - Cannot reach {self.host}"
            body = self._build_critical_email_body(failed_command)
            
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = SMTP_USER
            msg["To"] = ", ".join(ALERT_RECIPIENTS)
            msg.attach(MIMEText(body, "html", "utf-8"))
            
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            
            logger.critical("✅ Critical SSH failure alert email sent")
            self._alert_sent = True
            
        except Exception as e:
            logger.error(f"❌ Failed to send critical alert email: {e}")
    
    def _build_critical_email_body(self, failed_command):
        """Tạo HTML body cho critical alert email."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #d32f2f; background: #ffebee; padding: 15px; border-left: 4px solid #d32f2f;">
                🚨 CRITICAL: SOAR SSH Infrastructure Failure
            </h2>
            
            <div style="background: #fff3cd; border-left: 4px solid #ff9800; padding: 15px; margin: 20px 0;">
                <strong>⚠️ SOAR cannot execute blocking actions on Windows victim!</strong><br>
                <span style="color: #d32f2f;">Attack detected but unable to block attacker IP.</span>
            </div>
            
            <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
                <tr style="background: #f5f5f5;">
                    <td style="padding: 10px; font-weight: bold;">Target Host</td>
                    <td style="padding: 10px; color: #d32f2f; font-weight: bold;">
                        {self.host}:{self.port}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; font-weight: bold;">SSH User</td>
                    <td style="padding: 10px;">{self.username}</td>
                </tr>
                <tr style="background: #f5f5f5;">
                    <td style="padding: 10px; font-weight: bold;">Failure Count</td>
                    <td style="padding: 10px;">
                        <span style="background: #d32f2f; color: white; padding: 4px 12px; border-radius: 4px;">
                            {self._connection_failures} consecutive failures
                        </span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; font-weight: bold;">Failed Command</td>
                    <td style="padding: 10px; font-family: monospace; background: #f5f5f5;">
                        {failed_command[:100]}...
                    </td>
                </tr>
                <tr style="background: #f5f5f5;">
                    <td style="padding: 10px; font-weight: bold;">Last Attempt</td>
                    <td style="padding: 10px;">{timestamp}</td>
                </tr>
            </table>
            
            <div style="margin-top: 30px; padding: 20px; background: #e3f2fd; border-left: 4px solid #2196F3;">
                <h3 style="margin-top: 0; color: #1976D2;">🔧 Required Actions:</h3>
                <ol style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>Check Windows victim is online:</strong> ping {self.host}</li>
                    <li><strong>Verify SSH service running:</strong> Test SSH login manually</li>
                    <li><strong>Check network connectivity:</strong> Firewall rules, routing</li>
                    <li><strong>Review SSH credentials:</strong> Key/password still valid?</li>
                    <li><strong>Check SOAR logs:</strong> /var/log/soar/ssh_manager.log</li>
                </ol>
                <p style="color: #d32f2f; font-weight: bold; margin-top: 15px;">
                    ⚠️ Until resolved, SOAR cannot block attacker IPs on Windows!
                </p>
            </div>
            
            <p style="color: #666; margin-top: 30px; font-size: 12px; border-top: 1px solid #ddd; padding-top: 15px;">
                — SOAR Mini Engine v1.0 | SSH Manager Critical Alert<br>
                This is an automated alert. Do not reply to this email.
            </p>
        </body>
        </html>
        """
    
    def close(self):
        """Đóng SSH connection (cleanup)."""
        if self._ssh_client:
            try:
                self._ssh_client.close()
                logger.debug("SSH connection closed")
            except:
                pass
            self._ssh_client = None
    
    def __del__(self):
        """Destructor: Đảm bảo connection được đóng."""
        self.close()
