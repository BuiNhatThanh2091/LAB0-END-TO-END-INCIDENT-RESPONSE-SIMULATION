"""
config.py — Cấu hình toàn bộ SOAR Engine
==========================================
Chỉnh sửa file này trước khi chạy SOAR trên Ubuntu Monitor.
"""

import os


# ==============================================================
# AUTO LOAD .ENV FILE (if exists)
# ==============================================================
def _load_env_file():
    """Load environment variables from .env file if it exists."""
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        loaded_count = 0
        with open(env_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    try:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")  # Remove quotes
                        if key:  # Only set if key is not empty
                            os.environ[key] = value
                            loaded_count += 1
                    except ValueError:
                        # Skip malformed lines
                        continue
        print(f"✅ Loaded {loaded_count} environment variables from .env file")
        return True
    return False

# Auto-load .env file when config.py is imported
_env_loaded = _load_env_file()

# ============================================================
# MÔI TRƯỜNG CHẠY
# ============================================================
# True  = đọc log từ file local (test trên Windows)
# False = poll Splunk CLI trên Ubuntu (production)
DRY_RUN = False

# Thư mục chứa log mẫu khi DRY_RUN = True
LOCAL_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")

# ============================================================
# SPLUNK CLI
# ============================================================
SPLUNK_HOME = "/opt/splunk"
SPLUNK_AUTH = "admin:23162091"          # <<< ĐỔI LẠI

POLL_INTERVAL = 15  # giây — chu kỳ poll Splunk

# Đường dẫn source trong Splunk (trùng với Vector output)
SOURCES = {
    "zeek":       "/var/log/vector/zeek_filter_traffic.json",
    "suricata":   "/var/log/vector/suricata_traffic.json",
    "winlogbeat": "/var/log/vector/winlogbeat-debug.json",
}

# Tên file local tương ứng (dùng khi DRY_RUN = True)
LOCAL_FILES = {
    "zeek":       "zeek_filter_traffic.json",
    "suricata":   "suricata_traffic.json",
    "winlogbeat": "winlogbeat-debug.json",
}

# ============================================================
# ĐỊA CHỈ IP TRONG LAB
# ============================================================
VICTIM_IP  = "10.10.10.129"
MONITOR_IP = "10.10.10.128"   # Ubuntu server chạy SOAR

# ============================================================
# WHITELIST
# ============================================================
# IP trong whitelist vẫn bị theo dõi và tính điểm,
# nhưng ngưỡng block cao hơn (60 thay vì 35).
WHITELIST_IPS = {
    "127.0.0.1","192.168.225.135","10.10.10.128","10.10.10.1",   # Ubuntu monitor và infrastructure IPs
    # Thêm IP whitelist khác tại đây
}

# ============================================================
# SCORING RULES — Điểm cho mỗi loại sự kiện
# ============================================================

# R1: Beacon / Recon Scan
#     Mỗi batch 3 scan events → cộng điểm
SCORE_BEACON_SCAN_NON_WL = 20     # IP ngoài whitelist: +20 / batch 3
SCORE_BEACON_SCAN_WL     = 5     # IP trong whitelist: +5 / batch 3
SCAN_BATCH_SIZE           = 3

# R2: HTTP 8080 — Hosting malicious web server
#     Điểm cộng vào IP đang HOSTING server (resp_h trên port 8080)
SCORE_HTTP_8080 = 20             # +15 mỗi connection đến server

# R3: Brute Force (Failed Logon)
#     Mỗi batch 3 Event 4625 → cộng điểm cho attacker IP
SCORE_BRUTE_FORCE  = 30          # +30 / batch 3 fails
BRUTE_BATCH_SIZE   = 2

# R4: WinRM Session
#     Mỗi session (logon từ non-WL IP, gap > 1h = session mới)
SCORE_WINRM_SESSION = 30         # +30 / session

# R5: Critical File Access (Event 4663)
SCORE_FILE_ACCESS = 25           # +25 / event

# R6: PowerShell -ExecutionPolicy Bypass
SCORE_PS_BYPASS = 40             # +40 / detection

# R7: Exfiltration via Base64 encoding
SCORE_EXFIL_BASE64 = 35          # +35 / detection

# R8: Excessive Upload Detection (via Zeek orig_bytes)
# Phát hiện khi attacker đẩy tool/malware vào victim (orig_bytes lớn)
SCORE_EXCESSIVE_UPLOAD = 25      # +25 / detection
UPLOAD_THRESHOLD_KB = 50         # ≥50KB upload trong 1 session → cộng điểm

# R9: Excessive Download/Exfiltration Detection (via Zeek resp_bytes)
# Phát hiện khi attacker lấy dữ liệu từ victim ra ngoài (resp_bytes lớn)
SCORE_EXCESSIVE_DOWNLOAD = 30    # +30 / detection
DOWNLOAD_THRESHOLD_KB = 100      # ≥100KB download trong 1 session → cộng điểm
EXFIL_THRESHOLD_KB = 200         # ≥200KB download → coi như exfiltration nghiêm trọng
SCORE_MAJOR_EXFILTRATION = 50   # +50 / major exfiltration (>= 200KB)

# ============================================================
# NGƯỠNG QUYẾT ĐỊNH (THRESHOLDS)
# ============================================================
THRESHOLD_NON_WL = 35   # IP ngoài whitelist: ≥35 → auto-block
THRESHOLD_WL     = 60   # IP trong whitelist: ≥60 → block + email

# ============================================================
# AUTO-UNBLOCK
# ============================================================
UNBLOCK_AFTER_SECONDS = 3600   # 1 giờ sau khi block → tự động unblock

# ============================================================
# DECAY MECHANISM (Phase 2)
# ============================================================
# Giảm điểm tự động cho IP không hoạt động để giảm False Positive
DECAY_ENABLED = True                    # Bật/tắt decay
DECAY_INTERVAL_SECONDS = 3600          # 1 giờ = 1 decay cycle
DECAY_AMOUNT_PER_CYCLE = 10            # Trừ 10 điểm mỗi giờ không hoạt động
DECAY_MIN_SCORE = 0                    # Không decay xuống dưới 0

# Ví dụ: IP có 50 điểm, không hoạt động 3 giờ
#   → Sau 1h: 50 - 10 = 40
#   → Sau 2h: 40 - 10 = 30
#   → Sau 3h: 30 - 10 = 20

# ============================================================
# THREAT INTELLIGENCE MOCK (Phase 3)
# ============================================================
# Giả lập tra cứu reputation database (VirusTotal/AbuseIPDB)
THREAT_INTEL_ENABLED = True            # Bật/tắt TI enrichment
THREAT_INTEL_DB_PATH = os.path.join(
    os.path.dirname(__file__), "data", "threat_intel_db.json"
)

# Scoring boost khi IP match trong TI database
TI_SCORE_MALICIOUS = 50                # IP nằm trong blacklist → +50 điểm
TI_SCORE_SUSPICIOUS = 20               # IP đáng ngờ (low confidence) → +20 điểm
TI_SCORE_CLEAN = 0                     # IP sạch → không cộng điểm

# Threshold để trigger TI lookup (tránh lookup mọi IP)
TI_LOOKUP_THRESHOLD = 20               # Chỉ lookup IP có score ≥ 20

# ============================================================
# EDR — PROCESS CONTAINMENT (Phase 4)
# ============================================================
# Tính năng EDR: Kill malicious processes trên endpoint
# Bổ sung cho Network Containment (iptables/netsh)
PROCESS_CONTAINMENT_ENABLED = True    # Bật/tắt EDR module
EDR_KILL_WINRM_ON_BLOCK = True        # Kill WinRM shells khi block IP
EDR_VERIFY_KILL = True                # Verify process đã chết sau kill
EDR_LOGOFF_SCORE_THRESHOLD = 120      # Logoff khi score vượt ngưỡng + evidence critical
EDR_REQUIRE_CRITICAL_EVIDENCE = True  # Bắt buộc evidence Winlogbeat trước khi logoff
EDR_USER_MSG_TIMEOUT_SECONDS = 30     # Thời gian hiển thị popup msg.exe
EDR_USER_MSG_TEXT = (
    "He thong phat hien ma doc. Phien lam viec bi ngat de bao ve du lieu. "
    "Vui long lien he IT."
)
EDR_SUSPEND_FALLBACK_TO_KILL = True   # Suspend fail -> fallback kill + alert

# ============================================================
# SURICATA SIGNATURE IDs — Phân loại alert
# ============================================================
SCAN_SIDS = {1007300, 1101500}
#   1007300 — RECON TCP SYN scan (external->LAN)
#   1101500 — ET RECON Nmap TCP SYN scan (internal)

HTTP_SERVER_SIDS = {1007200, 1007201}
#   1007200 — Python http.server response (Server: SimpleHTTP)
#   1007201 — ACCESS to 8080 (candidate python http.server)

MAILHOG_SIDS = {1007001}
#   1007001 — MailHog UI access (request)

WINRM_SIDS = {2002000, 2002002, 2002102, 2002103, 2002104}
#   2002000 — WINRM client detected - Microsoft WinRM Client UA
#   2002002 — WINRM request to /wsman
#   2002102 — WINRM encrypted session (HTTP-SPNEGO)
#   2002103 — WINRM SOAP request inside encrypted multipart
#   2002104 — WINRM encrypted response (multipart/encrypted 200 OK)

# ============================================================
# ZEEK — Trạng thái kết nối chỉ scan
# ============================================================
SCAN_CONN_STATES = {"REJ", "S0", "OTH", "RSTR", "RSTO", "RSTOS0"}

# ============================================================
# WINLOGBEAT — Event Codes quan trọng
# ============================================================
EVENT_PROCESS_CREATE   = "1"    # Sysmon: Process Create
EVENT_NETWORK_CONNECT  = "3"    # Sysmon: Network Connection
EVENT_FILE_CREATE      = "11"   # Sysmon: File Create
EVENT_PS_SCRIPTBLOCK   = "4104" # PowerShell: ScriptBlock Logging
EVENT_LOGON_SUCCESS    = "4624" # Security: Successful Logon
EVENT_LOGON_FAILURE    = "4625" # Security: Failed Logon
EVENT_OBJECT_ACCESS    = "4663" # Security: Object Access (file audit)

RELEVANT_EVENT_CODES = {
    EVENT_PROCESS_CREATE, EVENT_NETWORK_CONNECT, EVENT_FILE_CREATE,
    EVENT_PS_SCRIPTBLOCK, EVENT_LOGON_SUCCESS, EVENT_LOGON_FAILURE,
    EVENT_OBJECT_ACCESS,
}

# ============================================================
# FILE NHẠY CẢM (Critical Files)
# ============================================================
CRITICAL_FILES = {
    "data_important.txt",
    # Thêm file nhạy cảm khác tại đây
}

# ============================================================
# WINRM SESSION — Khoảng cách tối đa coi là cùng 1 session
# ============================================================
WINRM_SESSION_GAP = 3600   # 1 giờ (giây)

# ============================================================
# CROSS-SOURCE DEDUP — Cửa sổ thời gian gộp event trùng
# ============================================================
DEDUP_WINDOW_SECONDS = 2   # Events cùng IP + port + type trong 2s = 1 event

# ============================================================
# WINDOWS SSH (để SOAR block IP trên máy victim)
# ============================================================
# 🔐 SECURITY: Use environment variables for credentials
# 
# Method 1: Export environment variables:
#    export SSH_USER="thanh"
#    export SSH_PASS="your_password" 
#    export SSH_KEY_PATH="/home/user/.ssh/id_rsa"
#
# Method 2: Create .env file (recommended for development):
#    cp .env.example .env
#    # Edit .env with your credentials
#    # Ensure .env is in .gitignore!
#
# Method 3: SSH Key Authentication (RECOMMENDED for production):
#    ssh-keygen -t rsa -b 4096 -C "soar@company.com"
#    ssh-copy-id thanh@10.10.10.129

WIN_SSH_HOST = "10.10.10.129"
WIN_SSH_PORT = 22

# SSH credentials - Use environment variables for security  
WIN_SSH_USER = os.getenv("SSH_USER", "thanh")
WIN_SSH_PASS = os.getenv("SSH_PASS", "thanh")  # Fallback password (not recommended)

# Handle SSH key path - empty string from .env should be treated as None
ssh_key_env = os.getenv("SSH_KEY_PATH", "")
WIN_SSH_KEY_PATH = ssh_key_env if ssh_key_env else os.path.expanduser("~/.ssh/id_rsa")

# ============================================================
# EMAIL ALERT (Gmail SMTP)
# ============================================================
# ⚠️ BEST PRACTICE: Đặt SMTP credentials vào environment variables
#    export SMTP_USER="your_email@gmail.com"
#    export SMTP_PASS="your_app_password"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT   = 587

# SMTP credentials - Use environment variables for security
SMTP_USER = os.getenv("SMTP_USER", "your_email@gmail.com")  
SMTP_PASS = os.getenv("SMTP_PASS", "your_app_password_here")  
ALERT_RECIPIENTS = os.getenv("ALERT_RECIPIENTS", "admin@company.com").split(",")

# Clean up recipient list (remove empty strings)
ALERT_RECIPIENTS = [email.strip() for email in ALERT_RECIPIENTS if email.strip()]

# ============================================================
# PATHS — File lưu trạng thái
# ============================================================
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT_FILE = os.path.join(BASE_DIR, "checkpoint.json")
STATE_FILE      = os.path.join(BASE_DIR, "ip_state.json")
LOG_FILE        = os.path.join(BASE_DIR, "soar.log")