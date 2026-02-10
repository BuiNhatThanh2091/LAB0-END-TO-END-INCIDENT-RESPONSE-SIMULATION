"""
ingestion.py — Layer 1: Thu thập log từ Splunk CLI
====================================================
Hai chế độ:
  - DRY_RUN = True  → đọc file JSON local (test trên Windows)
  - DRY_RUN = False → gọi Splunk CLI trên Ubuntu

Mỗi source có 1 parser riêng chuyển raw JSON → list of dict chuẩn.
"""

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from config import (
    DRY_RUN, LOCAL_LOG_DIR, LOCAL_FILES,
    SPLUNK_HOME, SPLUNK_AUTH, SOURCES,
    RELEVANT_EVENT_CODES,
    SCAN_CONN_STATES, SCAN_SIDS, HTTP_SERVER_SIDS,
    WINRM_SIDS, MAILHOG_SIDS,
    EVENT_PROCESS_CREATE, EVENT_NETWORK_CONNECT,
    EVENT_FILE_CREATE, EVENT_PS_SCRIPTBLOCK,
    EVENT_LOGON_SUCCESS, EVENT_LOGON_FAILURE,
    EVENT_OBJECT_ACCESS,
    CRITICAL_FILES,
    UPLOAD_THRESHOLD_KB, DOWNLOAD_THRESHOLD_KB,
)
from logger_setup import setup_logger

logger = setup_logger("ingestion")


# ==============================================================
# SPLUNK CLI
# ==============================================================

class SplunkCLI:
    """Giao tiếp với Splunk Free qua CLI (subprocess)."""

    def __init__(self):
        self.splunk_bin = os.path.join(SPLUNK_HOME, "bin", "splunk")

    def search(self, spl_query, max_results=10000):
        """
        Chạy SPL query qua Splunk CLI.
        Returns: list[dict] — mỗi dict là 1 event.
        """
        cmd = [
            self.splunk_bin, "search",
            spl_query,
            "-output", "json",
            "-maxout", str(max_results),
            "-auth", SPLUNK_AUTH,
        ]
        logger.debug(f"Splunk CLI: {spl_query[:120]}...")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.error(f"Splunk CLI lỗi (code {result.returncode}): "
                             f"{result.stderr[:300]}")
                return []
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error("Splunk CLI timeout (60s)")
            return []
        except FileNotFoundError:
            logger.error(f"Không tìm thấy Splunk binary: {self.splunk_bin}")
            return []

    def _parse_output(self, raw_output):
        """Parse Splunk CLI JSON output (NDJSON — 1 JSON/line)."""
        events = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Splunk CLI trả về {"preview": bool, "result": {...}}
                if "result" in obj:
                    events.append(obj["result"])
                else:
                    events.append(obj)
            except json.JSONDecodeError:
                continue
        return events


# ==============================================================
# LOCAL FILE READER (DRY_RUN mode)
# ==============================================================

def read_local_file(source_name):
    """Đọc file JSON local (1 JSON/line) cho chế độ DRY_RUN."""
    filename = LOCAL_FILES.get(source_name)
    if not filename:
        logger.error(f"Không có file local cho source: {source_name}")
        return []

    filepath = os.path.join(LOCAL_LOG_DIR, filename)
    if not os.path.exists(filepath):
        logger.error(f"File không tồn tại: {filepath}")
        return []

    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error [{filename}] line {line_num}: {e}")
    logger.info(f"[DRY_RUN] Đọc {len(events)} events từ {filename}")
    return events


# ==============================================================
# TIMESTAMP HELPERS
# ==============================================================

def parse_zeek_ts(ts_value):
    """Zeek timestamp: epoch float (e.g., 1731925575.123456)."""
    try:
        epoch = float(ts_value)
        return epoch, datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return 0, None


def parse_iso_ts(iso_string):
    """Parse ISO 8601 timestamp → (epoch_float, iso_string)."""
    if not iso_string:
        return 0, None
    try:
        # Xử lý nhiều format ISO: "2025-11-18T11:06:15.707352Z",
        # "2025-11-18T11:06:15.707352+0000", "2025-11-18T11:01:44.369Z"
        cleaned = iso_string.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt.timestamp(), dt.isoformat()
    except (ValueError, TypeError):
        return 0, iso_string


# ==============================================================
# ZEEK PARSER
# ==============================================================

def parse_zeek_events(raw_events, checkpoint_epoch=0):
    """
    Parse Zeek conn logs → list of normalized dicts.

    Phân loại event_type dựa trên conn_state, dest_port VÀ volume transfer:
      - "port_scan"       : conn_state ∈ {REJ, S0, OTH, RSTR, ...}
      - "http_8080"       : id.resp_p == 8080
      - "smb_connection"  : id.resp_p == 445
      - "winrm_connection": id.resp_p == 5985
      - "winrm_upload"    : id.resp_p == 5985 + orig_bytes >= threshold (R8)
      - "winrm_download"  : id.resp_p == 5985 + resp_bytes >= threshold (R9)
      - "file_upload"     : FTP/SSH + high orig_bytes
      - "file_download"   : FTP/SSH + high resp_bytes
      - "mailhog_access"  : id.resp_p == 8025
      - "network_conn"    : mọi kết nối khác
    """
    parsed = []
    for raw_splunk_event in raw_events:
        # Extract JSON từ _raw field
        raw_json_str = raw_splunk_event.get("_raw", "")
        if not raw_json_str:
            continue
            
        try:
            raw = json.loads(raw_json_str)
        except json.JSONDecodeError:
            continue
        # Lấy timestamp
        ts_val = raw.get("ts")
        epoch, iso = parse_zeek_ts(ts_val)

        # Chỉ xử lý events mới hơn checkpoint
        if epoch <= checkpoint_epoch:
            continue

        src_ip = raw.get("id.orig_h", "")
        dst_ip = raw.get("id.resp_h", "")
        dst_port = _safe_int(raw.get("id.resp_p", 0))
        conn_state = raw.get("conn_state", "")
        duration = _safe_float(raw.get("duration", 0))
        orig_bytes = _safe_int(raw.get("orig_bytes", 0))
        resp_bytes = _safe_int(raw.get("resp_bytes", 0))
        service = raw.get("service", "")

        # --- Phân loại event_type ---
        # Calculate transfer volumes in KB for thresholds
        orig_kb = orig_bytes / 1024.0 if orig_bytes > 0 else 0
        resp_kb = resp_bytes / 1024.0 if resp_bytes > 0 else 0
        
        event_type = "network_conn"

        # Priority 1: Volume-based classification (R8/R9 upload/download detection)
        if orig_kb >= UPLOAD_THRESHOLD_KB:
            if dst_port in [5985, 5986]:  # WinRM
                event_type = "winrm_upload"
            elif dst_port in [21, 22]:  # FTP/SSH
                event_type = "file_upload"
            elif dst_port in [80, 443]:  # HTTP/HTTPS
                event_type = "http_upload"
            else:
                event_type = "suspicious_upload"
        elif resp_kb >= DOWNLOAD_THRESHOLD_KB:
            if dst_port in [5985, 5986]:  # WinRM
                event_type = "winrm_download"
            elif dst_port in [21, 22]:  # FTP/SSH
                event_type = "file_download"
            elif dst_port in [80, 443]:  # HTTP/HTTPS
                event_type = "http_download"
            else:
                event_type = "suspicious_download"
        # Priority 2: Existing port-based classification
        elif conn_state in SCAN_CONN_STATES:
            event_type = "port_scan"
        elif dst_port == 8080:
            event_type = "http_8080"
        elif dst_port == 8025:
            event_type = "mailhog_access"
        elif dst_port == 445:
            event_type = "smb_connection"
        elif dst_port == 5985:
            event_type = "winrm_connection"

        parsed.append({
            "timestamp_epoch": epoch,
            "timestamp_iso": iso,
            "source": "zeek",
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "details": {
                "conn_state": conn_state,
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "orig_kb": round(orig_kb, 2),  # For R8/R9 analysis
                "resp_kb": round(resp_kb, 2),  # For R8/R9 analysis
                "service": service,
                "uid": raw.get("uid", ""),
                "history": raw.get("history", ""),
            },
            "raw": raw,
        })

    logger.info(f"Zeek: parsed {len(parsed)} events (sau checkpoint)")
    return parsed


# ==============================================================
# SURICATA PARSER
# ==============================================================

def parse_suricata_events(raw_events, checkpoint_epoch=0):
    """
    Parse Suricata alert logs → list of normalized dicts.

    Phân loại event_type dựa trên signature_id:
      - "port_scan"     : SID ∈ SCAN_SIDS
      - "http_8080"     : SID ∈ HTTP_SERVER_SIDS
      - "winrm_alert"   : SID ∈ WINRM_SIDS
      - "mailhog_alert" : SID ∈ MAILHOG_SIDS
      - "ids_alert"     : các alert khác
    """
    parsed = []
    for raw_splunk_event in raw_events:
        # Extract JSON từ _raw field
        raw_json_str = raw_splunk_event.get("_raw", "")
        if not raw_json_str:
            continue
            
        try:
            raw = json.loads(raw_json_str)
        except json.JSONDecodeError:
            continue
        # Chỉ xử lý event_type = "alert"
        if raw.get("event_type") != "alert":
            continue

        ts_str = raw.get("timestamp", "")
        epoch, iso = parse_iso_ts(ts_str)

        if epoch <= checkpoint_epoch:
            continue

        src_ip = raw.get("src_ip", "")
        dst_ip = raw.get("dest_ip", "")
        dst_port = _safe_int(raw.get("dest_port", 0))

        # Alert fields
        alert = raw.get("alert", {})
        if isinstance(alert, str):
            # Trường hợp Splunk flatten "alert.signature" thành string
            alert = {}
        signature = alert.get("signature", raw.get("alert.signature", ""))
        sig_id = _safe_int(
            alert.get("signature_id", raw.get("alert.signature_id", 0))
        )
        severity = _safe_int(
            alert.get("severity", raw.get("alert.severity", 3))
        )
        category = alert.get("category", raw.get("alert.category", ""))

        # HTTP fields (nếu có)
        http_ua = raw.get("http", {}).get("http_user_agent",
                          raw.get("http.http_user_agent", ""))

        # --- Phân loại ---
        event_type = "ids_alert"
        if sig_id in SCAN_SIDS:
            event_type = "port_scan"
        elif sig_id in HTTP_SERVER_SIDS:
            event_type = "http_8080"
        elif sig_id in WINRM_SIDS:
            event_type = "winrm_alert"
        elif sig_id in MAILHOG_SIDS:
            event_type = "mailhog_alert"

        parsed.append({
            "timestamp_epoch": epoch,
            "timestamp_iso": iso,
            "source": "suricata",
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "details": {
                "signature": signature,
                "signature_id": sig_id,
                "severity": severity,
                "category": category,
                "http_user_agent": http_ua,
            },
            "raw": raw,
        })

    logger.info(f"Suricata: parsed {len(parsed)} alert events (sau checkpoint)")
    return parsed


# ==============================================================
# WINLOGBEAT PARSER
# ==============================================================

def parse_winlogbeat_events(raw_events, checkpoint_epoch=0):
    """
    Parse Winlogbeat logs → list of normalized dicts.

    Phân loại theo event.code:
      4625 → "brute_force_fail"
      4624 → "logon_success"
      4663 → "file_access"
      4104 → "ps_scriptblock" (sub-classify: ps_bypass, exfil_base64)
      1    → "process_create" (sub-classify: winrm_process nếu wsmprovhost)
      3    → "network_conn"
      11   → "file_create"
    """
    parsed = []
    for raw_splunk_event in raw_events:
        # Extract JSON từ _raw field
        raw_json_str = raw_splunk_event.get("_raw", "")
        if not raw_json_str:
            continue
            
        try:
            raw = json.loads(raw_json_str)
        except json.JSONDecodeError:
            continue
        # Lấy event code
        event_code = str(
            raw.get("event", {}).get("code",
            raw.get("event.code",
            raw.get("winlog", {}).get("event_id", "")))
        )
        if event_code not in RELEVANT_EVENT_CODES:
            continue

        # Timestamp
        ts_str = raw.get("@timestamp",
                  raw.get("timestamp", ""))
        epoch, iso = parse_iso_ts(ts_str)
        if epoch <= checkpoint_epoch:
            continue

        # Event data (nested hoặc flattened)
        winlog = raw.get("winlog", {})
        event_data = winlog.get("event_data", {})

        # Lấy các fields quan trọng
        ip_address = event_data.get("IpAddress") or ""
        logon_type = event_data.get("LogonType") or ""
        image = event_data.get("Image") or ""
        cmd_line = event_data.get("CommandLine") or ""
        script_text = event_data.get("ScriptBlockText") or ""
        target_file = event_data.get("TargetFilename") or ""
        object_name = event_data.get("ObjectName") or ""
        access_mask = event_data.get("AccessMask") or ""
        src_ip = event_data.get("SourceIp") or ""
        dst_ip = event_data.get("DestinationIp") or ""
        dst_port = _safe_int(event_data.get("DestinationPort") or 0)
        src_port = _safe_int(event_data.get("SourcePort") or 0)
        host_name = raw.get("host", {}).get("name", "")
        user_name = (
            winlog.get("user", {}).get("name", "")
            or raw.get("user", {}).get("name", "")
        )

        # --- Phân loại chi tiết ---
        event_type, detail_src, detail_dst = _classify_winlogbeat(
            event_code, ip_address, logon_type, image, cmd_line,
            script_text, object_name, src_ip, dst_ip, dst_port,
        )

        parsed.append({
            "timestamp_epoch": epoch,
            "timestamp_iso": iso,
            "source": "winlogbeat",
            "event_type": event_type,
            "src_ip": detail_src,
            "dst_ip": detail_dst,
            "dst_port": dst_port,
            "details": {
                "event_code": event_code,
                "ip_address": ip_address,
                "logon_type": logon_type,
                "image": image,
                "command_line": cmd_line,
                "script_block_text": script_text[:500] if script_text else "",
                "target_filename": target_file,
                "object_name": object_name,
                "access_mask": access_mask,
                "host_name": host_name,
                "user_name": user_name,
            },
            "raw": raw,
        })

    logger.info(f"Winlogbeat: parsed {len(parsed)} events (sau checkpoint)")
    return parsed


def _classify_winlogbeat(event_code, ip_address, logon_type, image,
                         cmd_line, script_text, object_name,
                         src_ip, dst_ip, dst_port):
    """
    Phân loại event Winlogbeat thành event_type chi tiết.
    Returns: (event_type, source_ip, dest_ip)
    """
    # ---- Event 4625: Failed Logon ----
    if event_code == EVENT_LOGON_FAILURE:
        if logon_type == "3" and ip_address and ip_address != "-":
            return "brute_force_fail", ip_address, ""
        return "logon_failure_other", ip_address, ""

    # ---- Event 4624: Successful Logon ----
    if event_code == EVENT_LOGON_SUCCESS:
        if logon_type == "3" and ip_address and ip_address != "-":
            return "logon_success", ip_address, ""
        return "logon_success_local", "", ""

    # ---- Event 4663: Object Access ----
    if event_code == EVENT_OBJECT_ACCESS:
        # Kiểm tra có phải file nhạy cảm không
        obj_lower = object_name.lower()
        is_critical = any(cf.lower() in obj_lower for cf in CRITICAL_FILES)
        if is_critical:
            return "file_access_critical", "", ""
        return "file_access", "", ""

    # ---- Event 4104: PowerShell ScriptBlock ----
    if event_code == EVENT_PS_SCRIPTBLOCK:
        combined = (cmd_line + " " + script_text).lower()

        # R6: -ExecutionPolicy Bypass
        if "executionpolicy" in combined and "bypass" in combined:
            return "ps_bypass", "", ""

        # R7: ToBase64String + file nhạy cảm
        if "tobase64string" in combined:
            has_sensitive = any(
                cf.lower() in combined for cf in CRITICAL_FILES
            )
            if has_sensitive:
                return "exfil_base64", "", ""
            return "ps_base64_generic", "", ""

        return "ps_scriptblock", "", ""

    # ---- Event 1: Process Create ----
    if event_code == EVENT_PROCESS_CREATE:
        image_lower = image.lower()

        # WinRM shell process
        if "wsmprovhost.exe" in image_lower:
            return "winrm_process", "", ""

        # PowerShell bypass via CommandLine
        cmd_lower = cmd_line.lower()
        if "executionpolicy" in cmd_lower and "bypass" in cmd_lower:
            return "ps_bypass", "", ""

        return "process_create", "", ""

    # ---- Event 3: Network Connection ----
    if event_code == EVENT_NETWORK_CONNECT:
        return "network_conn", src_ip, dst_ip

    # ---- Event 11: File Create ----
    if event_code == EVENT_FILE_CREATE:
        return "file_create", "", ""

    return "unknown", "", ""


# ==============================================================
# MAIN POLL FUNCTION
# ==============================================================

def poll_all_sources(checkpoint_mgr):
    """
    Poll tất cả 3 sources → trả về tuple (zeek_events, suricata_events,
    winlogbeat_events) đã parsed + filtered theo checkpoint.
    """
    ckpt = checkpoint_mgr.load_checkpoint()

    if DRY_RUN:
        logger.info("=== [DRY_RUN] Đọc từ file local ===")
        zeek_raw = read_local_file("zeek")
        suri_raw = read_local_file("suricata")
        winlog_raw = read_local_file("winlogbeat")
    else:
        logger.info("=== Poll Splunk CLI (parallel) ===")
        splunk = SplunkCLI()

        # Chạy 3 queries song song để giảm thời gian ~3x
        queries = {
            "zeek": 'source="/var/log/vector/zeek_filter_traffic.json" earliest=-2m | fields _raw | head 500',
            "suricata": 'source="/var/log/vector/suricata_traffic.json" earliest=-2m | fields _raw | head 300',
            "winlogbeat": 'source="/var/log/vector/winlogbeat-debug.json" earliest=-2m | fields _raw | head 1000',
        }
        results = {}

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(splunk.search, q): name
                for name, q in queries.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    logger.error(f"Splunk query '{name}' failed: {e}")
                    results[name] = []

        zeek_raw = results.get("zeek", [])
        suri_raw = results.get("suricata", [])
        winlog_raw = results.get("winlogbeat", [])

    # Parse mỗi source
    zeek_events = parse_zeek_events(zeek_raw, ckpt.get("zeek", 0))
    suri_events = parse_suricata_events(suri_raw, ckpt.get("suricata", 0))
    winlog_events = parse_winlogbeat_events(winlog_raw, ckpt.get("winlogbeat", 0))

    return zeek_events, suri_events, winlog_events


# ==============================================================
# HELPERS
# ==============================================================

def _safe_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_float(val, default=0.0):
    try:
        return float(val)
    except (ValueError, TypeError):
        return default
