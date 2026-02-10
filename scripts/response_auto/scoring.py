"""
scoring.py — Layer 3: Zero Trust Risk Scoring Engine
======================================================
7 scoring rules áp dụng per-IP:

  R1  Beacon/Recon Scan     +5/batch10 (non-WL) | +1/batch10 (WL)
  R2  HTTP 8080 Hosting     +15 / connection
  R3  Brute Force           +20/batch5 fails (non-WL→WL) | email (WL→any)
  R4  WinRM Session         +30 / session
  R5  Critical File Access  +25 / event 4663
  R6  PowerShell Bypass     +40 / detection
  R7  Exfil Base64          +35 / detection

State per IP được lưu xuyên suốt các polling cycles thông qua ip_state.
"""

import time
from config import (
    WHITELIST_IPS,
    SCORE_BEACON_SCAN_NON_WL, SCORE_BEACON_SCAN_WL, SCAN_BATCH_SIZE,
    SCORE_HTTP_8080,
    SCORE_BRUTE_FORCE, BRUTE_BATCH_SIZE,
    SCORE_WINRM_SESSION, WINRM_SESSION_GAP,
    SCORE_FILE_ACCESS,
    SCORE_PS_BYPASS,
    SCORE_EXFIL_BASE64,
    # R8/R9: Upload/Download detection
    SCORE_EXCESSIVE_UPLOAD, UPLOAD_THRESHOLD_KB,
    SCORE_EXCESSIVE_DOWNLOAD, DOWNLOAD_THRESHOLD_KB,
    SCORE_MAJOR_EXFILTRATION, EXFIL_THRESHOLD_KB,
    # Phase 2: Decay mechanism
    DECAY_ENABLED, DECAY_INTERVAL_SECONDS, DECAY_AMOUNT_PER_CYCLE, DECAY_MIN_SCORE,
)
from logger_setup import setup_logger

logger = setup_logger("scoring")


class ScoringEngine:
    """
    Nhận dict {ip: [events]} từ Layer 2 và ip_state từ checkpoint.
    Áp dụng 7 scoring rules, cập nhật ip_state, trả về danh sách
    score changes để Layer 4 quyết định.
    """

    def __init__(self, ip_state, checkpoint_mgr):
        self.ip_state = ip_state
        self.checkpoint_mgr = checkpoint_mgr

    def apply_decay(self):
        """
        Phase 2: Decay Mechanism - Giảm điểm tự động cho IP không hoạt động.
        
        Logic:
          - Với mỗi IP trong ip_state:
            - Tính thời gian từ lần activity cuối (last_activity_time)
            - Nếu > DECAY_INTERVAL_SECONDS → Trừ DECAY_AMOUNT_PER_CYCLE điểm
            - Không decay xuống dưới DECAY_MIN_SCORE
            - Không decay IP đang bị blocked (để avoid premature unblock)
        
        Mục đích: Giảm False Positive - IP scan nhẹ 1 lần cách đây 2 ngày
                  không nên còn điểm cao.
        """
        if not DECAY_ENABLED:
            return
        
        current_time = time.time()
        decay_applied_count = 0
        
        for ip, data in self.ip_state.items():
            # Skip IP đang bị blocked (decay chỉ áp dụng cho IP active)
            if data.get("blocked", False):
                continue
            
            # Skip nếu score đã = 0
            current_score = data.get("total_score", 0)
            if current_score <= DECAY_MIN_SCORE:
                continue
            
            # Lấy last_activity_time (hoặc init nếu chưa có)
            last_activity = data.get("last_activity_time", current_time)
            time_since_activity = current_time - last_activity
            
            # Tính số decay cycles đã qua
            decay_cycles = int(time_since_activity // DECAY_INTERVAL_SECONDS)
            
            if decay_cycles > 0:
                # Tính decay amount
                decay_amount = decay_cycles * DECAY_AMOUNT_PER_CYCLE
                new_score = max(DECAY_MIN_SCORE, current_score - decay_amount)
                actual_decay = current_score - new_score
                
                if actual_decay > 0:
                    data["total_score"] = new_score
                    data["last_decay_time"] = current_time
                    
                    # Log decay event
                    data.setdefault("rules_log", []).append({
                        "time": current_time,
                        "rule": "DECAY",
                        "points": -actual_decay,
                        "reason": f"Không hoạt động {decay_cycles}h → trừ {actual_decay} điểm"
                    })
                    
                    decay_applied_count += 1
                    logger.info(
                        f"[DECAY] {ip}: {current_score} → {new_score} "
                        f"(-{actual_decay} sau {decay_cycles}h không hoạt động)"
                    )
        
        if decay_applied_count > 0:
            logger.info(f"✅ Decay applied to {decay_applied_count} IPs")

    def process(self, ip_events):
        """
        Áp dụng tất cả rules cho mỗi IP.

        Args:
            ip_events: dict {ip: [normalized_events]}

        Returns:
            list of dicts: [
                {"ip": str, "rule": str, "points": int, "reason": str},
                ...
            ]
        """
        all_changes = []

        for ip, events in ip_events.items():
            ip_data = self.checkpoint_mgr.get_or_create_ip(self.ip_state, ip)
            is_whitelist = ip in WHITELIST_IPS

            # Áp dụng từng rule
            changes = []
            changes += self._r1_beacon_scan(ip, ip_data, events, is_whitelist)
            changes += self._r2_http_8080(ip, ip_data, events)
            changes += self._r3_brute_force(ip, ip_data, events, is_whitelist)
            changes += self._r4_winrm_session(ip, ip_data, events)
            changes += self._r5_file_access(ip, ip_data, events)
            changes += self._r6_ps_bypass(ip, ip_data, events)
            changes += self._r7_exfil_base64(ip, ip_data, events)
            changes += self._r8_upload_detection(ip, ip_data, events)
            changes += self._r9_download_detection(ip, ip_data, events)

            # Phase 2: Update last_activity_time nếu có events
            if events:
                ip_data["last_activity_time"] = time.time()

            # Cập nhật total score
            for change in changes:
                ip_data["total_score"] += change["points"]
                ip_data["rules_log"].append({
                    "time": time.time(),
                    "rule": change["rule"],
                    "points": change["points"],
                    "reason": change["reason"],
                })

            if changes:
                logger.info(
                    f"[{ip}] {'(WL) ' if is_whitelist else ''}"
                    f"Score: {ip_data['total_score']} "
                    f"(+{sum(c['points'] for c in changes)} từ "
                    f"{len(changes)} rules)"
                )

            all_changes += changes

        return all_changes

    # ==============================================================
    # R1: BEACON / RECON SCAN
    # ==============================================================

    def _r1_beacon_scan(self, ip, ip_data, events, is_whitelist):
        """
        Đếm scan events (port_scan).
        Mỗi batch SCAN_BATCH_SIZE (10) events → cộng điểm.
        Whitelist: +1/batch | Non-whitelist: +5/batch
        """
        scan_events = [e for e in events if e["event_type"] == "port_scan"]
        if not scan_events:
            return []

        # Cộng dồn vào tổng
        ip_data["scan_count"] += len(scan_events)
        total = ip_data["scan_count"]
        old_batches = ip_data["scan_batches_scored"]
        new_batches = total // SCAN_BATCH_SIZE

        if new_batches <= old_batches:
            return []

        batches_to_score = new_batches - old_batches
        ip_data["scan_batches_scored"] = new_batches

        points_per_batch = (
            SCORE_BEACON_SCAN_WL if is_whitelist else SCORE_BEACON_SCAN_NON_WL
        )
        total_points = batches_to_score * points_per_batch

        return [{
            "ip": ip,
            "rule": "R1_BEACON_SCAN",
            "points": total_points,
            "reason": (
                f"{batches_to_score} batch(es) × {SCAN_BATCH_SIZE} scan events"
                f" = +{total_points} (total scan: {total},"
                f" {'WL' if is_whitelist else 'non-WL'})"
            ),
        }]

    # ==============================================================
    # R2: HTTP 8080 — HOSTING MALICIOUS WEB SERVER
    # ==============================================================

    def _r2_http_8080(self, ip, ip_data, events):
        """
        IP hosting web server trên port 8080.
        Mỗi connection đến server → +15 điểm cho hosting IP.

        Lưu ý: Trong group_by_ip (correlation.py), events http_8080 đã được
        gán vào IP hosting (resp_h / dest_ip).
        """
        http_events = [e for e in events if e["event_type"] == "http_8080"]
        if not http_events:
            return []

        points = len(http_events) * SCORE_HTTP_8080

        return [{
            "ip": ip,
            "rule": "R2_HTTP_8080",
            "points": points,
            "reason": (
                f"{len(http_events)} connection(s) đến HTTP server 8080"
                f" = +{points}"
            ),
        }]

    # ==============================================================
    # R3: BRUTE FORCE (Failed Logon)
    # ==============================================================

    def _r3_brute_force(self, ip, ip_data, events, is_whitelist):
        """
        Event 4625 từ non-WL IP→ WL target: +20 per batch 5 fails.
        WL IP brute force: chỉ email notification (0 điểm).

        Không có cooldown — mỗi batch 5 fail = +20 ngay lập tức.
        """
        fail_events = [
            e for e in events if e["event_type"] == "brute_force_fail"
        ]
        if not fail_events:
            return []

        changes = []

        if is_whitelist:
            # Whitelist IP brute forcing → đánh dấu cần gửi email, 0 điểm
            changes.append({
                "ip": ip,
                "rule": "R3_BRUTE_FORCE_WL_EMAIL",
                "points": 0,
                "reason": (
                    f"Whitelist IP {ip} phát hiện brute force"
                    f" ({len(fail_events)} fails) → GỬI EMAIL"
                ),
            })
        else:
            # Non-whitelist → cộng điểm theo batch
            ip_data["fail_count"] += len(fail_events)
            total = ip_data["fail_count"]
            old_batches = ip_data["fail_batches_scored"]
            new_batches = total // BRUTE_BATCH_SIZE

            if new_batches > old_batches:
                batches_to_score = new_batches - old_batches
                ip_data["fail_batches_scored"] = new_batches
                total_points = batches_to_score * SCORE_BRUTE_FORCE

                changes.append({
                    "ip": ip,
                    "rule": "R3_BRUTE_FORCE",
                    "points": total_points,
                    "reason": (
                        f"{batches_to_score} batch(es) × {BRUTE_BATCH_SIZE}"
                        f" fail logons = +{total_points}"
                        f" (total fails: {total})"
                    ),
                })

        return changes

    # ==============================================================
    # R4: WINRM SESSION
    # ==============================================================

    def _r4_winrm_session(self, ip, ip_data, events):
        """
        Detect WinRM session = Event 4624 (LogonType=3) + wsmprovhost.exe
        + Suricata WINRM alerts.

        Session definition: Tất cả events từ cùng IP trong khoảng
        WINRM_SESSION_GAP (1h) = 1 session.
        Nếu gap > 1h → session mới → +30.
        """
        winrm_indicators = [
            e for e in events
            if e["event_type"] in (
                "logon_success", "winrm_alert",
                "winrm_connection", "winrm_process",
            )
        ]
        if not winrm_indicators:
            return []

        # Lấy timestamps của WinRM activity
        winrm_times = sorted(
            e["timestamp_epoch"] for e in winrm_indicators
            if e["timestamp_epoch"] > 0
        )
        if not winrm_times:
            return []

        # Tìm session mới (gap > WINRM_SESSION_GAP so với sessions đã biết)
        existing_sessions = ip_data.get("winrm_session_times", [])
        new_session_count = 0

        for t in winrm_times:
            is_new = True
            # Kiểm tra với tất cả session times đã biết
            for existing_t in existing_sessions:
                if abs(t - existing_t) <= WINRM_SESSION_GAP:
                    is_new = False
                    break
            if is_new:
                existing_sessions.append(t)
                new_session_count += 1

        ip_data["winrm_session_times"] = existing_sessions

        if new_session_count == 0:
            return []

        points = new_session_count * SCORE_WINRM_SESSION

        return [{
            "ip": ip,
            "rule": "R4_WINRM_SESSION",
            "points": points,
            "reason": (
                f"{new_session_count} WinRM session(s) mới"
                f" = +{points} (total sessions:"
                f" {len(existing_sessions)})"
            ),
        }]

    # ==============================================================
    # R5: CRITICAL FILE ACCESS (Event 4663)
    # ==============================================================

    def _r5_file_access(self, ip, ip_data, events):
        """
        Event 4663 trên file nhạy cảm (data_important.txt).
        Mỗi event → +25 điểm.
        """
        critical_events = [
            e for e in events if e["event_type"] == "file_access_critical"
        ]
        if not critical_events:
            return []

        points = len(critical_events) * SCORE_FILE_ACCESS

        return [{
            "ip": ip,
            "rule": "R5_FILE_ACCESS",
            "points": points,
            "reason": (
                f"{len(critical_events)} truy cập file nhạy cảm"
                f" = +{points}"
            ),
        }]

    # ==============================================================
    # R6: POWERSHELL -ExecutionPolicy Bypass
    # ==============================================================

    def _r6_ps_bypass(self, ip, ip_data, events):
        """
        Phát hiện PowerShell chạy với -ExecutionPolicy Bypass.
        Event 4104 (ScriptBlock) hoặc Event 1 (Process Create).
        Mỗi detection → +40 điểm.
        """
        bypass_events = [
            e for e in events if e["event_type"] == "ps_bypass"
        ]
        if not bypass_events:
            return []

        points = len(bypass_events) * SCORE_PS_BYPASS

        # Log chi tiết command lines
        for evt in bypass_events:
            cmd = evt.get("details", {}).get("command_line", "")
            script = evt.get("details", {}).get("script_block_text", "")[:200]
            logger.warning(
                f"[R6] PS Bypass detected cho {ip}: "
                f"cmd='{cmd[:100]}' script='{script}'"
            )

        return [{
            "ip": ip,
            "rule": "R6_PS_BYPASS",
            "points": points,
            "reason": (
                f"{len(bypass_events)} PowerShell Bypass detection(s)"
                f" = +{points}"
            ),
        }]

    # ==============================================================
    # R7: EXFILTRATION via Base64 Encoding
    # ==============================================================

    def _r7_exfil_base64(self, ip, ip_data, events):
        """
        Phát hiện ToBase64String + tên file nhạy cảm trong ScriptBlock.
        Mỗi detection → +35 điểm.
        """
        exfil_events = [
            e for e in events if e["event_type"] == "exfil_base64"
        ]
        if not exfil_events:
            return []

        points = len(exfil_events) * SCORE_EXFIL_BASE64

        for evt in exfil_events:
            script = evt.get("details", {}).get("script_block_text", "")[:200]
            logger.warning(
                f"[R7] Exfil Base64 detected cho {ip}: script='{script}'"
            )

        return [{
            "ip": ip,
            "rule": "R7_EXFIL_BASE64",
            "points": points,
            "reason": (
                f"{len(exfil_events)} Base64 exfiltration detection(s)"
                f" = +{points}"
            ),
        }]

    # ==============================================================
    # R8: EXCESSIVE UPLOAD DETECTION (Zeek orig_bytes)
    # ==============================================================

    def _r8_upload_detection(self, ip, ip_data, events):
        """
        Phát hiện khi attacker đẩy tool/malware vào victim qua network.
        Dựa trên orig_bytes từ Zeek events ≥ UPLOAD_THRESHOLD_KB.
        Các loại: winrm_upload, file_upload, http_upload, suspicious_upload.
        Mỗi detection → +25 điểm.
        """
        upload_events = [
            e for e in events 
            if e["event_type"] in ("winrm_upload", "file_upload", "http_upload", "suspicious_upload")
        ]
        if not upload_events:
            return []

        points = len(upload_events) * SCORE_EXCESSIVE_UPLOAD
        
        # Log chi tiết volume transfers
        total_uploaded_kb = 0
        for evt in upload_events:
            orig_kb = evt.get("details", {}).get("orig_kb", 0)
            total_uploaded_kb += orig_kb
            dst_port = evt.get("dst_port", 0)
            logger.warning(
                f"[R8] Upload detected {ip} → port {dst_port}: {orig_kb:.1f}KB"
            )

        return [{
            "ip": ip,
            "rule": "R8_EXCESSIVE_UPLOAD",
            "points": points,
            "reason": (
                f"{len(upload_events)} upload session(s), {total_uploaded_kb:.1f}KB total"
                f" = +{points}"
            ),
        }]

    # ==============================================================
    # R9: EXCESSIVE DOWNLOAD/EXFILTRATION DETECTION (Zeek resp_bytes)
    # ==============================================================

    def _r9_download_detection(self, ip, ip_data, events):
        """
        Phát hiện khi attacker lấy dữ liệu từ victim ra ngoài.
        Dựa trên resp_bytes từ Zeek events ≥ DOWNLOAD_THRESHOLD_KB.
        
        2 mức độ:
          - ≥100KB: suspicious download (+30)
          - ≥200KB: major exfiltration (+50)
        """
        download_events = [
            e for e in events 
            if e["event_type"] in ("winrm_download", "file_download", "http_download", "suspicious_download")
        ]
        if not download_events:
            return []

        changes = []
        total_downloaded_kb = 0
        major_exfil_events = []
        
        for evt in download_events:
            resp_kb = evt.get("details", {}).get("resp_kb", 0)
            total_downloaded_kb += resp_kb
            
            if resp_kb >= EXFIL_THRESHOLD_KB:  # ≥200KB = major exfiltration
                major_exfil_events.append(evt)

        # Standard download scoring
        if download_events:
            points = len(download_events) * SCORE_EXCESSIVE_DOWNLOAD
            changes.append({
                "ip": ip,
                "rule": "R9_EXCESSIVE_DOWNLOAD",
                "points": points,
                "reason": (
                    f"{len(download_events)} download session(s), {total_downloaded_kb:.1f}KB total"
                    f" = +{points}"
                ),
            })
        
        # Major exfiltration bonus
        if major_exfil_events:
            major_kb = sum(evt.get("details", {}).get("resp_kb", 0) for evt in major_exfil_events)
            points = len(major_exfil_events) * SCORE_MAJOR_EXFILTRATION
            
            changes.append({
                "ip": ip,
                "rule": "R9_MAJOR_EXFILTRATION",
                "points": points,
                "reason": (
                    f"{len(major_exfil_events)} major exfiltration(s), {major_kb:.1f}KB"
                    f" = +{points} (CRITICAL)"
                ),
            })
            
            # Log critical exfiltration
            for evt in major_exfil_events:
                resp_kb = evt.get("details", {}).get("resp_kb", 0)
                dst_port = evt.get("dst_port", 0)
                logger.warning(
                    f"[R9] MAJOR EXFILTRATION DETECTED {ip} ← port {dst_port}: {resp_kb:.1f}KB"
                )

        return changes


# ==============================================================
# HELPER: Tóm tắt scoring cho logging
# ==============================================================

def format_score_summary(ip_state):
    """Trả về string tóm tắt score của tất cả IPs."""
    lines = []
    for ip, data in sorted(
        ip_state.items(), key=lambda x: x[1]["total_score"], reverse=True
    ):
        wl = "WL" if ip in WHITELIST_IPS else "  "
        blocked = "BLOCKED" if data.get("blocked") else "       "
        lines.append(
            f"  [{wl}] {ip:>15s}  score={data['total_score']:>4d}"
            f"  scan={data['scan_count']:>3d}"
            f"  fail={data['fail_count']:>3d}  {blocked}"
        )
    return "\n".join(lines)
