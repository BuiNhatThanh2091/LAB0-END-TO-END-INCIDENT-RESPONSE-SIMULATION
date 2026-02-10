"""
correlation.py — Layer 2: Normalize, Dedup, Group by IP
=========================================================
1. Gộp events từ 3 nguồn vào 1 list thống nhất
2. Cross-source dedup: cùng (src_ip, dst_port, event_type, ±5s) = 1 event
3. Group events theo IP → chuẩn bị cho scoring
4. Session correlation: gán IP attacker cho endpoint events (4663, 4104)
"""

from collections import defaultdict
from config import (
    DEDUP_WINDOW_SECONDS,
    VICTIM_IP,
)
from logger_setup import setup_logger

logger = setup_logger("correlation")


# ==============================================================
# 1. GỘP EVENTS
# ==============================================================

def merge_events(zeek_events, suricata_events, winlogbeat_events):
    """Gộp tất cả events vào 1 list, sắp xếp theo thời gian."""
    all_events = zeek_events + suricata_events + winlogbeat_events
    all_events.sort(key=lambda e: e.get("timestamp_epoch", 0))
    logger.info(
        f"Merged: {len(zeek_events)} Zeek + {len(suricata_events)} Suricata"
        f" + {len(winlogbeat_events)} Winlogbeat = {len(all_events)} events"
    )
    return all_events


# ==============================================================
# 2. CROSS-SOURCE DEDUP
# ==============================================================

def deduplicate(events):
    """
    Loại bỏ events trùng lặp across sources.

    Dedup key = (src_ip, dst_ip, dst_port, event_type_group, time_bucket)
    Trong đó time_bucket = timestamp_epoch // DEDUP_WINDOW_SECONDS

    Ví dụ: Zeek thấy connection đến port 445 VÀ Suricata cũng fire alert
    cho cùng IP:port trong 5s → chỉ giữ 1 event (ưu tiên source có chi tiết hơn).

    Quy tắc ưu tiên: winlogbeat > suricata > zeek
    (winlogbeat có IP attacker rõ ràng nhất qua Event 4624/4625)
    """
    # Nhóm event types thành groups để dedup
    EVENT_TYPE_GROUPS = {
        # Scan-related
        "port_scan": "scan",
        # HTTP 8080
        "http_8080": "http_8080",
        # SMB / Brute force
        "smb_connection": "brute_force",
        "brute_force_fail": "brute_force",
        # WinRM (including R8/R9 upload/download)
        "winrm_connection": "winrm",
        "winrm_alert": "winrm",
        "winrm_process": "winrm",
        "winrm_upload": "winrm_upload",      # R8: WinRM upload detection
        "winrm_download": "winrm_download",  # R9: WinRM download/exfiltration
        # File transfer detection (R8/R9)
        "file_upload": "file_transfer",
        "file_download": "file_transfer",
        "http_upload": "http_transfer",
        "http_download": "http_transfer", 
        "suspicious_upload": "suspicious_transfer",
        "suspicious_download": "suspicious_transfer",
    }
    SOURCE_PRIORITY = {"winlogbeat": 3, "suricata": 2, "zeek": 1}

    seen = {}  # key → best event
    for event in events:
        etype = event.get("event_type", "")
        group = EVENT_TYPE_GROUPS.get(etype, etype)

        src = event.get("src_ip", "")
        dst = event.get("dst_ip", "")
        port = event.get("dst_port", 0)
        epoch = event.get("timestamp_epoch", 0)
        bucket = int(epoch // DEDUP_WINDOW_SECONDS) if epoch > 0 else 0

        # Debug: Log each event being processed
        logger.debug(f"[DEDUP] Processing {etype}, src={src}, port={port}")

        # Chỉ dedup events thực sự giống nhau: cùng src, dst, port, type, và time window
        # Upload/download events với volumes khác nhau sẽ KHÔNG bị dedup
        # để đảm bảo R8/R9 scoring chính xác
        
        if etype in ["winrm_upload", "winrm_download", "file_upload", "file_download", 
                     "http_upload", "http_download", "suspicious_upload", "suspicious_download"]:
            # Cho upload/download, thêm volume info vào key để tránh dedup
            orig_kb = event.get("details", {}).get("orig_kb", 0)
            resp_kb = event.get("details", {}).get("resp_kb", 0) 
            volume_bucket = int(max(orig_kb, resp_kb) // 10)  # Group by 10KB buckets
            key = (src, dst, port, etype, bucket, volume_bucket)
            logger.debug(f"[DEDUP] Volume event {etype} with key {key}")
        else:
            # port_scan events với ports khác nhau sẽ KHÔNG bị dedup
            key = (src, dst, port, etype, bucket)  # Dùng etype thay vì group

        source = event.get("source", "")
        priority = SOURCE_PRIORITY.get(source, 0)

        if key not in seen or priority > SOURCE_PRIORITY.get(
            seen[key].get("source", ""), 0
        ):
            seen[key] = event
            logger.debug(f"[DEDUP] Kept event {etype}")
        else:
            logger.debug(f"[DEDUP] Dropped duplicate {etype}")

    deduped = sorted(seen.values(), key=lambda e: e.get("timestamp_epoch", 0))
    dropped = len(events) - len(deduped)
    if dropped > 0:
        logger.info(f"Dedup: {len(events)} → {len(deduped)} ({dropped} duplicates)")
    return deduped


# ==============================================================
# 3. SESSION CORRELATION (gán IP attacker cho endpoint events)
# ==============================================================

def correlate_sessions(events):
    """
    Xây dựng bảng 'active WinRM sessions' từ Event 4624 (LogonType=3).
    Sau đó gán attacker IP cho các endpoint events không có IP trực tiếp:
      - file_access_critical (Event 4663)
      - ps_bypass (Event 4104 / Event 1)
      - exfil_base64 (Event 4104)
      - winrm_process (Event 1 wsmprovhost.exe)

    Logic: Nếu có WinRM session active (Event 4624 từ external IP), thì
    các suspicious events trên victim host → gán cho IP đó.
    """
    # Bước 1: Thu thập active sessions
    active_sessions = []  # [(epoch, attacker_ip)]
    for event in events:
        if event["event_type"] == "logon_success":
            attacker_ip = event.get("src_ip", "")
            if attacker_ip and attacker_ip != "-" and attacker_ip != VICTIM_IP:
                active_sessions.append(
                    (event["timestamp_epoch"], attacker_ip)
                )

    if not active_sessions:
        logger.debug("Không có active WinRM session nào để correlate")
        return events

    active_sessions.sort(key=lambda x: x[0])
    logger.info(
        f"Session correlation: {len(active_sessions)} WinRM sessions detected"
    )

    # Bước 2: Gán IP cho endpoint events chưa có IP
    NEEDS_CORRELATION = {
        "file_access_critical", "file_access",
        "ps_bypass", "exfil_base64", "ps_base64_generic",
        "winrm_process", "file_create",
    }

    for event in events:
        if event["event_type"] not in NEEDS_CORRELATION:
            continue
        if event.get("src_ip"):
            continue  # Đã có IP → không cần gán

        # Tìm session gần nhất TRƯỚC event này
        event_time = event["timestamp_epoch"]
        best_ip = None
        for sess_time, sess_ip in reversed(active_sessions):
            if sess_time <= event_time:
                best_ip = sess_ip
                break

        if best_ip:
            event["src_ip"] = best_ip
            event["details"]["correlated_from"] = "session_correlation"
            logger.debug(
                f"Correlated {event['event_type']} → attacker {best_ip}"
            )

    return events


# ==============================================================
# 4. GROUP BY IP
# ==============================================================

def group_by_ip(events):
    """
    Nhóm events theo IP cần scoring.

    Quy tắc IP mapping:
      - port_scan:            src_ip = scanner → score src_ip
      - http_8080:            dst_ip = hosting IP (Zeek resp_h) → score dst_ip
      - brute_force_fail:     src_ip = attacker IP → score src_ip
      - logon_success:        src_ip = attacker IP → score src_ip
      - winrm_alert:          src_ip = attacker → score src_ip
      - winrm_process:        src_ip (correlated) → score src_ip
      - winrm_upload:         src_ip = uploader → score src_ip (R8)
      - winrm_download:       src_ip = downloader → score src_ip (R9)
      - file_upload/download: src_ip = file transfer initiator → score src_ip (R8/R9)
      - http_upload/download: src_ip = http transfer initiator → score src_ip (R8/R9) 
      - file_access_critical: src_ip (correlated) → score src_ip
      - ps_bypass:            src_ip (correlated) → score src_ip
      - exfil_base64:         src_ip (correlated) → score src_ip
    """
    ip_events = defaultdict(list)

    logger.info(f"[DEBUG] group_by_ip processing {len(events)} events")
    
    for event in events:
        etype = event.get("event_type", "")
        scored_ip = None
        
        print(f"🔍 [DEBUG] Processing event: {etype}, src_ip={event.get('src_ip')}, dst_ip={event.get('dst_ip')}")

        # HTTP 8080: score IP hosting server (= resp_h / dest_ip nhận request)
        if etype == "http_8080":
            if event["source"] == "zeek":
                scored_ip = event.get("dst_ip", "")  # resp_h trong Zeek
            elif event["source"] == "suricata":
                scored_ip = event.get("dst_ip", "")
        # Mọi loại khác: score src_ip
        elif etype in (
            "port_scan", "brute_force_fail", "logon_success",
            "winrm_alert", "winrm_connection", "winrm_process",
            "file_access_critical", "file_access",
            "ps_bypass", "exfil_base64",
            "network_conn", "smb_connection",
            # R8/R9: Upload/Download events
            "winrm_upload", "winrm_download", 
            "file_upload", "file_download",
            "http_upload", "http_download",
            "suspicious_upload", "suspicious_download",
        ):
            scored_ip = event.get("src_ip", "")
        
        print(f"🔍 [DEBUG] Event {etype} -> scored_ip: {scored_ip}, victim_ip: {VICTIM_IP}")

        # Safeguard: Không score victim IP để tránh tự chặn
        if scored_ip and scored_ip != VICTIM_IP:
            ip_events[scored_ip].append(event)
            print(f"✅ [DEBUG] Added event {etype} to IP {scored_ip}")
        elif scored_ip == VICTIM_IP:
            print(f"⚠️ [DEBUG] Skipped victim IP {VICTIM_IP} for event {etype}")
        else:
            print(f"❌ [DEBUG] Event {etype} not processed - scored_ip={scored_ip}")
    
    logger.info(f"[DEBUG] group_by_ip result: {len(ip_events)} IPs with events")

    logger.info(
        f"Group by IP: {len(ip_events)} unique IPs, "
        f"top IPs: {_top_ips(ip_events, 5)}"
    )
    return dict(ip_events)


# ==============================================================
# PIPELINE: Chạy toàn bộ Layer 2
# ==============================================================

def correlate_pipeline(zeek_events, suricata_events, winlogbeat_events):
    """
    Pipeline đầy đủ Layer 2:
      merge → dedup → session_correlate → group_by_ip
    Returns: dict {ip: [events]}
    """
    merged = merge_events(zeek_events, suricata_events, winlogbeat_events)
    deduped = deduplicate(merged)
    correlated = correlate_sessions(deduped)
    grouped = group_by_ip(correlated)
    return grouped


# ==============================================================
# HELPERS
# ==============================================================

def _top_ips(ip_events, n=5):
    """Trả về top N IPs theo số lượng events."""
    sorted_ips = sorted(
        ip_events.items(), key=lambda x: len(x[1]), reverse=True
    )[:n]
    return {ip: len(evts) for ip, evts in sorted_ips}
