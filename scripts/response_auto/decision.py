"""
decision.py — Layer 4: Threshold Evaluation & Action Router
=============================================================
So sánh total_score per IP với ngưỡng:
  - Non-whitelist IP ≥ 60  → BLOCK + EMAIL
  - Whitelist IP ≥ 100     → BLOCK + EMAIL
  - Whitelist IP brute force (R3) → EMAIL ONLY
  - Dưới ngưỡng             → LOG & MONITOR

⚠️ TẤT CẢ IP bị block đều gửi email alert!

Trả về danh sách Action objects cho Layer 5 (Response) thực thi.
"""

import time
from config import (
    WHITELIST_IPS,
    THRESHOLD_NON_WL,
    THRESHOLD_WL,
)
from logger_setup import setup_logger

logger = setup_logger("decision")


# ==============================================================
# ACTION TYPES
# ==============================================================
ACTION_BLOCK       = "BLOCK"          # Block IP trên cả Ubuntu + Windows
ACTION_BLOCK_EMAIL = "BLOCK_EMAIL"    # Block + gửi email
ACTION_EMAIL_ONLY  = "EMAIL_ONLY"     # Chỉ gửi email (WL brute force)
ACTION_LOG         = "LOG"            # Chỉ log, chưa hành động
ACTION_KILL_PROCESS = "KILL_PROCESS"  # EDR: Kill malicious processes trên victim


class Action:
    """Mô tả hành động cần thực thi."""

    def __init__(self, action_type, target_ip, score, reason,
                 is_whitelist=False, events=None):
        self.action_type = action_type
        self.target_ip = target_ip
        self.score = score
        self.reason = reason
        self.is_whitelist = is_whitelist
        self.events = events or []  # Events liên quan (dùng cho EDR process kill)
        self.created_at = time.time()

    def __repr__(self):
        return (
            f"Action({self.action_type}, ip={self.target_ip},"
            f" score={self.score})"
        )


# ==============================================================
# DECISION ENGINE
# ==============================================================

class DecisionEngine:
    """Đánh giá ip_state và trả về list of Actions."""

    def evaluate(self, ip_state, score_changes, ip_events=None):
        """
        Args:
            ip_state: dict {ip: {total_score, blocked, ...}}
            score_changes: list of dicts from scoring engine
                           (để detect R3_BRUTE_FORCE_WL_EMAIL)
            ip_events: dict {ip: [events]} — dùng cho EDR process containment

        Returns:
            list[Action]
        """
        logger.info(f"[DEBUG] Decision engine evaluating {len(ip_state)} IPs")
        logger.info(f"[DEBUG] Score changes: {len(score_changes)} items")
        
        if ip_events is None:
            ip_events = {}
        
        actions = []

        # --- Xử lý WL brute force email (R3 đặc biệt) ---
        for change in score_changes:
            if change["rule"] == "R3_BRUTE_FORCE_WL_EMAIL":
                logger.info(f"[DEBUG] Processing R3 email action for {change['ip']}")
                actions.append(Action(
                    action_type=ACTION_EMAIL_ONLY,
                    target_ip=change["ip"],
                    score=ip_state.get(change["ip"], {}).get("total_score", 0),
                    reason=change["reason"],
                    is_whitelist=True,
                ))

        # --- Kiểm tra ngưỡng cho mỗi IP ---
        for ip, data in ip_state.items():
            total_score = data.get("total_score", 0)
            is_blocked = data.get("blocked", False)
            is_wl = ip in WHITELIST_IPS
            
            logger.info(f"[DEBUG] Checking IP {ip}: score={total_score}, blocked={is_blocked}, whitelist={is_wl}")
            
            # Bỏ qua nếu đã block
            if is_blocked:
                logger.info(f"[DEBUG] IP {ip} already blocked, skipping")
                continue
                
            # Bỏ qua nếu score = 0  
            if total_score == 0:
                continue
            is_wl = ip in WHITELIST_IPS

            if is_wl:
                # Whitelist: ngưỡng 150
                if total_score >= THRESHOLD_WL:
                    actions.append(Action(
                        action_type=ACTION_BLOCK_EMAIL,
                        target_ip=ip,
                        score=total_score,
                        reason=(
                            f"Whitelist IP {ip} vượt ngưỡng:"
                            f" {total_score} ≥ {THRESHOLD_WL}"
                        ),
                        is_whitelist=True,
                    ))
                    logger.critical(
                        f"QUYẾT ĐỊNH: BLOCK + EMAIL cho WL IP {ip}"
                        f" (score={total_score})"
                    )
            else:
                # Non-whitelist: ngưỡng 60 (với email)
                if total_score >= THRESHOLD_NON_WL:
                    # Lấy events cho IP này (dùng cho EDR)
                    related_events = ip_events.get(ip, [])
                    
                    actions.append(Action(
                        action_type=ACTION_BLOCK_EMAIL,  # Changed from ACTION_BLOCK
                        target_ip=ip,
                        score=total_score,
                        reason=(
                            f"Non-WL IP {ip} vượt ngưỡng:"
                            f" {total_score} ≥ {THRESHOLD_NON_WL}"
                        ),
                        is_whitelist=False,
                        events=related_events,
                    ))
                    logger.critical(
                        f"QUYẾT ĐỊNH: AUTO-BLOCK + EMAIL cho IP {ip}"
                        f" (score={total_score})"
                    )
                    
                    # EDR: Nếu phát hiện process-level threats → thêm action KILL_PROCESS
                    process_threats = [
                        e for e in related_events
                        if e.get("event_type") in (
                            "ps_bypass", "exfil_base64", "winrm_process",
                            "process_create",
                        )
                    ]
                    if process_threats:
                        actions.append(Action(
                            action_type=ACTION_KILL_PROCESS,
                            target_ip=ip,
                            score=total_score,
                            reason=(
                                f"EDR: {len(process_threats)} malicious process(es) "
                                f"detected cho IP {ip} → Kill processes"
                            ),
                            is_whitelist=False,
                            events=related_events,
                        ))
                        logger.critical(
                            f"QUYẾT ĐỊNH: KILL PROCESS cho IP {ip} "
                            f"({len(process_threats)} process threats)"
                        )

        if actions:
            logger.info(
                f"Decision: {len(actions)} action(s) cần thực thi"
            )
        return actions
