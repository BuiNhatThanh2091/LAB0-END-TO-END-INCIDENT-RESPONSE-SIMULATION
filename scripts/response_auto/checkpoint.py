"""
checkpoint.py — Quản lý Checkpoint & IP State persistence
==========================================================
- Checkpoint: lưu timestamp event cuối cùng đã xử lý per-source
  → tránh xử lý trùng lặp khi SOAR restart.
- IP State: lưu điểm tích luỹ, counter batch, trạng thái block per-IP
  → giữ trạng thái scoring xuyên suốt các polling cycle.
"""

import json
import os
import time
from logger_setup import setup_logger

logger = setup_logger("checkpoint")


class CheckpointManager:
    """Đọc/ghi checkpoint.json và ip_state.json."""

    def __init__(self, checkpoint_file, state_file):
        self.checkpoint_file = checkpoint_file
        self.state_file = state_file

    # ----------------------------------------------------------
    # CHECKPOINT (last processed timestamp per source)
    # ----------------------------------------------------------

    def load_checkpoint(self):
        """
        Đọc checkpoint từ file.
        Returns: dict {"zeek": epoch, "suricata": epoch, "winlogbeat": epoch}
        """
        if not os.path.exists(self.checkpoint_file):
            logger.info("Không tìm thấy checkpoint file → bắt đầu từ epoch 0")
            return {"zeek": 0, "suricata": 0, "winlogbeat": 0}
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.debug(f"Loaded checkpoint: {data}")
            return data
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Lỗi đọc checkpoint: {e} → reset về epoch 0")
            return {"zeek": 0, "suricata": 0, "winlogbeat": 0}

    def save_checkpoint(self, data):
        """Ghi checkpoint xuống file."""
        try:
            with open(self.checkpoint_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved checkpoint: {data}")
        except IOError as e:
            logger.error(f"Lỗi ghi checkpoint: {e}")

    def get_checkpoint(self, source):
        """Lấy checkpoint cho 1 source cụ thể."""
        ckpt = self.load_checkpoint()
        return ckpt.get(source, 0)

    def update_checkpoint(self, source, epoch_time):
        """Cập nhật checkpoint cho 1 source (chỉ nếu mới hơn)."""
        ckpt = self.load_checkpoint()
        current = ckpt.get(source, 0)
        if epoch_time > current:
            ckpt[source] = epoch_time
            self.save_checkpoint(ckpt)
            logger.info(f"Checkpoint [{source}] cập nhật → {epoch_time}")

    # ----------------------------------------------------------
    # IP STATE (scoring state per IP — persist across restarts)
    # ----------------------------------------------------------

    def load_ip_state(self):
        """
        Đọc trạng thái scoring per-IP.
        Returns: dict {
            "10.10.10.130": {
                "total_score": int,
                "scan_count": int,
                "scan_batches_scored": int,
                "fail_count": int,
                "fail_batches_scored": int,
                "winrm_session_times": [epoch, ...],
                "blocked": bool,
                "blocked_at": epoch | None,
                "rules_log": [{"time": ..., "rule": ..., "points": ...}, ...],
                "first_seen": epoch,
                "last_seen": epoch,
            }
        }
        """
        if not os.path.exists(self.state_file):
            logger.info("Không tìm thấy ip_state file → bắt đầu trạng thái mới")
            return {}
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.debug(f"Loaded IP state: {len(data)} IPs")
            return data
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Lỗi đọc ip_state: {e} → reset")
            return {}

    def save_ip_state(self, state):
        """Ghi trạng thái IP xuống file."""
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved IP state: {len(state)} IPs")
        except IOError as e:
            logger.error(f"Lỗi ghi ip_state: {e}")

    def get_or_create_ip(self, state, ip):
        """Lấy hoặc khởi tạo state cho 1 IP."""
        if ip not in state:
            state[ip] = {
                "total_score": 0,
                "scan_count": 0,
                "scan_batches_scored": 0,
                "fail_count": 0,
                "fail_batches_scored": 0,
                "winrm_session_times": [],
                "blocked": False,
                "blocked_at": None,
                "rules_log": [],
                "first_seen": time.time(),
                "last_seen": time.time(),
            }
        state[ip]["last_seen"] = time.time()
        return state[ip]
