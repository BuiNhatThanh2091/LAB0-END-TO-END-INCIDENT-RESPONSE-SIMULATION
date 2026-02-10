"""
main.py — SOAR Engine Entry Point
===================================
Polling loop chính: kết nối 5 layers lại với nhau.

Prerequisites:
    1. Set up environment variables (recommended):
       python3 setup_env.py
    
    2. Test configuration:
       python3 test_env_setup.py
    
    3. Run SOAR:
       python3 main.py

Environment Variables (for security):
    SSH_USER, SSH_PASS, SSH_KEY_PATH - Windows victim access
    SMTP_USER, SMTP_PASS, ALERT_RECIPIENTS - Email alerts
    
    See .env.example for full list.

Workflow mỗi cycle (15s):
    1. Poll Splunk CLI (hoặc đọc file local khi DRY_RUN)
    2. Parse & Normalize events từ 3 nguồn
    3. Cross-source Dedup + Session Correlation + Group by IP
    4. Áp dụng 9 Scoring Rules → tính điểm per-IP
    5. So sánh ngưỡng → quyết định hành động
    6. Thực thi: Block (iptables+netsh), Kill Process (EDR), Email, Auto-Unblock
    7. Lưu checkpoint + ip_state
    8. Sleep 15s → lặp lại
"""

import sys
import os
import time
import signal

# Thêm thư mục hiện tại vào path (để import modules)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    DRY_RUN, POLL_INTERVAL,
    CHECKPOINT_FILE, STATE_FILE,
    THREAT_INTEL_ENABLED, TI_LOOKUP_THRESHOLD,
)
from logger_setup import setup_logger
from checkpoint import CheckpointManager
from ingestion import poll_all_sources
from correlation import correlate_pipeline
from scoring import ScoringEngine, format_score_summary
from decision import DecisionEngine
from response import ResponseEngine
from enrichment import ThreatIntelEnricher, enrich_ip_state, apply_ti_boost

logger = setup_logger("main")

# Flag để dừng gracefully
_running = True


def signal_handler(signum, frame):
    """Xử lý Ctrl+C để dừng gracefully."""
    global _running
    logger.info("Nhận tín hiệu dừng (Ctrl+C). Đang tắt SOAR...")
    _running = False


def main():
    """Main entry point — chạy SOAR polling loop."""
    global _running

    # Kiểm tra arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--reset":
            print("🔄 SOAR Reset Mode")
            reset_soar_state()
            return
        elif sys.argv[1] == "--help":
            print_help()
            return
        else:
            print(f"❌ Unknown argument: {sys.argv[1]}")
            print_help()
            return

    # Đăng ký signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("=" * 60)
    logger.info("  SOAR MINI ENGINE v1.0 — Starting")
    logger.info(f"  Mode: {'DRY_RUN (local files)' if DRY_RUN else 'PRODUCTION (Splunk CLI)'}")
    logger.info(f"  Poll interval: {POLL_INTERVAL}s")
    logger.info("=" * 60)

    # Kiểm tra nếu có IP đã blocked trong state (có thể từ test trước)
    temp_state = CheckpointManager(CHECKPOINT_FILE, STATE_FILE).load_ip_state()
    blocked_ips = [ip for ip, data in temp_state.items() if data.get("blocked")]
    
    if blocked_ips:
        logger.warning(f"⚠️  Found {len(blocked_ips)} blocked IP(s) from previous runs:")
        for ip in blocked_ips[:5]:  # Show first 5
            logger.warning(f"   - {ip}")
        if len(blocked_ips) > 5:
            logger.warning(f"   ... and {len(blocked_ips) - 5} more")
        logger.warning("💡 Consider running 'python3 main.py --reset' to clear state")
        logger.warning("   or 'python3 reset_soar.py' for interactive reset")
        print()
        
        # Đợi 3 giây để user có thể Ctrl+C nếu muốn reset
        for i in range(3, 0, -1):
            if not _running:
                return
            print(f"⏳ Continuing in {i}s... (Ctrl+C to abort and reset)", end="\r")
            time.sleep(1)
        print("🚀 Starting with existing state...                    ")

    # Khởi tạo components
    ckpt_mgr = CheckpointManager(CHECKPOINT_FILE, STATE_FILE)
    decision_engine = DecisionEngine()
    response_engine = ResponseEngine()
    
    # Phase 3: Threat Intelligence Enricher
    ti_enricher = None
    if THREAT_INTEL_ENABLED:
        ti_enricher = ThreatIntelEnricher()
        logger.info("✅ Threat Intelligence Enrichment: ENABLED")
    else:
        logger.info("ℹ️  Threat Intelligence Enrichment: DISABLED")

    # Load trạng thái từ lần chạy trước (nếu có)
    ip_state = ckpt_mgr.load_ip_state()
    logger.info(f"Loaded IP state: {len(ip_state)} IPs")
    
    # Khởi tạo scoring engine sau khi load state
    scoring_engine = ScoringEngine(ip_state, ckpt_mgr)

    cycle = 0
    while _running:
        cycle += 1
        cycle_start = time.time()

        logger.info(f"\n{'─' * 50}")
        logger.info(f"CYCLE #{cycle}")
        logger.info(f"{'─' * 50}")

        try:
            # ── LAYER 1: INGESTION ──
            zeek_events, suri_events, winlog_events = poll_all_sources(
                ckpt_mgr
            )
            total_new = len(zeek_events) + len(suri_events) + len(winlog_events)

            if total_new == 0:
                logger.info("Không có events mới. Chờ cycle tiếp theo...")
                _update_checkpoints(
                    ckpt_mgr, zeek_events, suri_events, winlog_events
                )
                _sleep_or_exit(cycle_start)
                continue

            # ── LAYER 2: CORRELATION ──
            ip_events = correlate_pipeline(
                zeek_events, suri_events, winlog_events
            )

            if not ip_events:
                logger.info("Không có events liên quan đến scoring.")
                _update_checkpoints(
                    ckpt_mgr, zeek_events, suri_events, winlog_events
                )
                _sleep_or_exit(cycle_start)
                continue

            # ── LAYER 3: SCORING ──
            # Phase 2: Apply decay trước khi scoring
            scoring_engine.apply_decay()
            
            # Scoring rules
            score_changes = scoring_engine.process(ip_events)
            
            # Phase 3: Threat Intel Enrichment (sau scoring)
            ti_changes = []
            if ti_enricher and THREAT_INTEL_ENABLED:
                logger.info("[TI] Starting Threat Intelligence enrichment...")
                ti_results = enrich_ip_state(ti_enricher, ip_state, score_threshold=TI_LOOKUP_THRESHOLD)
                
                if ti_results:
                    ti_changes = apply_ti_boost(ip_state, ti_results)
                    score_changes.extend(ti_changes)  # Merge TI changes vào score_changes
                    logger.info(f"[TI] Applied {len(ti_changes)} TI score boosts")

            # Log tóm tắt
            if score_changes:
                logger.info(f"\nScore Summary:\n{format_score_summary(ip_state)}")

            # ── LAYER 4: DECISION ──
            logger.info(f"[DEBUG] Starting decision phase...")
            actions = decision_engine.evaluate(ip_state, score_changes, ip_events)
            logger.info(f"[DEBUG] Decision engine returned {len(actions)} actions")
            
            for i, action in enumerate(actions):
                logger.info(f"[DEBUG] Action {i+1}: {action.action_type} for {action.target_ip} (score={action.score})")

            # ── LAYER 5: RESPONSE ──
            if actions:
                logger.info(f"[DEBUG] Executing {len(actions)} actions via response engine...")
                response_engine.execute(actions, ip_state)
                logger.info(f"[DEBUG] Response execution completed")
            else:
                logger.info(f"[DEBUG] No actions to execute")

            # Auto-unblock check
            response_engine.check_auto_unblock(ip_state)

            # ── SAVE STATE ──
            _update_checkpoints(
                ckpt_mgr, zeek_events, suri_events, winlog_events
            )
            ckpt_mgr.save_ip_state(ip_state)

            elapsed = time.time() - cycle_start
            logger.info(f"Cycle #{cycle} hoàn tất trong {elapsed:.2f}s")

        except Exception as e:
            logger.error(f"Lỗi trong cycle #{cycle}: {e}", exc_info=True)

        # Nếu DRY_RUN, chỉ chạy 1 cycle
        if DRY_RUN:
            logger.info("\n[DRY_RUN] Chạy xong 1 cycle. Kết thúc.")
            _print_final_report(ip_state)
            
            # Auto-reset cho DRY_RUN mode để chuẩn bị test lần sau
            logger.info("\n🔄 [DRY_RUN] Auto-resetting state for next test...")
            try:
                reset_soar_state()
                logger.info("✅ [DRY_RUN] State reset completed")
            except Exception as e:
                logger.warning(f"⚠️  [DRY_RUN] Reset failed: {e}")
                
            break

        _sleep_or_exit(cycle_start)

    logger.info("SOAR Engine đã dừng.")


# ==============================================================
# HELPERS
# ==============================================================

def print_help():
    """In hướng dẫn sử dụng"""
    print("=" * 60)
    print("📋 SOAR MINI ENGINE v1.0 - Usage")
    print("=" * 60)
    print("Commands:")
    print("  python3 main.py           - Run SOAR engine")
    print("  python3 main.py --reset   - Reset all SOAR state (for testing)")
    print("  python3 main.py --help    - Show this help")
    print()
    print("Setup & Configuration:")
    print("  python3 setup_env.py      - Interactive environment setup")
    print("  python3 test_env_setup.py - Test configuration")
    print("  cp .env.example .env       - Manual environment setup")
    print()
    print("Testing & Debug:")
    print("  python3 debug_ip_state.py - Check current IP states")
    print("  python3 debug_env_loading.py - Debug .env file loading")
    print("  python3 reset_soar.py     - Interactive reset tool")
    print("  python3 test_ssh.py       - Test SSH connection")
    print("  python3 test_block.py     - Test firewall blocking")
    print("  python3 test_email.py     - Test email alerts")
    print()
    print("Security Files:")
    print("  .env.example              - Environment variables template")
    print("  .gitignore                - Protects sensitive files")
    print("  💡 Always use environment variables for credentials!")

def reset_soar_state():
    """Reset SOAR state để test lại từ đầu"""
    print("🔄 Resetting SOAR state for testing...")
    
    import json
    import subprocess
    try:
        import paramiko
    except ImportError:
        print("❌ paramiko not available, skipping Windows reset")
        return
        
    # 1. Clear IP state
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
        print(f"✅ Cleared IP state: {STATE_FILE}")
    
    # 2. Clear checkpoints
    if os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)
        print(f"✅ Cleared checkpoints: {CHECKPOINT_FILE}")
    
    # 3. Remove Ubuntu iptables rules
    try:
        cmd = 'sudo iptables -S | grep SOAR_BLOCK | sed "s/-A/iptables -D/" | sudo bash'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Removed Ubuntu iptables rules")
        else:
            print(f"⚠️  Ubuntu iptables: {result.stderr}")
    except Exception as e:
        print(f"⚠️  Could not remove Ubuntu rules: {e}")
    
    # 4. Remove Windows firewall rules
    try:
        from config import WIN_SSH_HOST, WIN_SSH_PORT, WIN_SSH_USER, WIN_SSH_PASS
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(WIN_SSH_HOST, port=WIN_SSH_PORT, 
                   username=WIN_SSH_USER, password=WIN_SSH_PASS, timeout=10)
        
        # Remove SOAR rules
        cmd = 'netsh advfirewall firewall delete rule name="SOAR_BLOCK*"'
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
        output = stdout.read().decode().strip()
        ssh.close()
        
        print("✅ Removed Windows firewall rules")
        
    except Exception as e:
        print(f"⚠️  Could not remove Windows rules: {e}")
    
    print("✅ SOAR state reset completed!")
    print("🎯 Ready for fresh testing - all blocks removed, state cleared")

def _update_checkpoints(ckpt_mgr, zeek_events, suri_events, winlog_events):
    """Cập nhật checkpoint cho mỗi source dựa trên event mới nhất."""
    for source_name, events in [
        ("zeek", zeek_events),
        ("suricata", suri_events),
        ("winlogbeat", winlog_events),
    ]:
        if events:
            max_epoch = max(e.get("timestamp_epoch", 0) for e in events)
            if max_epoch > 0:
                ckpt_mgr.update_checkpoint(source_name, max_epoch)


def _sleep_or_exit(cycle_start):
    """Sleep đến hết POLL_INTERVAL, kiểm tra _running mỗi giây."""
    elapsed = time.time() - cycle_start
    remaining = max(0, POLL_INTERVAL - elapsed)
    for _ in range(int(remaining)):
        if not _running:
            return
        time.sleep(1)


def _print_final_report(ip_state):
    """In báo cáo cuối cùng khi DRY_RUN hoàn tất."""
    logger.info("\n" + "=" * 60)
    logger.info("  FINAL REPORT — DRY RUN")
    logger.info("=" * 60)

    if not ip_state:
        logger.info("  Không có IP nào được scoring.")
        return

    logger.info(f"\n{format_score_summary(ip_state)}\n")

    # Chi tiết từng IP
    for ip, data in sorted(
        ip_state.items(),
        key=lambda x: x[1]["total_score"],
        reverse=True,
    ):
        if data["total_score"] == 0:
            continue

        logger.info(f"  ── {ip} (score={data['total_score']}) ──")
        for log_entry in data.get("rules_log", []):
            logger.info(
                f"    [{log_entry['rule']}] +{log_entry['points']}"
                f" — {log_entry['reason'][:120]}"
            )
        if data.get("blocked"):
            logger.info(f"    >>> IP ĐÃ BỊ BLOCK <<<")
        logger.info("")


# ==============================================================
# ENTRY POINT
# ==============================================================

if __name__ == "__main__":
    main()
