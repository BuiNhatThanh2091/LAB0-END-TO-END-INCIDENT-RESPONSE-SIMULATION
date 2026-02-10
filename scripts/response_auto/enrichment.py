"""
enrichment.py — Threat Intelligence Enrichment Layer (Mock)
=============================================================
Giả lập tra cứu Threat Intelligence database (VirusTotal/AbuseIPDB).

Trong môi trường thực (production):
  - Gọi API VirusTotal: virustotal.com/api/v3/ip_addresses/{ip}
  - Gọi API AbuseIPDB: abuseipdb.com/check/{ip}
  - Gọi API AlienVault OTX, ThreatFox, etc.

Trong lab này (mock):
  - Đọc file JSON local (data/threat_intel_db.json)
  - Giả lập latency để realistic (random 0.5-1.5s)
  - Trả về cấu trúc giống API thật

Sử dụng:
    enricher = ThreatIntelEnricher()
    result = enricher.lookup_ip("10.10.10.130")
    if result["reputation"] == "malicious":
        score_boost = 50
"""

import json
import os
import time
import random
from config import (
    THREAT_INTEL_ENABLED, THREAT_INTEL_DB_PATH,
    TI_SCORE_MALICIOUS, TI_SCORE_SUSPICIOUS, TI_SCORE_CLEAN,
)
from logger_setup import setup_logger

logger = setup_logger("enrichment")


class ThreatIntelEnricher:
    """
    Mock Threat Intelligence lookup engine.
    
    Ưu điểm giả lập trong lab:
      1. Không tốn API quota (VirusTotal free = 4 req/min)
      2. Không cần internet (chạy offline)
      3. Kiểm soát được test data
      4. Demo được flow enrichment cho portfolio/báo cáo
    """
    
    def __init__(self):
        self.db_path = THREAT_INTEL_DB_PATH
        self.db = self._load_database()
        self.lookup_count = 0
        self.cache = {}  # Cache để tránh lookup lặp lại
        
        if self.db:
            ip_count = len([k for k in self.db.keys() if not k.startswith("_")])
            logger.info(f"ThreatIntelEnricher initialized: {ip_count} IPs in database")
        else:
            logger.warning("ThreatIntelEnricher initialized: Database empty or missing")
    
    def _load_database(self):
        """Load mock TI database từ JSON file."""
        if not os.path.exists(self.db_path):
            logger.error(f"Threat Intel DB not found: {self.db_path}")
            return {}
        
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                db = json.load(f)
            
            logger.debug(f"Loaded TI database from {self.db_path}")
            return db
            
        except Exception as e:
            logger.error(f"Failed to load TI database: {e}")
            return {}
    
    def lookup_ip(self, ip, simulate_latency=True):
        """
        Tra cứu reputation của IP.
        
        Args:
            ip: IP address string
            simulate_latency: Có giả lập network latency không (0.5-1.5s)
            
        Returns:
            dict: {
                "ip": str,
                "found": bool,
                "reputation": "clean" | "suspicious" | "malicious",
                "confidence": int (0-100),
                "score_boost": int (điểm cộng thêm),
                "reason": str,
                "details": dict (thông tin chi tiết từ DB)
            }
        """
        if not THREAT_INTEL_ENABLED:
            return self._not_found_result(ip)
        
        # Check cache
        if ip in self.cache:
            logger.debug(f"[TI] Cache hit for {ip}")
            return self.cache[ip]
        
        # Giả lập API call latency (realistic behavior)
        if simulate_latency:
            latency = random.uniform(0.5, 1.5)
            time.sleep(latency)
            logger.debug(f"[TI] Simulated API latency: {latency:.2f}s")
        
        self.lookup_count += 1
        
        # Lookup trong database
        if ip in self.db and not ip.startswith("_"):
            result = self._found_result(ip, self.db[ip])
        else:
            result = self._not_found_result(ip)
        
        # Cache result
        self.cache[ip] = result
        
        logger.info(
            f"[TI] {ip}: {result['reputation']} "
            f"(confidence={result['confidence']}%, boost=+{result['score_boost']})"
        )
        
        return result
    
    def _found_result(self, ip, db_entry):
        """Xây dựng kết quả khi IP được tìm thấy trong DB."""
        reputation = db_entry.get("reputation", "unknown")
        confidence = db_entry.get("confidence", 50)
        
        # Map reputation → score boost
        score_boost = {
            "malicious": TI_SCORE_MALICIOUS,
            "suspicious": TI_SCORE_SUSPICIOUS,
            "clean": TI_SCORE_CLEAN,
        }.get(reputation, 0)
        
        return {
            "ip": ip,
            "found": True,
            "reputation": reputation,
            "confidence": confidence,
            "score_boost": score_boost,
            "reason": db_entry.get("reason", "No reason provided"),
            "details": {
                "category": db_entry.get("category", "unknown"),
                "source": db_entry.get("source", "Mock DB"),
                "abuse_score": db_entry.get("abuse_score", 0),
                "tags": db_entry.get("tags", []),
                "last_seen": db_entry.get("last_seen", "unknown"),
            }
        }
    
    def _not_found_result(self, ip):
        """Xây dựng kết quả khi IP không tìm thấy trong DB."""
        return {
            "ip": ip,
            "found": False,
            "reputation": "unknown",
            "confidence": 0,
            "score_boost": 0,
            "reason": "IP not found in Threat Intel database",
            "details": {}
        }
    
    def bulk_lookup(self, ip_list, simulate_latency=True):
        """
        Tra cứu nhiều IP cùng lúc.
        
        Args:
            ip_list: List of IP addresses
            simulate_latency: Giả lập latency cho mỗi lookup
            
        Returns:
            dict: {ip: result_dict}
        """
        results = {}
        for ip in ip_list:
            results[ip] = self.lookup_ip(ip, simulate_latency=simulate_latency)
        return results
    
    def get_stats(self):
        """Lấy thống kê về enrichment usage."""
        return {
            "lookups_performed": self.lookup_count,
            "cache_size": len(self.cache),
            "database_ips": len([k for k in self.db.keys() if not k.startswith("_")]),
        }


# ==============================================================
# HELPER FUNCTIONS
# ==============================================================

def enrich_ip_state(enricher, ip_state, score_threshold=20):
    """
    Enrich toàn bộ IP state với TI data.
    
    Chỉ lookup IP có score >= threshold để tránh lookup vô nghĩa.
    
    Args:
        enricher: ThreatIntelEnricher instance
        ip_state: dict {ip: {total_score, ...}}
        score_threshold: Chỉ lookup IP có score >= threshold
        
    Returns:
        dict: {ip: TI_result} cho các IP đã lookup
    """
    ips_to_lookup = [
        ip for ip, data in ip_state.items()
        if data.get("total_score", 0) >= score_threshold
        and not data.get("blocked", False)  # Không lookup IP đã block
    ]
    
    if not ips_to_lookup:
        logger.debug("[TI] No IPs meet threshold for enrichment")
        return {}
    
    logger.info(f"[TI] Enriching {len(ips_to_lookup)} IPs (score >= {score_threshold})")
    
    # Bulk lookup
    ti_results = enricher.bulk_lookup(ips_to_lookup, simulate_latency=False)
    
    # Log summary
    malicious_count = sum(1 for r in ti_results.values() if r["reputation"] == "malicious")
    suspicious_count = sum(1 for r in ti_results.values() if r["reputation"] == "suspicious")
    
    logger.info(
        f"[TI] Enrichment complete: {malicious_count} malicious, "
        f"{suspicious_count} suspicious, {len(ti_results) - malicious_count - suspicious_count} clean/unknown"
    )
    
    return ti_results


def apply_ti_boost(ip_state, ti_results):
    """
    Áp dụng score boost từ TI data vào ip_state.
    
    Args:
        ip_state: dict {ip: {total_score, ...}}
        ti_results: dict {ip: TI_result}
        
    Returns:
        list: Score changes (format giống scoring.py)
    """
    changes = []
    
    for ip, ti_result in ti_results.items():
        if ip not in ip_state:
            continue
        
        boost = ti_result["score_boost"]
        if boost > 0:
            ip_state[ip]["total_score"] += boost
            ip_state[ip]["ti_enriched"] = True
            ip_state[ip]["ti_reputation"] = ti_result["reputation"]
            
            # Log change
            ip_state[ip].setdefault("rules_log", []).append({
                "time": time.time(),
                "rule": "TI_ENRICHMENT",
                "points": boost,
                "reason": f"TI: {ti_result['reputation']} ({ti_result['reason']})"
            })
            
            changes.append({
                "ip": ip,
                "rule": "TI_ENRICHMENT",
                "points": boost,
                "reason": ti_result["reason"]
            })
            
            logger.info(
                f"[TI] {ip}: +{boost} điểm ({ti_result['reputation']}, "
                f"confidence={ti_result['confidence']}%)"
            )
    
    return changes
