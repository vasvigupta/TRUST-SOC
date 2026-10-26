"""
Signal (a): Rule and Context Corroboration (r)
==============================================
Validates whether an alerted flow matches deterministic network signatures,
MITRE ATT&CK technique patterns, asset criticality, and whitelist rules.

Strictly adheres to Section 4.2(a) and Section 11 (Milestone 2) specifications.
Does NOT inspect ground_truth or Detection Agent probability p_d.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from src.config.config import (
    RULES_PATH,
    ASSET_CONTEXT_PATH,
    STRONG_CONTRADICTION_THRESHOLD,
)


class RuleContextVerifier:
    """Evaluates deterministic network rules, asset inventory, and whitelist constraints."""

    def __init__(
        self,
        rules_path: Path = RULES_PATH,
        asset_path: Path = ASSET_CONTEXT_PATH,
        strong_contra_thresh: float = STRONG_CONTRADICTION_THRESHOLD,
    ):
        self.strong_contra_thresh = strong_contra_thresh

        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules_config = json.load(f)

        with open(asset_path, "r", encoding="utf-8") as f:
            self.asset_config = json.load(f)

        self.class_rules = self.rules_config.get("classes", {})
        self.critical_assets = self.asset_config.get("critical_assets", {})
        self.whitelisted_flows = self.asset_config.get("whitelisted_flows", [])

    def verify_flow(
        self,
        predicted_class: str,
        flow_metadata: Dict[str, Any],
        flow_features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Computes corroboration score r in [0, 1].

        Args:
            predicted_class: The attack class predicted by Detection Agent.
            flow_metadata: Dict with Source IP, Destination IP, Source Port, Destination Port, Protocol.
            flow_features: Dict with unscaled or original feature measurements.

        Returns:
            Dict conforming to common signal contract:
            {"score": float, "strongly_contradictory": bool, "details": dict}
        """
        # If class is Benign or unknown, return neutral / base
        if predicted_class not in self.class_rules:
            return {
                "score": 0.5,
                "strongly_contradictory": False,
                "details": {"reason": f"Class '{predicted_class}' has no active rule template."},
            }

        rule_def = self.class_rules[predicted_class]
        mitre_info = rule_def.get("mitre", {})
        class_rules = rule_def.get("rules", {})

        dst_ip = str(flow_metadata.get("Destination IP", "")).strip()
        src_ip = str(flow_metadata.get("Source IP", "")).strip()
        dst_port = int(flow_metadata.get("Destination Port", 0))
        protocol = int(flow_metadata.get("Protocol", 0))

        matched_rules = []
        violated_rules = []

        # 1. Whitelist Check (e.g. Standard Internal Infrastructure DNS)
        for wl in self.whitelisted_flows:
            if dst_ip == wl.get("dst_ip") and dst_port == wl.get("dst_port") and protocol == wl.get("protocol"):
                # Traffic is normal whitelisted infrastructure traffic
                details = {
                    "matched_rules": [],
                    "violated_rules": [f"Whitelisted infrastructure flow: {wl.get('description')}"],
                    "asset_criticality": "INTERNAL_INFRASTRUCTURE",
                    "mitre_technique": mitre_info,
                    "explanation": "Flow matches whitelisted internal service pattern.",
                }
                score = 0.05
                return {
                    "score": round(score, 4),
                    "strongly_contradictory": score < self.strong_contra_thresh,
                    "details": details,
                }

        # 2. Asset Criticality Check
        asset_info = self.critical_assets.get(dst_ip, {})
        asset_crit = asset_info.get("criticality", "STANDARD")
        crit_weight = asset_info.get("criticality_weight", 0.5)

        # 3. Class-Specific Deterministic Pattern Checks
        score = 0.0

        if predicted_class == "DoS/DDoS":
            expected_ports = class_rules.get("expected_ports", [80, 443, 8080])
            if dst_port in expected_ports:
                matched_rules.append(f"Target port {dst_port} matches expected DoS service ports {expected_ports}")
                score += 0.35
            else:
                violated_rules.append(f"Target port {dst_port} unexpected for DoS attack")

            duration = float(flow_features.get("Flow Duration", 0))
            pkts_rate = float(flow_features.get("Flow Packets/s", 0))
            pkt_len_mean = float(flow_features.get("Packet Length Mean", 0))

            if duration >= class_rules.get("flow_duration_min_us", 500000) or pkts_rate >= 5000 or pkt_len_mean >= 100:
                matched_rules.append("Flow duration, packet rate, or packet payload matches DoS volume profile")
                score += 0.35
            else:
                violated_rules.append("Flow volume and duration within low benign thresholds")

            if dst_ip == "192.168.10.50":
                matched_rules.append("Target is Ubuntu Web Server (192.168.10.50)")
                score += 0.30
            else:
                score += crit_weight * 0.20

        elif predicted_class == "Port Scan":
            duration = float(flow_features.get("Flow Duration", 0))
            fwd_pkts = float(flow_features.get("Total Fwd Packets", 0))
            pkts_rate = float(flow_features.get("Flow Packets/s", 0))

            if duration <= class_rules.get("flow_duration_max_us", 100000):
                matched_rules.append(f"Short flow duration ({duration:.0f} us) matches rapid port probing")
                score += 0.40
            else:
                violated_rules.append(f"Long flow duration ({duration:.0f} us) contradicts fast port sweep")

            if fwd_pkts <= class_rules.get("total_fwd_packets_max", 3):
                matched_rules.append(f"Low forward packet count ({fwd_pkts:.0f}) matches probe signature")
                score += 0.30
            else:
                violated_rules.append(f"High forward packet count ({fwd_pkts:.0f}) contradicts single-probe scan")

            if pkts_rate >= class_rules.get("flow_packets_s_min", 1000.0) or fwd_pkts <= 2:
                matched_rules.append("High instantaneous probe rate")
                score += 0.30
            else:
                score += 0.10

        elif predicted_class == "Brute Force":
            expected_ports = class_rules.get("expected_ports", [21, 22])
            if dst_port in expected_ports:
                matched_rules.append(f"Target port {dst_port} matches credential services (FTP/SSH)")
                score += 0.50
            else:
                violated_rules.append(f"Target port {dst_port} is not FTP (21) or SSH (22)")
                score += 0.0  # heavy contradiction

            fwd_pkts = float(flow_features.get("Total Fwd Packets", 0))
            if fwd_pkts >= class_rules.get("total_fwd_packets_min", 3):
                matched_rules.append(f"Repeated handshake/credential exchange ({fwd_pkts:.0f} pkts)")
                score += 0.25
            else:
                violated_rules.append(f"Too few packets ({fwd_pkts:.0f}) for credential brute force exchange")

            if dst_ip == "192.168.10.50":
                matched_rules.append("Target is central auth server (192.168.10.50)")
                score += 0.25
            else:
                score += crit_weight * 0.20

        elif predicted_class == "Web Attack":
            expected_ports = class_rules.get("expected_ports", [80, 443, 8080])
            if dst_port in expected_ports:
                matched_rules.append(f"Target port {dst_port} matches web application services")
                score += 0.50
            else:
                violated_rules.append(f"Target port {dst_port} is not a web application service")
                score += 0.0

            duration = float(flow_features.get("Flow Duration", 0))
            if duration >= class_rules.get("flow_duration_min_us", 100000):
                matched_rules.append("Sustained HTTP transaction duration")
                score += 0.25
            else:
                violated_rules.append("Instantaneous flow contradicts multi-stage web attack payload")

            if dst_ip == "192.168.10.50":
                matched_rules.append("Target is primary web server (192.168.10.50)")
                score += 0.25
            else:
                score += crit_weight * 0.20

        elif predicted_class == "Botnet":
            c2_ips = class_rules.get("known_c2_ips", ["205.174.165.73"])
            pkt_len_mean = float(flow_features.get("Packet Length Mean", 0))

            is_c2_conn = (dst_ip in c2_ips) or (src_ip in c2_ips)
            is_c2_port = (dst_port == 8080)

            if is_c2_conn or is_c2_port:
                matched_rules.append(f"Connection involves Botnet C2 infrastructure ({dst_ip}:{dst_port})")
                score += 0.55
            else:
                violated_rules.append(f"Target {dst_ip}:{dst_port} not associated with botnet C2 traffic")

            if pkt_len_mean <= class_rules.get("packet_length_mean_max", 250.0):
                matched_rules.append(f"Lightweight beacon payload length ({pkt_len_mean:.1f} bytes)")
                score += 0.25
            else:
                violated_rules.append(f"Heavy payload ({pkt_len_mean:.1f} bytes) contradicts periodic bot beacon")

            # If flow is internal standard service (e.g. port 22 or 53 or 80 to internal IP without C2), penalize
            if not is_c2_conn and not is_c2_port and dst_ip.startswith("192.168.10."):
                score = min(score, 0.15)
                violated_rules.append("Internal standard service flow falsely alerted as external botnet")
            else:
                score += 0.20

        # Clamping
        score = max(0.0, min(1.0, float(score)))

        details = {
            "matched_rules": matched_rules,
            "violated_rules": violated_rules,
            "asset_criticality": asset_crit,
            "mitre_technique": mitre_info,
        }

        return {
            "score": round(score, 4),
            "strongly_contradictory": score < self.strong_contra_thresh,
            "details": details,
        }
