"""
TRUST-SOC Label Mapping Specification (Stage 1.2)
=================================================
Maps the 15 raw CICIDS2017 labels to the 6 locked project classes:
1. Benign
2. DoS/DDoS
3. Port Scan
4. Brute Force
5. Web Attack
6. Botnet

Excludes:
- Infiltration (36 flows, <0.001%)
- Heartbleed (11 flows, <0.0004%)
"""

from typing import Optional, Dict

PROJECT_CLASSES = [
    "Benign",
    "DoS/DDoS",
    "Port Scan",
    "Brute Force",
    "Web Attack",
    "Botnet",
]

LABEL_MAPPING: Dict[str, str] = {
    # ── Benign ────────────────────────────────────────────────────────
    "BENIGN": "Benign",

    # ── DoS / DDoS ────────────────────────────────────────────────────
    "DoS Hulk": "DoS/DDoS",
    "DDoS": "DoS/DDoS",
    "DoS GoldenEye": "DoS/DDoS",
    "DoS slowloris": "DoS/DDoS",
    "DoS Slowhttptest": "DoS/DDoS",

    # ── Port Scan ─────────────────────────────────────────────────────
    "PortScan": "Port Scan",

    # ── Brute Force (Network Protocols) ───────────────────────────────
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",

    # ── Web Attack (Application Layer) ────────────────────────────────
    # Handles encoding variants across different operating systems / CSV exports
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack \x96 Brute Force": "Web Attack",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack \x96 XSS": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack \x96 Sql Injection": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",

    # ── Botnet ────────────────────────────────────────────────────────
    "Bot": "Botnet",
}

EXCLUDED_LABELS: Dict[str, str] = {
    "Infiltration": "Out-of-scope workstation exploit (36 flows across 2.8M, 0.001%)",
    "Heartbleed": "Out-of-scope memory disclosure (11 flows across 2.8M, 0.0004%)",
}


def map_raw_label(raw_label: str) -> Optional[str]:
    """
    Maps a raw CICIDS2017 label string to a project class.
    Returns None if the label is excluded.
    """
    clean_label = str(raw_label).strip()
    # Normalize unicode / cp1252 dashes in web attack labels
    normalized_label = clean_label.replace("–", "-").replace("\x96", "-")

    if clean_label in LABEL_MAPPING:
        return LABEL_MAPPING[clean_label]

    if normalized_label in LABEL_MAPPING:
        return LABEL_MAPPING[normalized_label]

    for raw_key, target in LABEL_MAPPING.items():
        if raw_key.replace("–", "-").replace("\x96", "-") == normalized_label:
            return target

    if clean_label in EXCLUDED_LABELS or normalized_label in EXCLUDED_LABELS:
        return None

    raise ValueError(f"Unrecognized dataset label: '{raw_label}'")
