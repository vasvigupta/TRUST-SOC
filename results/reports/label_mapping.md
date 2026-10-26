# TRUST-SOC: Label Mapping Specification (Stage 1.2)

## 1. Overview
The CICIDS2017 dataset (TrafficLabelling / GeneratedLabelledFlows variant) contains **15 distinct raw labels** across **2,830,743 valid network flows**.

The synopsis and project architecture lock the detection pipeline into **six standardized project classes**:
1. `Benign`
2. `DoS/DDoS`
3. `Port Scan`
4. `Brute Force`
5. `Web Attack`
6. `Botnet`

---

## 2. Label Mapping Table

| # | Original CICIDS2017 Raw Label | Raw Flow Count | % of Valid Dataset | TRUST-SOC Target Class | Classification Justification |
|---|---|---|---|---|---|
| 1 | `BENIGN` | 2,273,097 | 80.3004% | **Benign** | Normal background traffic. |
| 2 | `DoS Hulk` | 231,073 | 8.1630% | **DoS/DDoS** | Application-layer volumetric HTTP flood. |
| 3 | `PortScan` | 158,930 | 5.6144% | **Port Scan** | Network reconnaissance / service scanning (SYN / RST sweeps). |
| 4 | `DDoS` | 128,027 | 4.5227% | **DoS/DDoS** | Distributed volumetric Denial of Service traffic. |
| 5 | `DoS GoldenEye` | 10,293 | 0.3636% | **DoS/DDoS** | HTTP Keep-Alive DoS tool. |
| 6 | `FTP-Patator` | 7,938 | 0.2804% | **Brute Force** | Multi-threaded FTP credential brute force attack. |
| 7 | `SSH-Patator` | 5,897 | 0.2083% | **Brute Force** | Multi-threaded SSH credential brute force attack. |
| 8 | `DoS slowloris` | 5,796 | 0.2048% | **DoS/DDoS** | Low-and-slow HTTP connection exhaustion DoS. |
| 9 | `DoS Slowhttptest` | 5,499 | 0.1943% | **DoS/DDoS** | Slow HTTP POST/Read attack variant. |
| 10 | `Bot` | 1,966 | 0.0695% | **Botnet** | Ares botnet C2 periodic communication / command execution. |
| 11 | `Web Attack – Brute Force` | 1,507 | 0.0532% | **Web Attack** | HTTP application credential stuffing against web portal. Kept under Web Attack (distinct from network protocol brute force). |
| 12 | `Web Attack – XSS` | 652 | 0.0230% | **Web Attack** | Cross-Site Scripting exploit injection payload. |
| 13 | `Web Attack – Sql Injection` | 21 | 0.0007% | **Web Attack** | SQL injection exploit attempt. |
| 14 | `Infiltration` | 36 | 0.0013% | **EXCLUDED** | Windows Vista / Mac workstation exploitation via Dropbox/MetaSploit. Only 36 flows across 2.8M flows (0.001%). Out-of-scope for 6 classes; excluded to prevent spurious training noise. |
| 15 | `Heartbleed` | 11 | 0.0004% | **EXCLUDED** | OpenSSL CVE-2014-0160 memory disclosure vulnerability. Only 11 flows in entire dataset (0.0004%). Excluded as statistically non-viable for machine learning stratification. |

---

## 3. Projected 6-Class Distribution (Post-Mapping)

| Target Class | Total Flows | Share of Mapped Dataset | Attack vs Benign |
|---|---|---|---|
| **Benign** | 2,273,097 | 80.3017% | Benign Baseline |
| **DoS/DDoS** | 380,688 | 13.4487% | Attack |
| **Port Scan** | 158,930 | 5.6145% | Attack |
| **Brute Force** | 13,835 | 0.4888% | Attack |
| **Web Attack** | 2,180 | 0.0770% | Attack |
| **Botnet** | 1,966 | 0.0695% | Attack |
| **Total Mapped Flows** | **2,830,696** | **100.00%** | (557,599 Attack flows, 19.70%) |
| *Excluded Flows* | 47 | (36 Infiltration + 11 Heartbleed) | Excluded |

---

## 4. Specific Design Clarifications

1. **`Web Attack – Brute Force` vs Network `Brute Force`**:
   `Web Attack – Brute Force` targets web applications (HTTP ports 80/8080) and exhibits distinct payload and packet size characteristics compared to protocol brute-force attacks (`FTP-Patator` on port 21 and `SSH-Patator` on port 22). It is therefore classified strictly under **Web Attack**.

2. **Encoding Normalization**:
   The Web Attack labels in CICIDS2017 raw CSVs contain byte encoding variations (en-dash `–`, `\x96`, or hyphen `-`). The mapping parser normalizes all dash variants to ensure 100% matching.
