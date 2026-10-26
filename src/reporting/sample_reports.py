"""
Sample Evidence Reports Generation (Stage 3.4)
==============================================
Generates sample evidence-linked reports in both JSON and ReportLab PDF formats
for representative alerts across confidence bands:
  1. HIGH Confidence Incident (CONFIRM -> Auto-Escalate)
  2. MEDIUM Confidence Incident (REDUCE -> Suspicious / Review)
  3. REJECTED False Alarm (REJECT -> Dropped with audit evidence)

Outputs:
  - results/reports/json/{alert_id}.json
  - results/reports/pdf/{alert_id}.pdf
"""

import logging
from pathlib import Path
from typing import Dict, Any, List
from src.ingestion.log_replay import LogReplaySimulator
from src.reporting.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("TRUST-SOC.sample_reports")


def generate_sample_reports() -> List[Dict[str, Any]]:
    """
    Finds representative alerts across confidence bands and produces JSON & PDF reports.
    """
    log.info("Initializing Log Replay Simulator to sample representative alerts...")
    sim = LogReplaySimulator(enable_shap=True)
    rep_gen = ReportGenerator()

    samples_to_find = {
        "HIGH": None,
        "MEDIUM": None,
        "REJECT": None,
    }

    max_search = 500
    count = 0

    log.info("Searching replay stream for representative alert states...")
    while any(v is None for v in samples_to_find.values()) and count < max_search:
        count += 1
        alert = sim.next()

        if not alert.get("detection", {}).get("is_alert"):
            continue

        ver_dec = alert.get("verification", {}).get("decision")
        band = alert.get("scoring", {}).get("band")

        if samples_to_find["HIGH"] is None and band == "HIGH" and ver_dec == "CONFIRM":
            samples_to_find["HIGH"] = alert
            log.info(f"Found HIGH confidence sample (Alert {alert['alert_id']}: {alert['detection']['predicted_class']})")

        elif samples_to_find["MEDIUM"] is None and (band == "MEDIUM" or ver_dec == "REDUCE"):
            samples_to_find["MEDIUM"] = alert
            log.info(f"Found MEDIUM confidence sample (Alert {alert['alert_id']}: {alert['detection']['predicted_class']})")

        elif samples_to_find["REJECT"] is None and ver_dec == "REJECT":
            samples_to_find["REJECT"] = alert
            log.info(f"Found REJECT false-alarm sample (Alert {alert['alert_id']}: {alert['detection']['predicted_class']})")

    generated = []
    for category, alert in samples_to_find.items():
        if alert is not None:
            log.info(f"Generating evidence reports for {category} alert ({alert['alert_id']})...")
            res = rep_gen.generate_both_reports(alert)
            generated.append({
                "category": category,
                "alert_id": alert["alert_id"],
                "predicted_class": alert["detection"]["predicted_class"],
                "decision": alert["verification"]["decision"],
                "band": alert["scoring"]["band"],
                "composite": alert["scoring"]["composite"],
                "json_path": res["json_path"],
                "pdf_path": res["pdf_path"],
            })

    log.info("=" * 60)
    log.info(f"SAMPLE EVIDENCE REPORTS GENERATED: {len(generated)}")
    for g in generated:
        log.info(
            f"[{g['category']}] {g['predicted_class']} (C={g['composite']:.3f}, {g['band']}, {g['decision']})\n"
            f"   JSON: {g['json_path']}\n"
            f"   PDF:  {g['pdf_path']}"
        )
    log.info("=" * 60)

    return generated


if __name__ == "__main__":
    generate_sample_reports()
