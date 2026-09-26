"""
FastAPI Route — /reports
=========================
GET /reports/{alert_id}/pdf  — download PDF for one alert
GET /reports/shap-plot       — serve the global SHAP bar chart PNG
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, FileResponse
from src.database.alert_store import get_alert
from src.reporting.pdf_report import generate_pdf
from src.config.config import SHAP_DIR, CM_DIR

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{alert_id}/pdf",
            summary="Download PDF evidence report for one alert",
            response_class=Response)
def download_pdf(alert_id: str):
    alert = get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    pdf_bytes = generate_pdf(alert)
    return Response(
        content     = pdf_bytes,
        media_type  = "application/pdf",
        headers     = {
            "Content-Disposition": f'attachment; filename="TRUST-SOC_{alert_id}.pdf"'
        },
    )


@router.get("/shap-plot",
            summary="Global SHAP feature importance bar chart (PNG)")
def shap_plot():
    path = SHAP_DIR / "shap_summary_bar.png"
    if not path.exists():
        raise HTTPException(status_code=404, detail="SHAP plot not found. Run SHAP stage first.")
    return FileResponse(str(path), media_type="image/png")


@router.get("/confusion-matrix",
            summary="Confusion matrix PNG")
def confusion_matrix():
    path = CM_DIR / "confusion_matrix.png"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Confusion matrix not found. Run evaluate stage first.")
    return FileResponse(str(path), media_type="image/png")
