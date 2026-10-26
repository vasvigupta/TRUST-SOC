"""
TRUST-SOC Theme Configuration
=============================
Locked light theme tokens for all components:
- Matplotlib / SHAP static plots
- PDF reports (ReportLab)
- Streamlit prototype
- Dashboard (CSS properties)

Rules:
- White / very-light backgrounds only (#F7F9FC / #FFFFFF).
- Never rely on colour alone - always include text labels (HIGH / MEDIUM / LOW).
- WCAG AA contrast (>= 4.5:1 for normal body text).
"""

THEME = {
    # Surfaces & Backgrounds
    "bg": "#F7F9FC",           # page background
    "surface": "#FFFFFF",      # cards, tables, drawers
    "border": "#D9E0EA",       # borders and dividers
    "text": "#1F2937",         # primary body text
    "text_muted": "#5B6676",   # secondary / muted text
    "primary": "#1F3864",      # deep navy (matches synopsis headers)
    "primary_soft": "#E8EEF8", # soft navy tint
    "accent": "#2F6FB3",       # interactive blue accent

    # Confidence bands (must always be paired with text labels)
    "high": "#B42318",         # HIGH (red)
    "medium": "#B54708",       # MEDIUM (amber)
    "low": "#2E7D5B",          # LOW (green)

    # Verification decisions
    "confirm": "#1F6F43",      # CONFIRM (forest green)
    "reduce": "#B54708",       # REDUCE (amber)
    "reject": "#5B6676",       # REJECT (muted grey)
}

def apply_matplotlib_theme(plt):
    """
    Configures Matplotlib global rcParams to enforce the TRUST-SOC light theme.
    """
    plt.rcParams.update({
        "figure.facecolor": THEME["surface"],
        "axes.facecolor": THEME["surface"],
        "savefig.facecolor": THEME["surface"],
        "axes.edgecolor": THEME["border"],
        "axes.labelcolor": THEME["text"],
        "text.color": THEME["text"],
        "xtick.color": THEME["text"],
        "ytick.color": THEME["text"],
        "grid.color": THEME["border"],
        "grid.alpha": 0.5,
        "grid.linestyle": "--",
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "Arial", "DejaVu Sans", "Helvetica"],
    })
