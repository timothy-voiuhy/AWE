"""
Catppuccin Mocha colour tokens.

Import individual names and use them in f-string stylesheets:

    from gui.palette import BASE, SURFACE0, TEXT, BLUE

    widget.setStyleSheet(f"background: {BASE}; color: {TEXT};")

Qt stylesheets require literal {{ / }} when used inside f-strings because
Python interprets single braces as format slots.
"""

# ── Background layers (darkest → lightest) ────────────────────────────────────
CRUST    = "#11111B"
MANTLE   = "#181825"
BASE     = "#1E1E2E"

# ── Surfaces / overlays ───────────────────────────────────────────────────────
SURFACE0 = "#313244"
SURFACE1 = "#45475A"
SURFACE2 = "#585B70"
OVERLAY0 = "#6C7086"
OVERLAY1 = "#7F849C"
OVERLAY2 = "#9399B2"

# ── Text ──────────────────────────────────────────────────────────────────────
SUBTEXT1 = "#BAC2DE"
TEXT     = "#CDD6F4"

# ── Accent colours ────────────────────────────────────────────────────────────
ROSEWATER = "#F5E0DC"
FLAMINGO  = "#F2CDCD"
PINK      = "#F5C2E7"
MAUVE     = "#CBA6F7"
RED       = "#F38BA8"
MAROON    = "#EBA0AC"
PEACH     = "#FAB387"
YELLOW    = "#F9E2AF"
GREEN     = "#A6E3A1"
TEAL      = "#94E2D5"
SKY       = "#89DCEB"
SAPPHIRE  = "#74C7EC"
BLUE      = "#89B4FA"
LAVENDER  = "#B4BEFE"

# ── Reusable stylesheet fragments ─────────────────────────────────────────────

SCROLLBAR_V = (
    f"QScrollBar:vertical {{ background:{MANTLE}; width:8px; border:none; }}"
    f"QScrollBar::handle:vertical {{ background:{SURFACE0}; border-radius:4px; min-height:20px; }}"
    f"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}"
)

SCROLLBAR_V_THIN = (
    f"QScrollBar:vertical {{ background:{MANTLE}; width:4px; border:none; }}"
    f"QScrollBar::handle:vertical {{ background:{SURFACE0}; border-radius:2px; min-height:20px; }}"
    f"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}"
)

TAB_BAR = f"""
    QTabWidget::pane {{ border:none; background:{BASE}; }}
    QTabBar::tab {{ background:{MANTLE}; color:{OVERLAY0}; border:none;
                   border-bottom:2px solid transparent; padding:6px 18px; font-size:9px; }}
    QTabBar::tab:selected {{ color:{TEXT}; border-bottom:2px solid {MAUVE}; background:{BASE}; }}
    QTabBar::tab:hover:!selected {{ color:{TEXT}; background:{SURFACE0}; }}
"""
