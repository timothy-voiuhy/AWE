"""
App-level appearance helpers — theme palette, font state, and persistence.
Shared between targetWindow and settingsWindow.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

# ── Persistence file ──────────────────────────────────────────────────────────

_SETTINGS_FILE = Path(os.path.expanduser("~")) / ".config" / "awe" / "ui_settings.json"


def load_ui_settings() -> dict:
    try:
        return json.loads(_SETTINGS_FILE.read_text())
    except Exception:
        return {}


def save_ui_settings(data: dict) -> None:
    _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_FILE.write_text(json.dumps(data, indent=2))


# ── Theme palettes ────────────────────────────────────────────────────────────

THEMES: dict[str, dict] = {
    "Catppuccin Mocha": {
        "base":    "#1E1E2E",
        "mantle":  "#181825",
        "surface": "#313244",
        "overlay": "#45475A",
        "text":    "#CDD6F4",
        "subtext": "#BAC2DE",
        "accent":  "#CBA6F7",
        "accent2": "#89B4FA",
        "green":   "#A6E3A1",
        "red":     "#F38BA8",
        "yellow":  "#F9E2AF",
        "peach":   "#FAB387",
    },
    "Catppuccin Macchiato": {
        "base":    "#1E2030",
        "mantle":  "#181926",
        "surface": "#363A4F",
        "overlay": "#494D64",
        "text":    "#CAD3F5",
        "subtext": "#B8C0E0",
        "accent":  "#C6A0F6",
        "accent2": "#8AADF4",
        "green":   "#A6DA95",
        "red":     "#ED8796",
        "yellow":  "#EED49F",
        "peach":   "#F5A97F",
    },
    "Catppuccin Frappe": {
        "base":    "#303446",
        "mantle":  "#292C3C",
        "surface": "#414559",
        "overlay": "#51576D",
        "text":    "#C6D0F5",
        "subtext": "#B5BFE2",
        "accent":  "#CA9EE6",
        "accent2": "#8CAAEE",
        "green":   "#A6D189",
        "red":     "#E78284",
        "yellow":  "#E5C890",
        "peach":   "#EF9F76",
    },
    "Catppuccin Latte": {
        "base":    "#EFF1F5",
        "mantle":  "#E6E9EF",
        "surface": "#CCD0DA",
        "overlay": "#ACB0BE",
        "text":    "#4C4F69",
        "subtext": "#5C5F77",
        "accent":  "#8839EF",
        "accent2": "#1E66F5",
        "green":   "#40A02B",
        "red":     "#D20F39",
        "yellow":  "#DF8E1D",
        "peach":   "#FE640B",
    },
}

MONO_FONTS = [
    "Cascadia Code", "JetBrains Mono", "Fira Code",
    "Hack", "Inconsolata", "Source Code Pro",
    "Ubuntu Mono", "DejaVu Sans Mono", "Monospace",
]

# Current state — updated by apply_appearance()
_app_state: dict = {
    "theme": "Catppuccin Mocha",
    "font_family": "Monospace",
    "font_size": 10,
}


def apply_appearance(
    theme_name: str | None = None,
    font_family: str | None = None,
    font_size: int | None = None,
) -> None:
    """Apply theme colours and font in a single stylesheet."""
    if theme_name  is not None: _app_state["theme"]       = theme_name
    if font_family is not None: _app_state["font_family"] = font_family
    if font_size   is not None: _app_state["font_size"]   = font_size

    t   = THEMES.get(_app_state["theme"], THEMES["Catppuccin Mocha"])
    fam = _app_state["font_family"]
    sz  = _app_state["font_size"]

    QApplication.instance().setFont(QFont(fam, sz))
    QApplication.instance().setStyleSheet(f"""
        QWidget          {{ background:{t['base']}; color:{t['text']};
                            font-family:'{fam}'; font-size:{sz}pt; }}
        QMainWindow      {{ background:{t['mantle']}; }}
        QFrame           {{ border:none; }}
        QScrollBar:vertical   {{ background:{t['mantle']}; width:8px; border:none; }}
        QScrollBar::handle:vertical {{ background:{t['surface']}; border-radius:4px; min-height:20px; }}
        QScrollBar:horizontal {{ background:{t['mantle']}; height:8px; border:none; }}
        QScrollBar::handle:horizontal {{ background:{t['surface']}; border-radius:4px; min-width:20px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
        QTabWidget::pane {{ border:1px solid {t['surface']}; background:{t['base']}; }}
        QTabBar::tab      {{ background:{t['mantle']}; color:{t['subtext']};
                             padding:6px 14px; border:none; border-radius:4px 4px 0 0; }}
        QTabBar::tab:selected {{ background:{t['surface']}; color:{t['text']}; }}
        QTabBar::tab:hover    {{ background:{t['overlay']}; color:{t['text']}; }}
        QPushButton  {{ background:{t['surface']}; color:{t['text']};
                        border:1px solid {t['overlay']}; border-radius:5px;
                        padding:5px 14px; min-height:26px; }}
        QPushButton:hover {{ background:{t['overlay']}; border-color:{t['accent2']}; }}
        QPushButton:pressed {{ background:{t['mantle']}; }}
        QLineEdit, QComboBox, QTextEdit, QSpinBox {{
            background:{t['mantle']}; color:{t['text']};
            border:1px solid {t['overlay']}; border-radius:4px;
            padding:3px 8px; }}
        QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QSpinBox:focus {{
            border-color:{t['accent2']}; }}
        QTableWidget  {{ background:{t['base']}; gridline-color:{t['surface']};
                         alternate-background-color:{t['mantle']}; }}
        QHeaderView::section {{ background:{t['surface']}; color:{t['subtext']};
                                 border:none; padding:4px 8px; }}
        QTreeView, QListView {{ background:{t['base']}; alternate-background-color:{t['mantle']}; }}
        QToolTip  {{ background:{t['surface']}; color:{t['text']};
                     border:1px solid {t['overlay']}; border-radius:4px; padding:4px; }}
        QSplitter::handle {{ background:{t['surface']}; }}
        QMenu     {{ background:{t['mantle']}; color:{t['text']};
                     border:1px solid {t['surface']}; border-radius:6px; padding:4px; }}
        QMenu::item:selected {{ background:{t['surface']}; border-radius:3px; }}
        QMenu::separator {{ background:{t['surface']}; height:1px; margin:4px 6px; }}
    """)
