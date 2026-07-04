"""AWE Catppuccin Mocha -> forgeai chat-widget QSS override.

forgeai.ui.theme.ThemeManager is intentionally never constructed here — it calls
QApplication.setStyleSheet() unconditionally, which would blow away AWE's own
appearance stylesheet (gui.appearance.apply_appearance). Instead this module builds
a small QSS fragment scoped to forgeai's known objectNames (confirmed by reading
forgeai/ui/widgets/{chat_widget,message_widget,tool_call_widget,permission_widget}.py)
and callers append it to whatever stylesheet is already applied.
"""
from __future__ import annotations

from gui.palette import (
    BASE, MANTLE, SURFACE0, SURFACE1, TEXT, SUBTEXT1, OVERLAY0,
    MAUVE, PINK, GREEN, RED, PEACH,
)


def awe_forgeai_qss() -> str:
    return f"""
    QWidget#ChatWidget {{ background:{BASE}; }}

    QTextEdit#ChatInput {{
        background:{MANTLE}; color:{TEXT};
        border:1px solid {SURFACE0}; border-radius:8px;
        padding:6px 10px;
    }}
    QTextEdit#ChatInput:focus {{ border-color:{MAUVE}; }}

    QPushButton#RoundPrimaryActionButton {{
        background:{MAUVE}; color:{BASE}; border:none; border-radius:18px;
        font-size:14px;
    }}
    QPushButton#RoundPrimaryActionButton:hover {{ background:{PINK}; }}

    QFrame#MessageBubbleUser {{ background:{SURFACE0}; border-radius:10px; }}
    QFrame#MessageBubbleAssistant {{ background:{MANTLE}; border-radius:10px; }}
    QLabel#MessageRoleLabel {{ color:{SUBTEXT1}; font-size:8pt; font-weight:bold; }}

    QFrame#ToolCallRow {{ background:{SURFACE1}; border-radius:6px; }}
    QLabel#ToolCallStateIdle {{ color:{OVERLAY0}; }}
    QLabel#ToolCallStateStarted {{ color:{PEACH}; }}
    QLabel#ToolCallStateFinished {{ color:{GREEN}; }}
    QLabel#ToolCallStateError {{ color:{RED}; }}

    QFrame#PermissionRequestWidget {{
        background:{MANTLE}; border:1px solid {PEACH}; border-radius:8px;
    }}
    """
