from PySide6.QtGui import QEnterEvent
from PySide6.QtWidgets import QPushButton, QToolTip


class HoverButton(QPushButton):
    def __init__(self, text, tooltip_text, parent=None):
        super().__init__(text, parent)
        self.setToolTip(tooltip_text)

    def enterEvent(self, event: QEnterEvent) -> None:
        QToolTip.showText(self.mapToGlobal(self.rect().bottomLeft()), self.toolTip())
