from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QDockWidget, QPushButton, QMainWindow


class NetworkWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        # self.IniatializeNetworkWindow()

    def IniatializeNetworkWindow(self):
        self.NetworkWindow_ = QWidget()
        self.setCentralWidget(self.NetworkWindow_)
        self.setWindowTitle("Network")
        self.NetworkWindowLayoutMain = QVBoxLayout()
        # network dock
        self.NetworkMapDock = QDockWidget()
        self.NetworkMapDockArea = Qt.DockWidgetArea()
        self.addDockWidget(
            self.NetworkMapDockArea.RightDockWidgetArea, self.NetworkMapDock
        )

        self.test_button = QPushButton()
        self.test_button.setText("button")

        self.NetworkMapDockWidget = QWidget(self.NetworkMapDock)
        self.NetworkDockLayout = QVBoxLayout()
        self.NetworkMapDockWidget.setLayout(self.NetworkDockLayout)

        self.NetworkDockLayout.addWidget(self.test_button)
        self.NetworkWindow_.setLayout(self.NetworkWindowLayoutMain)

        return self.NetworkWindow_