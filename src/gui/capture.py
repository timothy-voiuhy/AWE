from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout


class ProxyCaptureWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.cw_layout = QVBoxLayout()
        self.central_widget.setLayout(self.cw_layout)


