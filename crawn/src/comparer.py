from PySide6.QtWidgets import QWidget, QMainWindow, QVBoxLayout

"""drill
-comparing two text objects.
-use the aid of a syntaxhighlighter when showing the similarities and differences between the objects
-the highlighting is dependent on whether there is a similarity or not.
-
"""


class ComparerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.comparer_central_widget = QWidget()
        self.setCentralWidget(self.comparer_central_widget)

        self.comparer_main_layout = QVBoxLayout()
        self.comparer_central_widget.setLayout(self.comparer_main_layout)
