To draw a line and a circle in PySide6 (a Python binding for the Qt framework), you can create a custom widget inheriting from QPainter and draw the line and circle using its drawing functions. Here's a simple example demonstrating how to do this:

python
Copy code
import sys
from PySide6.QtWidgets import QApplication, QWidget
from PySide6.QtGui import QPainter, QPen, QColor
from PySide6.QtCore import Qt


class DrawingWidget(QWidget):
    def __init__(self):
        super().__init__()

    def paintEvent(self, event):
        # Create a QPainter object
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)  # Enable antialiasing for smoother lines

        # Draw a line
        pen = QPen(QColor("blue"))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawLine(20, 20, 200, 100)

        # Draw a circle
        pen.setColor(QColor("red"))
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)  # No fill for the circle
        painter.drawEllipse(100, 50, 100, 100)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Create the main window
    window = QWidget()
    window.setWindowTitle("Drawing Line and Circle")
    window.resize(300, 200)

    # Create the custom drawing widget and set it as the central widget
    drawing_widget = DrawingWidget()
    window.setCentralWidget(drawing_widget)

    # Show the window
    window.show()

    sys.exit(app.exec())
In this example:

We create a custom widget DrawingWidget inheriting from QWidget.
In the paintEvent method of the widget, we override the default paint behavior and use a QPainter object to draw a line and a circle.
We set the color and width of the line and circle using QPen.
The QPainter provides various drawing functions like drawLine and drawEllipse which we use to draw the line and circle respectively.
Finally, we create an instance of QApplication, create the main window, set the custom widget as the central widget, and then start the application event loop.