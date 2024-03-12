from PySide6.QtCore import Qt
from PySide6.QtGui import QMatrix4x4, QVector3D, QQuaternion
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget
from PySide6.Qt3DCore import Qt3DCore
from PySide6.Qt3DExtras import Qt3DExtras

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        # Create the 3D view
        self.view = Qt3DExtras.Qt3DWindow()
        self.setCentralWidget(QWidget.createWindowContainer(self.view))

        # Create the 3D scene
        self.scene = Qt3DCore.QEntity()

        # Create a 3D cube
        cube_entity = Qt3DCore.QEntity(self.scene)
        cube_mesh = Qt3DExtras.QCuboidMesh()
        cube_material = Qt3DExtras.QPhongMaterial()
        cube_transform = Qt3DCore.QTransform()

        # Set the cube's properties
        cube_entity.addComponent(cube_mesh)
        cube_entity.addComponent(cube_material)
        cube_entity.addComponent(cube_transform)

        cube_transform.setScale3D(QVector3D(1.0, 1.0, 1.0))
        cube_transform.setRotation(QQuaternion.fromAxisAndAngle(QVector3D(1, 0, 0), 45))


        # Create the root entity
        root_entity = Qt3DCore.QEntity(self.scene)
        root_entity.addComponent(cube_entity)

        # Set up the camera
        camera_entity = self.view.camera()
        camera_entity.lens().setPerspectiveProjection(45.0, 16.0/9.0, 0.1, 100.0)
        camera_entity.setPosition(QVector3D(0, 0, 10))
        camera_entity.setViewCenter(QVector3D(0, 0, 0))

        # Set up the camera controller
        cam_controller = Qt3DExtras.QOrbitCameraController(self.scene)
        cam_controller.setCamera(camera_entity)

        # Set up the main window
        self.setWindowTitle("PySide6 3D Example")
        self.setGeometry(100, 100, 800, 600)

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()
