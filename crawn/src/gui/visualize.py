import sys

from PySide6.Qt3DCore import Qt3DCore
from PySide6.Qt3DExtras import Qt3DExtras
from PySide6.Qt3DRender import Qt3DRender
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QVector3D
from PySide6.QtWidgets import (QApplication, QFormLayout, QLabel, QVBoxLayout, QWidget, QMainWindow, QListWidget)


class BasicShape(Qt3DCore.QEntity):
    def __init__(self, parent,main_window, shape:str, diffuse_color:QColor=None, shininess=0.5, angle_transform:tuple = None,
                 translation_transforms:QVector3D = None, transform_scale:float = None) -> None:
        super().__init__(parent)
        self.entity = Qt3DCore.QEntity()
        self.mainWindow = main_window
        self.material = Qt3DExtras.QPhongAlphaMaterial()
        self.transform = Qt3DCore.QTransform()
        self.shape = shape
        self.shininess=  shininess
        self.diffuse_color = diffuse_color
        self.mesh = self.getMesh()
        
        # geometry
        self.angle_transform = angle_transform
        self.translation_transforms = translation_transforms
        self.transform_scale = transform_scale
        
        # picker
        self.picker = Qt3DRender.QObjectPicker()
        self.picker.clicked.connect(self.handlePickerClickEvent)
        self.picker.setDragEnabled(True)

        self.setSettings()
        
        self.addComponent(self.material)
        self.addComponent(self.mesh)
        self.addComponent(self.transform)
        self.addComponent(self.picker)
    
    def handlePickerClickEvent(self):
        self.mainWindow.handlePickerClickEvent()
    #@classmethod
    #def getCount(self)

    def setSettings(self):
        # set material settings
        if self.diffuse_color is not None:
            self.material.setDiffuse(Qt.magenta)
        self.material.setShininess(self.shininess)        
        # set transform settings
        if self.angle_transform is not None:
            self.transform.setRotationX(self.angle_transform[0])
            self.transform.setRotationY(self.angle_transform[1])
            self.transform.setRotationZ(self.angle_transform[2])
        if self.translation_transforms is not None:
            self.transform.setTranslation(self.translation_transforms)
        if self.transform_scale is not None:
            self.transform.setScale(self.transform_scale)

    def getMesh(self):
        if self.shape == "circle":
            return Qt3DExtras.QSphereMesh()
        elif self.shape == "cuboid":
            return Qt3DExtras.QCuboidMesh()
        elif self.shape == "cylinder":
            return Qt3DExtras.QCylinderMesh()
        elif self.shape == "plane":
            return Qt3DExtras.QPlaneMesh()
        elif self.shape == "cone":
            return Qt3DExtras.QConeMesh()
    
    def addCone(self, top_radius, bottom_radius, length):
        #mesh = Qt3DExtras.QConeMesh()
        self.mesh.setTopRadius(top_radius)
        self.mesh.setBottomRadius(bottom_radius)
        self.mesh.setLength(length)

    def addCylinder(self, length:int=None, radius:int = None, n_rings = None, slices = None):
       #mesh  = Qt3DExtras.QCylinderGeometry()
        self.mesh.setLength(length)
        self.mesh.setRadius(radius)
        if n_rings is not None:
            self.mesh.setRings(n_rings)
        if slices is not None:
            self.mesh.setSlices(slices)
    
    def addPlane(self, height=None, width= None):
        #mesh = Qt3DExtras.QPlaneMesh()
        self.mesh.setHeight(height)
        self.mesh.setWidth(width)
    
    def addLine(self):
        pass

    def addCuboid(self, xExtent, yExtent, zExtent):
        # mesh = Qt3DExtras.QCuboidMesh()
        self.mesh.setXExtent(xExtent)
        self.mesh.setYExtent(yExtent)
        self.mesh.setZExtent(zExtent)

class VizWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        PERSPECTIVE_PROJECTION_VALUES = (45.0, 16.0 / 9.0, 0.1, 1000.0)
        self.central_widget  = QWidget()
        self.setCentralWidget(self.central_widget)

        self.central_widget_layout = QVBoxLayout()
        self.central_widget.setLayout(self.central_widget_layout)

        self.view = Qt3DExtras.Qt3DWindow()
        self.view.defaultFrameGraph().setClearColor(QColor(Qt.white))
        self.root_entity = self.getRootEntity()
        self.view.setRootEntity(self.root_entity)
        self.win_container = QWidget.createWindowContainer(self.view)
        
        self.container_size = self.view.size()
        self.win_container.setMaximumSize(self.container_size)
        self.win_container.setMinimumSize(self.container_size*0.5)
        self.central_widget_layout.addWidget(self.win_container)
        
        self.camera_pos_layout = QFormLayout()
        self.camera_pos_label = QLabel()
        self.camera_pos_layout.addRow("camera position", self.camera_pos_label)
        self.central_widget_layout.addLayout(self.camera_pos_layout)

        self.entityWidgets= QListWidget()
        self.central_widget_layout.addWidget(self.entityWidgets)

    def handlePickerClickEvent(self):
        pass

    def getRootEntity(self):
        self.rootEntity = Qt3DCore.QEntity()
        # setUpBasicShape
        self.cylinder = BasicShape(self.rootEntity,self, "cylinder",
                                   angle_transform=(20, 20, 20),
                                   shininess=0
                                   )
        self.cylinder.addCylinder(5, 1)
        self.cone = BasicShape(self.rootEntity,self, "cone",
                                   angle_transform=(20, 20, 20),
                                   translation_transforms=QVector3D(4,3,2),
                                   shininess=0
                                   )
        # # self.cylinder.addCuboid(1, 3, 4)
        self.cone.addCone(0.5, 1, 2)
        self.setupCamera(self.rootEntity)
        return self.rootEntity
    
    def setupCamera(self,rootEntity):
        # camera
        self.camera = self.view.camera()
        self.camera.setViewCenter(QVector3D(0, 0, 0))
        self.camera.setPosition(QVector3D(0, 0, 10))
        self.camera.lens().setPerspectiveProjection(45.0, 16.0 / 9.0, 0.1, 1000.0)
        self.camera.positionChanged.connect(self.updateCameraPosLabel)
        # camera controller
        self.camera_controller = Qt3DExtras.QOrbitCameraController(rootEntity)
        self.camera_controller.setLinearSpeed(40)
        self.camera_controller.setLookSpeed(40)
        self.camera_controller.setCamera(self.camera)
        
    def updateCameraPosLabel(self):
        camera_position = self.camera.position().toTuple()
        x = camera_position[0]
        y = camera_position[1]
        z = camera_position[2]
        self.camera_pos_label.clear()
        self.camera_pos_label.setText(f"x:{x :.2f} y: {y:.2f} z: {z:.2f}")

if __name__ == "__main__":
    app = QApplication()
    win = VizWindow()
    win.show()
    sys.exit(app.exec())
