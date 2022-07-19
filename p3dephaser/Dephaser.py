from PySide6.QtWidgets import QApplication
from .MainWidget import MainWidget
import sys

class Dephaser(object):

    def __init__(self):
        self.app = QApplication(sys.argv)

    def run(self):
        self.main = MainWidget(self)
        self.main.resize(1200, 400)
        self.main.show()
        self.app.exec()
