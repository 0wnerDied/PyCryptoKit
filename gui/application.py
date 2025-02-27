from PySide6.QtWidgets import QApplication
import sys
from .main_window import MainWindow


class Application:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.window = MainWindow()

    def run(self):
        self.window.show()
        return self.app.exec()
