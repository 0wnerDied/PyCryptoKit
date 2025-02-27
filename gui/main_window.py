from PySide6.QtWidgets import QMainWindow, QTabWidget
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import Qt
from .views.hash_view import HashView

# from .views.symmetric_view import SymmetricView
# from .views.asymmetric_view import AsymmetricView
from .views.signature_view import SignatureView


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyCryptoKit")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def setup_ui(self):
        # 创建菜单栏
        menubar = self.menuBar()
        file_menu = menubar.addMenu("文件")

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menubar.addMenu("帮助")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        # 创建标签页
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # 添加功能页面
        self.hash_view = HashView()
        # self.symmetric_view = SymmetricView()
        # self.asymmetric_view = AsymmetricView()
        self.signature_view = SignatureView()

        self.tabs.addTab(self.hash_view, "哈希计算")
        # self.tabs.addTab(self.symmetric_view, "对称加密")
        # self.tabs.addTab(self.asymmetric_view, "非对称加密")
        self.tabs.addTab(self.signature_view, "数字签名")

        # 状态栏
        self.statusBar().showMessage("就绪")

    def show_about(self):
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.about(
            self,
            "关于 PyCryptoKit",
            "PyCryptoKit - 加密工具箱\n\n"
            "一个用于加密、解密、哈希计算和数字签名的工具",
        )
