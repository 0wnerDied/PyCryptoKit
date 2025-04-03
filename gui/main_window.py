from PySide6.QtWidgets import (
    QMainWindow,
    QTabWidget,
    QScrollArea,
    QWidget,
    QVBoxLayout,
    QDialog,
    QTextBrowser,
    QPushButton,
    QHBoxLayout,
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices

from .views import HashView, SymmetricView, AsymmetricView, SignatureView


class AboutDialog(QDialog):
    """关于对话框，显示详细的项目信息"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于 PyCryptoKit")
        self.setMinimumSize(600, 400)

        layout = QVBoxLayout(self)

        # 创建文本浏览器显示详细信息
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)

        about_text = """
        <h2>PyCryptoKit - 密码学图形工具箱</h2>
        <p>版本: 1.0.0</p>
        <p>PyCryptoKit 是一个基于 Python 开发的密码学图形工具箱，为用户提供直观的图形界面来执行各种密码学操作。本工具箱集成了常见的加密、解密、哈希计算和数字签名等功能，适用于教学演示、安全研究和日常加密需求。</p>
        
        <h3>主要功能:</h3>
        <ul>
            <li><b>哈希计算</b>: MD5、SHA系列、SHA3系列、BLAKE系列、SM3 等</li>
            <li><b>对称加密</b>: AES、ChaCha20、Salsa20、SM4 等算法</li>
            <li><b>非对称加密</b>: RSA、ECC、ElGamal、Edwards 等公钥密码系统</li>
            <li><b>数字签名</b>: RSA 签名、ECDSA 签名、EdDSA 签名等</li>
        </ul>
        
        <p>本项目为中国民航大学 2023 级信息安全专业密码学课程设计</p>
        <p>作者: <a href="https://github.com/0wnerDied">0wnerDied</a></p>
        
        <h3>技术栈:</h3>
        <ul>
            <li>Python 3.10+</li>
            <li>PySide6 (Qt for Python)</li>
            <li>cryptography</li>
            <li>pycryptodome</li>
        </ul>
        
        <p>本项目采用 MIT 许可证。</p>
        """

        text_browser.setHtml(about_text)
        layout.addWidget(text_browser)

        # 添加按钮
        button_layout = QHBoxLayout()
        github_button = QPushButton("访问作者 GitHub")
        github_button.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://github.com/0wnerDied"))
        )

        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)

        button_layout.addWidget(github_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyCryptoKit")
        self.setMinimumSize(1280, 720)
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        # 创建菜单栏
        menubar = self.menuBar()
        file_menu = menubar.addMenu("文件")

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # 添加"关于"菜单
        about_menu = menubar.addMenu("关于")
        about_action = QAction("关于 PyCryptoKit", self)
        about_action.triggered.connect(self.show_about)
        about_menu.addAction(about_action)

        # 创建主容器, 用于应用圆角
        main_container = QWidget()
        main_layout = QVBoxLayout(main_container)
        main_layout.setContentsMargins(10, 10, 10, 10)
        self.setCentralWidget(main_container)

        # 创建标签页
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 添加功能页面并使其可滚动
        self.hash_view = self.create_scrollable_view(HashView())
        self.signature_view = self.create_scrollable_view(SignatureView())
        self.asymmetric_view = self.create_scrollable_view(AsymmetricView())
        self.symmetric_view = self.create_scrollable_view(SymmetricView())

        self.tabs.addTab(self.hash_view, "哈希计算")
        self.tabs.addTab(self.symmetric_view, "对称加密")
        self.tabs.addTab(self.asymmetric_view, "密钥生成")
        self.tabs.addTab(self.signature_view, "数字签名")

        # 状态栏
        self.statusBar().showMessage("就绪")

    def create_scrollable_view(self, view):
        """
        将视图包装在滚动区域中
        """
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)  # 允许小部件调整大小
        scroll.setWidget(view)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        return scroll

    def apply_styles(self):
        """
        应用样式表, 实现圆角效果, 同时保持暗黑模式兼容性
        """
        self.setStyleSheet(
            """
            QTabWidget::pane {
                border: 1px solid palette(mid);
                border-radius: 8px;
            }
            
            QTabWidget::tab-bar {
                alignment: center;
            }
            
            QTabBar::tab {
                border: 1px solid palette(mid);
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                border-bottom: 2px solid palette(highlight);
            }
            
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            
            /* 垂直滚动条样式 */
            QScrollBar:vertical {
                background: palette(base);
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:vertical {
                background: palette(mid);
                min-height: 20px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:vertical:hover {
                background: palette(dark);
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            
            /* 水平滚动条样式 */
            QScrollBar:horizontal {
                background: palette(base);
                height: 12px;
                margin: 0px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:horizontal {
                background: palette(mid);
                min-width: 20px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background: palette(dark);
            }
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
            
            QStatusBar {
                border-top: 1px solid palette(mid);
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
            }
        """
        )

    def show_about(self):
        """显示详细的关于对话框"""
        about_dialog = AboutDialog(self)
        about_dialog.exec()
