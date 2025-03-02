from PySide6.QtWidgets import (
    QMainWindow,
    QTabWidget,
    QScrollArea,
    QWidget,
    QVBoxLayout,
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve

from .views.hash_view import HashView
from .views.symmetric_view import SymmetricView

# from .views.asymmetric_view import AsymmetricView
from .views.signature_view import SignatureView


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyCryptoKit")
        self.setMinimumSize(1280, 720)

        # 初始设置窗口透明度为0（完全透明）
        self.setWindowOpacity(0.0)

        self.setup_ui()
        self.apply_styles()

        # 添加淡入动画
        self.fade_in_animation()

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

        # 创建主容器，用于应用圆角
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
        self.symmetric_view = self.create_scrollable_view(SymmetricView())

        self.tabs.addTab(self.hash_view, "哈希计算")
        self.tabs.addTab(self.symmetric_view, "对称加密")
        # self.tabs.addTab(self.asymmetric_view, "非对称加密")
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
        应用样式表，实现圆角效果，同时保持暗黑模式兼容性
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
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.about(
            self,
            "关于 PyCryptoKit",
            "PyCryptoKit - 加密工具箱\n\n"
            "一个用于加密、解密、哈希计算和数字签名的工具",
        )

    def fade_in_animation(self):
        """窗口淡入动画效果"""
        # 创建属性动画
        self.fade_in = QPropertyAnimation(self, b"windowOpacity")
        self.fade_in.setDuration(800)  # 动画持续800毫秒
        self.fade_in.setStartValue(0.0)  # 开始时完全透明
        self.fade_in.setEndValue(1.0)  # 结束时完全不透明
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)  # 使用缓出三次方曲线
        self.fade_in.start()  # 开始动画

    def closeEvent(self, event):
        """窗口关闭时的淡出动画"""
        # 如果已经在执行关闭动画，则允许默认关闭行为
        if hasattr(self, "_closing") and self._closing:
            event.accept()
            return

        # 阻止默认的关闭行为
        event.ignore()
        self._closing = True

        # 创建淡出动画
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(500)  # 动画持续500毫秒
        self.fade_out.setStartValue(1.0)  # 开始时完全不透明
        self.fade_out.setEndValue(0.0)  # 结束时完全透明
        self.fade_out.setEasingCurve(QEasingCurve.Type.InCubic)  # 使用缓入三次方曲线

        # 当动画完成时，真正关闭窗口
        self.fade_out.finished.connect(self._force_close)

        # 开始动画
        self.fade_out.start()

    def _force_close(self):
        """强制关闭窗口"""
        # 设置属性确保窗口被删除
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        # 调用原生close方法，确保正常的关闭流程
        super().close()
