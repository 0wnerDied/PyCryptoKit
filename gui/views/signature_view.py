from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QTextEdit,
    QFileDialog,
    QGroupBox,
    QRadioButton,
    QCheckBox,
    QApplication,
    QTabWidget,
    QMessageBox,
)
import os
import base64
import binascii
from typing import Optional

from core.signature import (
    sign,
    list_algorithms as list_signature_algorithms,
    get_algorithm_info as get_signature_algorithm_info
)


class SignatureView(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # 创建标签页
        self.tab_widget = QTabWidget()
        self.sign_tab = QWidget()
        self.verify_tab = QWidget()

        self.setup_sign_tab()
        self.setup_verify_tab()

        self.tab_widget.addTab(self.sign_tab, "签名")
        self.tab_widget.addTab(self.verify_tab, "验证")

        layout.addWidget(self.tab_widget)
        self.setLayout(layout)

    def setup_sign_tab(self):
        layout = QVBoxLayout()

        # 算法选择
        algo_group = QGroupBox("签名算法")
        algo_layout = QVBoxLayout()

        # 获取所有可用算法
        self.algorithms = list_signature_algorithms()

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.sign_algo_combo = QComboBox()

        # 添加所有算法
        for algo in self.algorithms:
            self.sign_algo_combo.addItem(algo)

        # 默认选择 RSA
        if "RSA" in self.algorithms:
            index = self.sign_algo_combo.findText("RSA")
            if index >= 0:
                self.sign_algo_combo.setCurrentIndex(index)

        self.sign_algo_combo.currentIndexChanged.connect(self.on_sign_algorithm_changed)
        algo_selector.addWidget(self.sign_algo_combo)
        algo_layout.addLayout(algo_selector)

        # 算法信息
        self.sign_algo_info = QLabel()
        self.sign_algo_info.setWordWrap(True)
        algo_layout.addWidget(self.sign_algo_info)

        # 更新算法信息
        self.update_sign_algorithm_info()

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 密钥选择
        key_group = QGroupBox("私钥")
        key_layout = QVBoxLayout()

        # 私钥输入方式选择
        key_type_layout = QHBoxLayout()
        self.key_text_radio = QRadioButton("文本输入")
        self.key_file_radio = QRadioButton("文件输入")
        self.key_text_radio.setChecked(True)
        key_type_layout.addWidget(self.key_text_radio)
        key_type_layout.addWidget(self.key_file_radio)
        key_layout.addLayout(key_type_layout)

        # 私钥文本输入
        self.key_text_widget = QWidget()
        key_text_layout = QVBoxLayout(self.key_text_widget)
        key_text_layout.setContentsMargins(0, 0, 0, 0)

        self.key_input = QTextEdit()
        self.key_input.setPlaceholderText("在此输入PEM格式的私钥")
        key_text_layout.addWidget(self.key_input)

        key_layout.addWidget(self.key_text_widget)

        # 私钥文件输入
        self.key_file_widget = QWidget()
        key_file_layout = QVBoxLayout(self.key_file_widget)
        key_file_layout.setContentsMargins(0, 0, 0, 0)

        key_file_input_layout = QHBoxLayout()
        self.key_file_path = QLineEdit()
        self.key_file_path.setPlaceholderText("选择私钥文件")
        key_file_input_layout.addWidget(self.key_file_path)
        self.key_browse_btn = QPushButton("浏览...")
        self.key_browse_btn.clicked.connect(self.browse_key_file)
        key_file_input_layout.addWidget(self.key_browse_btn)
        key_file_layout.addLayout(key_file_input_layout)

        key_layout.addWidget(self.key_file_widget)

        # 连接单选按钮信号
        self.key_text_radio.toggled.connect(self.toggle_key_input_mode)
        self.key_file_radio.toggled.connect(self.toggle_key_input_mode)

        # 初始状态
        self.key_file_widget.hide()

        # 密钥密码
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("密钥密码:"))
        self.key_password = QLineEdit()
        self.key_password.setPlaceholderText("如果私钥有密码保护，请在此输入")
        self.key_password.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.key_password)
        key_layout.addLayout(password_layout)

        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # 输入选择
        input_group = QGroupBox("待签名数据")
        input_layout = QVBoxLayout()

        # 输入方式选择
        input_type_layout = QHBoxLayout()
        self.text_radio = QRadioButton("文本输入")
        self.file_radio = QRadioButton("文件输入")
        self.text_radio.setChecked(True)
        input_type_layout.addWidget(self.text_radio)
        input_type_layout.addWidget(self.file_radio)
        input_layout.addLayout(input_type_layout)

        # 文本输入相关控件
        self.text_widget = QWidget()
        text_layout = QVBoxLayout(self.text_widget)
        text_layout.setContentsMargins(0, 0, 0, 0)

        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("在此输入要签名的文本")
        text_layout.addWidget(self.text_input)

        # 编码选项
        encoding_layout = QHBoxLayout()
        encoding_layout.addWidget(QLabel("文本编码:"))
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(
            ["UTF-8", "ASCII", "ISO-8859-1", "GBK", "GB18030", "UTF-16"]
        )
        encoding_layout.addWidget(self.encoding_combo)

        # 十六进制输入选项
        self.hex_input_check = QCheckBox("十六进制输入")
        encoding_layout.addWidget(self.hex_input_check)
        text_layout.addLayout(encoding_layout)

        input_layout.addWidget(self.text_widget)

        # 文件输入相关控件
        self.file_widget = QWidget()
        file_layout = QVBoxLayout(self.file_widget)
        file_layout.setContentsMargins(0, 0, 0, 0)

        # 文件选择
        file_input_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("选择要签名的文件")
        self.file_path.textChanged.connect(self.on_file_path_changed)
        file_input_layout.addWidget(self.file_path)
        self.browse_btn = QPushButton("浏览...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_input_layout.addWidget(self.browse_btn)
        file_layout.addLayout(file_input_layout)

        # 文件信息标签
        self.file_info = QLabel()
        self.file_info.setWordWrap(True)
        file_layout.addWidget(self.file_info)

        input_layout.addWidget(self.file_widget)

        # 连接单选按钮信号
        self.text_radio.toggled.connect(self.toggle_input_mode)
        self.file_radio.toggled.connect(self.toggle_input_mode)

        # 初始状态
        self.file_widget.hide()

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 签名按钮
        btn_layout = QHBoxLayout()
        self.sign_btn = QPushButton("生成签名")
        self.sign_btn.clicked.connect(self.generate_signature)
        btn_layout.addWidget(self.sign_btn)

        # 复制按钮
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.clicked.connect(self.copy_result)
        btn_layout.addWidget(self.copy_btn)

        # 保存按钮
        self.save_btn = QPushButton("保存签名")
        self.save_btn.clicked.connect(self.save_signature)
        btn_layout.addWidget(self.save_btn)

        # 清除按钮
        self.clear_btn = QPushButton("清除")
        self.clear_btn.clicked.connect(self.clear_sign_fields)
        btn_layout.addWidget(self.clear_btn)

        layout.addLayout(btn_layout)

        # 结果显示
        result_group = QGroupBox("签名结果")
        result_layout = QVBoxLayout()
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        result_layout.addWidget(self.result)

        # 显示格式选项
        format_layout = QHBoxLayout()

        # 创建互斥的格式选择
        self.format_group = QGroupBox("显示格式")
        format_group_layout = QHBoxLayout()

        self.base64_radio = QRadioButton("Base64 格式")
        self.hex_radio = QRadioButton("十六进制格式")
        self.base64_radio.setChecked(True)  # 默认选择Base64

        # 将单选按钮添加到布局
        format_group_layout.addWidget(self.base64_radio)
        format_group_layout.addWidget(self.hex_radio)

        # 连接信号
        self.base64_radio.toggled.connect(self.update_result_format)
        self.hex_radio.toggled.connect(self.update_result_format)

        self.format_group.setLayout(format_group_layout)
        format_layout.addWidget(self.format_group)

        self.uppercase_check = QCheckBox("大写显示")
        self.uppercase_check.toggled.connect(self.update_result_format)
        format_layout.addWidget(self.uppercase_check)

        result_layout.addLayout(format_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 保存最后生成的签名
        self.last_signature = b""

        self.sign_tab.setLayout(layout)

    def setup_verify_tab(self):
        layout = QVBoxLayout()

        # 算法选择
        algo_group = QGroupBox("签名算法")
        algo_layout = QVBoxLayout()

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.verify_algo_combo = QComboBox()

        # 添加所有算法
        for algo in self.algorithms:
            self.verify_algo_combo.addItem(algo)

        # 默认选择 RSA
        if "RSA" in self.algorithms:
            index = self.verify_algo_combo.findText("RSA")
            if index >= 0:
                self.verify_algo_combo.setCurrentIndex(index)

        self.verify_algo_combo.currentIndexChanged.connect(
            self.on_verify_algorithm_changed
        )
        algo_selector.addWidget(self.verify_algo_combo)
        algo_layout.addLayout(algo_selector)

        # 算法信息
        self.verify_algo_info = QLabel()
        self.verify_algo_info.setWordWrap(True)
        algo_layout.addWidget(self.verify_algo_info)

        # 更新算法信息
        self.update_verify_algorithm_info()

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 公钥选择
        key_group = QGroupBox("公钥")
        key_layout = QVBoxLayout()

        # 公钥输入方式选择
        key_type_layout = QHBoxLayout()
        self.verify_key_text_radio = QRadioButton("文本输入")
        self.verify_key_file_radio = QRadioButton("文件输入")
        self.verify_key_text_radio.setChecked(True)
        key_type_layout.addWidget(self.verify_key_text_radio)
        key_type_layout.addWidget(self.verify_key_file_radio)
        key_layout.addLayout(key_type_layout)

        # 公钥文本输入
        self.verify_key_text_widget = QWidget()
        key_text_layout = QVBoxLayout(self.verify_key_text_widget)
        key_text_layout.setContentsMargins(0, 0, 0, 0)

        self.verify_key_input = QTextEdit()
        self.verify_key_input.setPlaceholderText("在此输入PEM格式的公钥")
        key_text_layout.addWidget(self.verify_key_input)

        key_layout.addWidget(self.verify_key_text_widget)

        # 公钥文件输入
        self.verify_key_file_widget = QWidget()
        key_file_layout = QVBoxLayout(self.verify_key_file_widget)
        key_file_layout.setContentsMargins(0, 0, 0, 0)

        key_file_input_layout = QHBoxLayout()
        self.verify_key_file_path = QLineEdit()
        self.verify_key_file_path.setPlaceholderText("选择公钥文件")
        key_file_input_layout.addWidget(self.verify_key_file_path)
        self.verify_key_browse_btn = QPushButton("浏览...")
        self.verify_key_browse_btn.clicked.connect(self.browse_verify_key_file)
        key_file_input_layout.addWidget(self.verify_key_browse_btn)
        key_file_layout.addLayout(key_file_input_layout)

        key_layout.addWidget(self.verify_key_file_widget)

        # 连接单选按钮信号
        self.verify_key_text_radio.toggled.connect(self.toggle_verify_key_input_mode)
        self.verify_key_file_radio.toggled.connect(self.toggle_verify_key_input_mode)

        # 初始状态
        self.verify_key_file_widget.hide()

        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # 输入选择
        input_group = QGroupBox("待验证数据")
        input_layout = QVBoxLayout()

        # 输入方式选择
        input_type_layout = QHBoxLayout()
        self.verify_text_radio = QRadioButton("文本输入")
        self.verify_file_radio = QRadioButton("文件输入")
        self.verify_text_radio.setChecked(True)
        input_type_layout.addWidget(self.verify_text_radio)
        input_type_layout.addWidget(self.verify_file_radio)
        input_layout.addLayout(input_type_layout)

        # 文本输入相关控件
        self.verify_text_widget = QWidget()
        text_layout = QVBoxLayout(self.verify_text_widget)
        text_layout.setContentsMargins(0, 0, 0, 0)

        self.verify_text_input = QTextEdit()
        self.verify_text_input.setPlaceholderText("在此输入要验证的文本")
        text_layout.addWidget(self.verify_text_input)

        # 编码选项
        encoding_layout = QHBoxLayout()
        encoding_layout.addWidget(QLabel("文本编码:"))
        self.verify_encoding_combo = QComboBox()
        self.verify_encoding_combo.addItems(
            ["UTF-8", "ASCII", "ISO-8859-1", "GBK", "GB18030", "UTF-16"]
        )
        encoding_layout.addWidget(self.verify_encoding_combo)

        # 十六进制输入选项
        self.verify_hex_input_check = QCheckBox("十六进制输入")
        encoding_layout.addWidget(self.verify_hex_input_check)
        text_layout.addLayout(encoding_layout)

        input_layout.addWidget(self.verify_text_widget)

        # 文件输入相关控件
        self.verify_file_widget = QWidget()
        file_layout = QVBoxLayout(self.verify_file_widget)
        file_layout.setContentsMargins(0, 0, 0, 0)

        # 文件选择
        file_input_layout = QHBoxLayout()
        self.verify_file_path = QLineEdit()
        self.verify_file_path.setPlaceholderText("选择要验证的文件")
        self.verify_file_path.textChanged.connect(self.on_verify_file_path_changed)
        file_input_layout.addWidget(self.verify_file_path)
        self.verify_browse_btn = QPushButton("浏览...")
        self.verify_browse_btn.clicked.connect(self.browse_verify_file)
        file_input_layout.addWidget(self.verify_browse_btn)
        file_layout.addLayout(file_input_layout)

        # 文件信息标签
        self.verify_file_info = QLabel()
        self.verify_file_info.setWordWrap(True)
        file_layout.addWidget(self.verify_file_info)

        input_layout.addWidget(self.verify_file_widget)

        # 连接单选按钮信号
        self.verify_text_radio.toggled.connect(self.toggle_verify_input_mode)
        self.verify_file_radio.toggled.connect(self.toggle_verify_input_mode)

        # 初始状态
        self.verify_file_widget.hide()

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 签名输入
        signature_group = QGroupBox("签名")
        signature_layout = QVBoxLayout()

        # 签名输入方式选择
        sig_type_layout = QHBoxLayout()
        self.sig_text_radio = QRadioButton("文本输入")
        self.sig_file_radio = QRadioButton("文件输入")
        self.sig_text_radio.setChecked(True)
        sig_type_layout.addWidget(self.sig_text_radio)
        sig_type_layout.addWidget(self.sig_file_radio)
        signature_layout.addLayout(sig_type_layout)

        # 签名文本输入
        self.sig_text_widget = QWidget()
        sig_text_layout = QVBoxLayout(self.sig_text_widget)
        sig_text_layout.setContentsMargins(0, 0, 0, 0)

        self.sig_input = QTextEdit()
        self.sig_input.setPlaceholderText("在此输入签名（Base64 或十六进制格式）")
        sig_text_layout.addWidget(self.sig_input)

        # 签名格式选项
        sig_format_layout = QHBoxLayout()
        self.sig_base64_radio = QRadioButton("Base64 格式")
        self.sig_hex_radio = QRadioButton("十六进制格式")
        self.sig_base64_radio.setChecked(True)
        sig_format_layout.addWidget(self.sig_base64_radio)
        sig_format_layout.addWidget(self.sig_hex_radio)
        sig_text_layout.addLayout(sig_format_layout)

        signature_layout.addWidget(self.sig_text_widget)

        # 签名文件输入
        self.sig_file_widget = QWidget()
        sig_file_layout = QVBoxLayout(self.sig_file_widget)
        sig_file_layout.setContentsMargins(0, 0, 0, 0)

        # 签名文件选择
        sig_file_input_layout = QHBoxLayout()
        self.sig_file_path = QLineEdit()
        self.sig_file_path.setPlaceholderText("选择签名文件")
        sig_file_input_layout.addWidget(self.sig_file_path)
        self.sig_browse_btn = QPushButton("浏览...")
        self.sig_browse_btn.clicked.connect(self.browse_sig_file)
        sig_file_input_layout.addWidget(self.sig_browse_btn)
        sig_file_layout.addLayout(sig_file_input_layout)

        signature_layout.addWidget(self.sig_file_widget)

        # 连接单选按钮信号
        self.sig_text_radio.toggled.connect(self.toggle_sig_input_mode)
        self.sig_file_radio.toggled.connect(self.toggle_sig_input_mode)

        # 初始状态
        self.sig_file_widget.hide()

        signature_group.setLayout(signature_layout)
        layout.addWidget(signature_group)

        # 验证按钮
        btn_layout = QHBoxLayout()
        self.verify_btn = QPushButton("验证签名")
        self.verify_btn.clicked.connect(self.verify_signature)
        btn_layout.addWidget(self.verify_btn)

        # 清除按钮
        self.verify_clear_btn = QPushButton("清除")
        self.verify_clear_btn.clicked.connect(self.clear_verify_fields)
        btn_layout.addWidget(self.verify_clear_btn)

        layout.addLayout(btn_layout)

        # 验证结果
        result_group = QGroupBox("验证结果")
        result_layout = QVBoxLayout()
        self.verify_result = QLabel('请点击"验证签名"按钮进行验证')
        self.verify_result.setWordWrap(True)
        result_layout.addWidget(self.verify_result)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        self.verify_tab.setLayout(layout)

    def update_sign_algorithm_info(self):
        """更新签名算法信息"""
        algorithm = self.sign_algo_combo.currentText()
        if algorithm:
            try:
                info = get_signature_algorithm_info(algorithm)
                description = info.get("description", "")
                default_params = info.get("default_params", {})

                params_str = ", ".join([f"{k}: {v}" for k, v in default_params.items()])
                info_text = f"{description}\n默认参数: {params_str}"
                self.sign_algo_info.setText(info_text)
            except Exception as e:
                self.sign_algo_info.setText(f"获取算法信息失败: {str(e)}")

    def update_verify_algorithm_info(self):
        """更新验证算法信息"""
        algorithm = self.verify_algo_combo.currentText()
        if algorithm:
            try:
                info = get_signature_algorithm_info(algorithm)
                description = info.get("description", "")
                default_params = info.get("default_params", {})

                params_str = ", ".join([f"{k}: {v}" for k, v in default_params.items()])
                info_text = f"{description}\n默认参数: {params_str}"
                self.verify_algo_info.setText(info_text)
            except Exception as e:
                self.verify_algo_info.setText(f"获取算法信息失败: {str(e)}")

    def on_sign_algorithm_changed(self, index):
        """签名算法变更处理"""
        self.update_sign_algorithm_info()

    def on_verify_algorithm_changed(self, index):
        """验证算法变更处理"""
        self.update_verify_algorithm_info()

    def toggle_key_input_mode(self, checked):
        """切换私钥输入模式"""
        if self.key_text_radio.isChecked():
            self.key_text_widget.show()
            self.key_file_widget.hide()
        else:
            self.key_text_widget.hide()
            self.key_file_widget.show()

    def toggle_verify_key_input_mode(self, checked):
        """切换公钥输入模式"""
        if self.verify_key_text_radio.isChecked():
            self.verify_key_text_widget.show()
            self.verify_key_file_widget.hide()
        else:
            self.verify_key_text_widget.hide()
            self.verify_key_file_widget.show()

    def toggle_input_mode(self, checked):
        """切换签名数据输入模式"""
        if self.text_radio.isChecked():
            self.text_widget.show()
            self.file_widget.hide()
        else:
            self.text_widget.hide()
            self.file_widget.show()

    def toggle_verify_input_mode(self, checked):
        """切换验证数据输入模式"""
        if self.verify_text_radio.isChecked():
            self.verify_text_widget.show()
            self.verify_file_widget.hide()
        else:
            self.verify_text_widget.hide()
            self.verify_file_widget.show()

    def toggle_sig_input_mode(self, checked):
        """切换签名输入模式"""
        if self.sig_text_radio.isChecked():
            self.sig_text_widget.show()
            self.sig_file_widget.hide()
        else:
            self.sig_text_widget.hide()
            self.sig_file_widget.show()

    def browse_key_file(self):
        """浏览私钥文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择私钥文件",
            "",
            "所有文件 (*.*);; PEM 文件 (*.pem);; Key 文件 (*.key)",
        )
        if file_path:
            self.key_file_path.setText(file_path)

    def browse_verify_key_file(self):
        """浏览公钥文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择公钥文件",
            "",
            "所有文件 (*.*);; PEM 文件 (*.pem);; Key 文件 (*.key)",
        )
        if file_path:
            self.verify_key_file_path.setText(file_path)

    def browse_file(self):
        """浏览要签名的文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择要签名的文件", "", "所有文件 (*.*)"
        )
        if file_path:
            self.file_path.setText(file_path)

    def browse_verify_file(self):
        """浏览要验证的文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择要验证的文件", "", "所有文件 (*.*)"
        )
        if file_path:
            self.verify_file_path.setText(file_path)

    def browse_sig_file(self):
        """浏览签名文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择签名文件", "", "所有文件 (*.*);; 签名文件 (*.sig)"
        )
        if file_path:
            self.sig_file_path.setText(file_path)

    def on_file_path_changed(self):
        """文件路径变更处理"""
        file_path = self.file_path.text()
        if os.path.exists(file_path):
            try:
                size = os.path.getsize(file_path)
                size_str = self.format_file_size(size)
                self.file_info.setText(f"文件大小: {size_str}")
            except Exception as e:
                self.file_info.setText(f"获取文件信息失败: {str(e)}")
        else:
            self.file_info.setText("文件不存在")

    def on_verify_file_path_changed(self):
        """验证文件路径变更处理"""
        file_path = self.verify_file_path.text()
        if os.path.exists(file_path):
            try:
                size = os.path.getsize(file_path)
                size_str = self.format_file_size(size)
                self.verify_file_info.setText(f"文件大小: {size_str}")
            except Exception as e:
                self.verify_file_info.setText(f"获取文件信息失败: {str(e)}")
        else:
            self.verify_file_info.setText("文件不存在")

    def format_file_size(self, size_bytes):
        """格式化文件大小显示"""
        if size_bytes < 1024:
            return f"{size_bytes} 字节"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def get_key_data(self) -> Optional[bytes]:
        """获取私钥数据"""
        try:
            if self.key_text_radio.isChecked():
                # 从文本框获取私钥
                key_data = self.key_input.toPlainText().encode("utf-8")
            else:
                # 从文件获取私钥
                key_path = self.key_file_path.text()
                if not os.path.exists(key_path):
                    QMessageBox.warning(self, "错误", "私钥文件不存在")
                    return None

                with open(key_path, "rb") as f:
                    key_data = f.read()

            return key_data
        except Exception as e:
            QMessageBox.warning(self, "错误", f"读取私钥失败: {str(e)}")
            return None

    def get_verify_key_data(self) -> Optional[bytes]:
        """获取公钥数据"""
        try:
            if self.verify_key_text_radio.isChecked():
                # 从文本框获取公钥
                key_data = self.verify_key_input.toPlainText().encode("utf-8")
            else:
                # 从文件获取公钥
                key_path = self.verify_key_file_path.text()
                if not os.path.exists(key_path):
                    QMessageBox.warning(self, "错误", "公钥文件不存在")
                    return None

                with open(key_path, "rb") as f:
                    key_data = f.read()

            return key_data
        except Exception as e:
            QMessageBox.warning(self, "错误", f"读取公钥失败: {str(e)}")
            return None

    def get_input_data(self) -> Optional[bytes]:
        """获取待签名数据"""
        try:
            if self.text_radio.isChecked():
                # 从文本框获取数据
                text = self.text_input.toPlainText()

                if self.hex_input_check.isChecked():
                    # 十六进制输入
                    try:
                        data = bytes.fromhex(text)
                    except ValueError:
                        QMessageBox.warning(self, "错误", "十六进制格式不正确")
                        return None
                else:
                    # 文本输入
                    encoding = self.encoding_combo.currentText()
                    data = text.encode(encoding)
            else:
                # 从文件获取数据
                file_path = self.file_path.text()
                if not os.path.exists(file_path):
                    QMessageBox.warning(self, "错误", "文件不存在")
                    return None

                with open(file_path, "rb") as f:
                    data = f.read()

            return data
        except Exception as e:
            QMessageBox.warning(self, "错误", f"读取数据失败: {str(e)}")
            return None

    def get_verify_input_data(self) -> Optional[bytes]:
        """获取待验证数据"""
        try:
            if self.verify_text_radio.isChecked():
                # 从文本框获取数据
                text = self.verify_text_input.toPlainText()

                if self.verify_hex_input_check.isChecked():
                    # 十六进制输入
                    try:
                        data = bytes.fromhex(text)
                    except ValueError:
                        QMessageBox.warning(self, "错误", "十六进制格式不正确")
                        return None
                else:
                    # 文本输入
                    encoding = self.verify_encoding_combo.currentText()
                    data = text.encode(encoding)
            else:
                # 从文件获取数据
                file_path = self.verify_file_path.text()
                if not os.path.exists(file_path):
                    QMessageBox.warning(self, "错误", "文件不存在")
                    return None

                with open(file_path, "rb") as f:
                    data = f.read()

            return data
        except Exception as e:
            QMessageBox.warning(self, "错误", f"读取数据失败: {str(e)}")
            return None

    def get_signature_data(self) -> Optional[bytes]:
        """获取签名数据"""
        try:
            if self.sig_text_radio.isChecked():
                # 从文本框获取签名
                sig_text = self.sig_input.toPlainText()

                if self.sig_base64_radio.isChecked():
                    # Base64 格式
                    try:
                        data = base64.b64decode(sig_text)
                    except binascii.Error:
                        QMessageBox.warning(self, "错误", "Base64 格式不正确")
                        return None
                else:
                    # 十六进制格式
                    try:
                        data = bytes.fromhex(sig_text)
                    except ValueError:
                        QMessageBox.warning(self, "错误", "十六进制格式不正确")
                        return None
            else:
                # 从文件获取签名
                file_path = self.sig_file_path.text()
                if not os.path.exists(file_path):
                    QMessageBox.warning(self, "错误", "签名文件不存在")
                    return None

                with open(file_path, "rb") as f:
                    data = f.read()

            return data
        except Exception as e:
            QMessageBox.warning(self, "错误", f"读取签名失败: {str(e)}")
            return None

    def generate_signature(self):
        """生成签名"""
        # 获取算法
        algorithm = self.sign_algo_combo.currentText()
        if not algorithm:
            QMessageBox.warning(self, "错误", "请选择签名算法")
            return

        # 获取私钥
        key_data = self.get_key_data()
        if key_data is None:
            return

        # 检查私钥是否为空
        if not key_data or len(key_data.strip()) == 0:
            QMessageBox.warning(self, "错误", "请填充或选择正确私钥文件")
            return

        # 获取密钥密码
        password = self.key_password.text()
        if password:
            password = password.encode("utf-8")
        else:
            password = None

        # 获取待签名数据
        data = self.get_input_data()
        if data is None:
            return

        try:
            # 执行签名操作
            signature = sign(
                data=data, key=key_data, algorithm=algorithm, password=password
            )

            # 保存签名
            self.last_signature = signature

            # 更新显示
            self.update_result_format()

        except Exception as e:
            error_msg = str(e)

            # 检查是否是私钥相关错误
            if (
                "Could not deserialize key data" in error_msg
                or "unsupported" in error_msg.lower()
                or "private key" in error_msg.lower()
                or "密钥格式" in error_msg
                or "密码不正确" in error_msg
            ):
                QMessageBox.critical(self, "签名失败", "请填充或选择正确私钥文件")
            else:
                QMessageBox.critical(
                    self, "签名失败", f"生成签名时发生错误: {error_msg}"
                )

    def update_result_format(self):
        """更新结果显示格式"""
        if not self.last_signature:
            return

        try:
            if self.base64_radio.isChecked():
                # Base64 格式
                result = base64.b64encode(self.last_signature).decode("ascii")
            elif self.hex_radio.isChecked():
                # 十六进制格式
                result = self.last_signature.hex()
                if self.uppercase_check.isChecked():
                    result = result.upper()
            else:
                # 默认使用 Base64
                result = base64.b64encode(self.last_signature).decode("ascii")

            self.result.setText(result)
        except Exception as e:
            self.result.setText(f"格式转换错误: {str(e)}")

    def copy_result(self):
        """复制结果到剪贴板"""
        result = self.result.toPlainText()
        if result:
            clipboard = QApplication.clipboard()
            clipboard.setText(result)
            QMessageBox.information(self, "复制成功", "签名结果已复制到剪贴板")
        else:
            QMessageBox.warning(self, "复制失败", "没有可复制的签名结果")

    def save_signature(self):
        """保存签名到文件"""
        if not self.last_signature:
            QMessageBox.warning(self, "保存失败", "没有可保存的签名结果")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存签名", "", "签名文件 (*.sig);;所有文件 (*.*)"
        )

        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.last_signature)
                QMessageBox.information(self, "保存成功", f"签名已保存到 {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "保存失败", f"保存签名时发生错误: {str(e)}")

    def clear_sign_fields(self):
        """清除签名相关字段"""
        self.text_input.clear()
        self.file_path.clear()
        self.key_input.clear()
        self.key_file_path.clear()
        self.key_password.clear()
        self.result.clear()
        self.last_signature = b""
        self.file_info.clear()
        self.base64_radio.setChecked(True)

    def verify_signature(self):
        """验证签名"""
        # 获取算法
        algorithm = self.verify_algo_combo.currentText()
        if not algorithm:
            QMessageBox.warning(self, "错误", "请选择签名算法")
            return

        # 获取公钥
        key_data = self.get_verify_key_data()
        if key_data is None:
            return

        # 获取待验证数据
        data = self.get_verify_input_data()
        if data is None:
            return

        # 获取签名
        signature = self.get_signature_data()
        if signature is None:
            return

        try:
            # 导入验证签名函数
            from core.signature import verify_signature

            # 验证签名
            result = verify_signature(
                data=data, signature=signature, key=key_data, algorithm=algorithm
            )

            if result:
                self.verify_result.setText("✅ 签名验证成功！数据完整性和来源已确认。")
                self.verify_result.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.verify_result.setText(
                    "❌ 签名验证失败！数据可能已被篡改或签名无效。"
                )
                self.verify_result.setStyleSheet("color: red; font-weight: bold;")

        except Exception as e:
            self.verify_result.setText(f"❌ 验证过程出错: {str(e)}")
            self.verify_result.setStyleSheet("color: red;")

    def clear_verify_fields(self):
        """清除验证相关字段"""
        self.verify_text_input.clear()
        self.verify_file_path.clear()
        self.verify_key_input.clear()
        self.verify_key_file_path.clear()
        self.sig_input.clear()
        self.sig_file_path.clear()
        self.verify_result.setText('请点击"验证签名"按钮进行验证')
        self.verify_result.setStyleSheet("")
        self.verify_file_info.clear()
