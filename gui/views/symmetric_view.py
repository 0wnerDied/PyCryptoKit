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

from core import (
    encrypt,
    decrypt,
    encrypt_to_base64,
    decrypt_from_base64,
    SymmetricAlgorithm,
    Mode,
    Padding,
)


class SymmetricView(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # 创建选项卡
        self.tabs = QTabWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        self.tabs.addTab(self.encrypt_tab, "加密")
        self.tabs.addTab(self.decrypt_tab, "解密")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def setup_encrypt_tab(self):
        layout = QVBoxLayout()

        # 算法选择
        algo_group = QGroupBox("加密算法")
        algo_layout = QVBoxLayout()

        # 获取所有可用算法
        self.algorithms = [algo.value for algo in SymmetricAlgorithm]

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.algo_combo = QComboBox()

        # 添加所有算法
        for algo in self.algorithms:
            self.algo_combo.addItem(algo)

        # 默认选择 AES
        if "AES" in self.algorithms:
            index = self.algo_combo.findText("AES")
            if index >= 0:
                self.algo_combo.setCurrentIndex(index)

        self.algo_combo.currentIndexChanged.connect(self.on_algorithm_changed)
        algo_selector.addWidget(self.algo_combo)
        algo_layout.addLayout(algo_selector)

        # 加密模式选择（仅对块密码有效）
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("加密模式:"))
        self.mode_combo = QComboBox()
        # 为SM4移除GCM模式
        self.all_modes = [mode.value for mode in Mode]
        self.mode_combo.addItems(self.all_modes)
        mode_layout.addWidget(self.mode_combo)
        algo_layout.addLayout(mode_layout)

        # 填充方式选择（仅对块密码有效）
        padding_layout = QHBoxLayout()
        padding_layout.addWidget(QLabel("填充方式:"))
        self.padding_combo = QComboBox()
        self.padding_combo.addItems([padding.value for padding in Padding])
        padding_layout.addWidget(self.padding_combo)
        algo_layout.addLayout(padding_layout)

        # 密钥大小选择（仅对AES有效）
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("密钥长度:"))
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["128", "192", "256"])
        self.key_size_combo.setCurrentText("256")  # 默认256位
        key_size_layout.addWidget(self.key_size_combo)
        algo_layout.addLayout(key_size_layout)

        # 连接算法变更事件
        self.algo_combo.currentIndexChanged.connect(self.update_algorithm_options)
        self.mode_combo.currentIndexChanged.connect(self.update_mode_options)

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 密钥和IV输入
        key_group = QGroupBox("密钥和初始向量")
        key_layout = QVBoxLayout()

        # 密钥输入
        key_input_layout = QHBoxLayout()
        key_input_layout.addWidget(QLabel("密钥:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("输入加密密钥")
        key_input_layout.addWidget(self.key_input)

        # 生成随机密钥按钮
        self.gen_key_btn = QPushButton("生成随机密钥")
        self.gen_key_btn.clicked.connect(self.generate_random_key)
        key_input_layout.addWidget(self.gen_key_btn)

        key_layout.addLayout(key_input_layout)

        # 密钥格式选项
        key_format_layout = QHBoxLayout()
        self.key_hex_check = QCheckBox("十六进制密钥")
        key_format_layout.addWidget(self.key_hex_check)
        self.key_b64_check = QCheckBox("Base64密钥")
        key_format_layout.addWidget(self.key_b64_check)

        # 默认选择十六进制
        self.key_hex_check.setChecked(True)
        self.key_hex_check.toggled.connect(
            lambda checked: self.handle_key_format_change(self.key_hex_check)
        )
        self.key_b64_check.toggled.connect(
            lambda checked: self.handle_key_format_change(self.key_b64_check)
        )

        key_layout.addLayout(key_format_layout)

        # IV输入
        iv_input_layout = QHBoxLayout()
        iv_input_layout.addWidget(QLabel("初始向量(IV):"))
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText("输入初始向量 (某些模式需要)")
        iv_input_layout.addWidget(self.iv_input)

        # 生成随机IV按钮
        self.gen_iv_btn = QPushButton("生成随机IV")
        self.gen_iv_btn.clicked.connect(self.generate_random_iv)
        iv_input_layout.addWidget(self.gen_iv_btn)

        key_layout.addLayout(iv_input_layout)

        # IV格式选项
        iv_format_layout = QHBoxLayout()
        self.iv_hex_check = QCheckBox("十六进制IV")
        iv_format_layout.addWidget(self.iv_hex_check)
        self.iv_b64_check = QCheckBox("Base64 IV")
        iv_format_layout.addWidget(self.iv_b64_check)

        # 默认选择十六进制
        self.iv_hex_check.setChecked(True)
        self.iv_hex_check.toggled.connect(
            lambda checked: self.handle_iv_format_change(self.iv_hex_check)
        )
        self.iv_b64_check.toggled.connect(
            lambda checked: self.handle_iv_format_change(self.iv_b64_check)
        )

        key_layout.addLayout(iv_format_layout)

        # 关联数据（仅对GCM模式有效）
        aad_layout = QHBoxLayout()
        aad_layout.addWidget(QLabel("关联数据(AAD):"))
        self.aad_input = QLineEdit()
        self.aad_input.setPlaceholderText("GCM模式关联数据 (可选)")
        aad_layout.addWidget(self.aad_input)
        key_layout.addLayout(aad_layout)

        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # 输入选择
        input_group = QGroupBox("明文输入")
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
        self.text_input.setPlaceholderText("在此输入要加密的文本")
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
        self.file_path.setPlaceholderText("选择要加密的文件")
        file_input_layout.addWidget(self.file_path)
        self.browse_btn = QPushButton("浏览...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_input_layout.addWidget(self.browse_btn)
        file_layout.addLayout(file_input_layout)

        # 文件信息标签
        self.file_info = QLabel()
        self.file_info.setWordWrap(True)
        file_layout.addWidget(self.file_info)

        # 输出文件路径
        output_file_layout = QHBoxLayout()
        output_file_layout.addWidget(QLabel("输出文件:"))
        self.output_file_path = QLineEdit()
        self.output_file_path.setPlaceholderText("加密后的输出文件路径")
        output_file_layout.addWidget(self.output_file_path)
        self.output_browse_btn = QPushButton("浏览...")
        self.output_browse_btn.clicked.connect(self.browse_output_file)
        output_file_layout.addWidget(self.output_browse_btn)
        file_layout.addLayout(output_file_layout)

        input_layout.addWidget(self.file_widget)

        # 连接单选按钮信号
        self.text_radio.toggled.connect(self.toggle_input_mode)
        self.file_radio.toggled.connect(self.toggle_input_mode)

        # 初始状态
        self.file_widget.hide()

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 加密按钮
        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("加密")
        self.encrypt_btn.clicked.connect(self.perform_encryption)
        btn_layout.addWidget(self.encrypt_btn)

        # 复制按钮
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.clicked.connect(self.copy_result)
        btn_layout.addWidget(self.copy_btn)

        # 清除按钮
        self.clear_btn = QPushButton("清除")
        self.clear_btn.clicked.connect(self.clear_fields)
        btn_layout.addWidget(self.clear_btn)

        layout.addLayout(btn_layout)

        # 结果显示
        result_group = QGroupBox("加密结果")
        result_layout = QVBoxLayout()
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        result_layout.addWidget(self.result)

        # 显示格式选项
        format_layout = QHBoxLayout()
        self.base64_output_check = QCheckBox("Base64输出")
        self.base64_output_check.setChecked(True)  # 默认使用Base64输出
        format_layout.addWidget(self.base64_output_check)

        self.hex_output_check = QCheckBox("十六进制输出")
        format_layout.addWidget(self.hex_output_check)

        # 互斥选择
        self.base64_output_check.toggled.connect(
            lambda checked: self.hex_output_check.setChecked(False) if checked else None
        )
        self.hex_output_check.toggled.connect(
            lambda checked: (
                self.base64_output_check.setChecked(False) if checked else None
            )
        )

        result_layout.addLayout(format_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 保存最后计算的结果
        self.last_result = b""

        self.encrypt_tab.setLayout(layout)

        # 初始化算法选项
        self.update_algorithm_options()

    def setup_decrypt_tab(self):
        layout = QVBoxLayout()

        # 算法选择
        algo_group = QGroupBox("解密算法")
        algo_layout = QVBoxLayout()

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.decrypt_algo_combo = QComboBox()

        # 添加所有算法
        for algo in self.algorithms:
            self.decrypt_algo_combo.addItem(algo)

        # 默认选择 AES
        if "AES" in self.algorithms:
            index = self.decrypt_algo_combo.findText("AES")
            if index >= 0:
                self.decrypt_algo_combo.setCurrentIndex(index)

        self.decrypt_algo_combo.currentIndexChanged.connect(
            self.on_decrypt_algorithm_changed
        )
        algo_selector.addWidget(self.decrypt_algo_combo)
        algo_layout.addLayout(algo_selector)

        # 加密模式选择
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("加密模式:"))
        self.decrypt_mode_combo = QComboBox()
        self.decrypt_mode_combo.addItems(self.all_modes)
        self.decrypt_mode_combo.currentIndexChanged.connect(
            self.update_decrypt_mode_options
        )
        mode_layout.addWidget(self.decrypt_mode_combo)
        algo_layout.addLayout(mode_layout)

        # 填充方式选择
        padding_layout = QHBoxLayout()
        padding_layout.addWidget(QLabel("填充方式:"))
        self.decrypt_padding_combo = QComboBox()
        self.decrypt_padding_combo.addItems([padding.value for padding in Padding])
        padding_layout.addWidget(self.decrypt_padding_combo)
        algo_layout.addLayout(padding_layout)

        # 密钥大小选择（仅对AES有效）
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("密钥长度:"))
        self.decrypt_key_size_combo = QComboBox()
        self.decrypt_key_size_combo.addItems(["128", "192", "256"])
        self.decrypt_key_size_combo.setCurrentText("256")  # 默认256位
        key_size_layout.addWidget(self.decrypt_key_size_combo)
        algo_layout.addLayout(key_size_layout)

        # 连接算法变更事件
        self.decrypt_algo_combo.currentIndexChanged.connect(
            self.update_decrypt_algorithm_options
        )

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 密钥和IV输入
        key_group = QGroupBox("密钥和初始向量")
        key_layout = QVBoxLayout()

        # 密钥输入
        key_input_layout = QHBoxLayout()
        key_input_layout.addWidget(QLabel("密钥:"))
        self.decrypt_key_input = QLineEdit()
        self.decrypt_key_input.setPlaceholderText("输入解密密钥")
        key_input_layout.addWidget(self.decrypt_key_input)
        key_layout.addLayout(key_input_layout)

        # 密钥格式选项
        key_format_layout = QHBoxLayout()
        self.decrypt_key_hex_check = QCheckBox("十六进制密钥")
        key_format_layout.addWidget(self.decrypt_key_hex_check)
        self.decrypt_key_b64_check = QCheckBox("Base64密钥")
        key_format_layout.addWidget(self.decrypt_key_b64_check)

        # 默认选择十六进制
        self.decrypt_key_hex_check.setChecked(True)
        self.decrypt_key_hex_check.toggled.connect(
            lambda checked: self.handle_decrypt_key_format_change(
                self.decrypt_key_hex_check
            )
        )
        self.decrypt_key_b64_check.toggled.connect(
            lambda checked: self.handle_decrypt_key_format_change(
                self.decrypt_key_b64_check
            )
        )

        key_layout.addLayout(key_format_layout)

        # IV输入
        iv_input_layout = QHBoxLayout()
        iv_input_layout.addWidget(QLabel("初始向量(IV):"))
        self.decrypt_iv_input = QLineEdit()
        self.decrypt_iv_input.setPlaceholderText("输入初始向量 (某些模式需要)")
        iv_input_layout.addWidget(self.decrypt_iv_input)
        key_layout.addLayout(iv_input_layout)

        # IV格式选项
        iv_format_layout = QHBoxLayout()
        self.decrypt_iv_hex_check = QCheckBox("十六进制IV")
        iv_format_layout.addWidget(self.decrypt_iv_hex_check)
        self.decrypt_iv_b64_check = QCheckBox("Base64 IV")
        iv_format_layout.addWidget(self.decrypt_iv_b64_check)

        # 默认选择十六进制
        self.decrypt_iv_hex_check.setChecked(True)
        self.decrypt_iv_hex_check.toggled.connect(
            lambda checked: self.handle_decrypt_iv_format_change(
                self.decrypt_iv_hex_check
            )
        )
        self.decrypt_iv_b64_check.toggled.connect(
            lambda checked: self.handle_decrypt_iv_format_change(
                self.decrypt_iv_b64_check
            )
        )

        key_layout.addLayout(iv_format_layout)

        # 关联数据（仅对GCM模式有效）
        aad_layout = QHBoxLayout()
        aad_layout.addWidget(QLabel("关联数据(AAD):"))
        self.decrypt_aad_input = QLineEdit()
        self.decrypt_aad_input.setPlaceholderText("GCM模式关联数据 (可选)")
        aad_layout.addWidget(self.decrypt_aad_input)
        key_layout.addLayout(aad_layout)

        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # 输入选择
        input_group = QGroupBox("密文输入")
        input_layout = QVBoxLayout()

        # 输入方式选择
        input_type_layout = QHBoxLayout()
        self.decrypt_text_radio = QRadioButton("文本输入")
        self.decrypt_file_radio = QRadioButton("文件输入")
        self.decrypt_text_radio.setChecked(True)
        input_type_layout.addWidget(self.decrypt_text_radio)
        input_type_layout.addWidget(self.decrypt_file_radio)
        input_layout.addLayout(input_type_layout)

        # 文本输入相关控件
        self.decrypt_text_widget = QWidget()
        text_layout = QVBoxLayout(self.decrypt_text_widget)
        text_layout.setContentsMargins(0, 0, 0, 0)

        self.decrypt_text_input = QTextEdit()
        self.decrypt_text_input.setPlaceholderText("在此输入要解密的密文")
        text_layout.addWidget(self.decrypt_text_input)

        # 输入格式选项
        format_layout = QHBoxLayout()
        self.decrypt_base64_input_check = QCheckBox("Base64输入")
        self.decrypt_base64_input_check.setChecked(True)  # 默认使用Base64输入
        format_layout.addWidget(self.decrypt_base64_input_check)

        self.decrypt_hex_input_check = QCheckBox("十六进制输入")
        format_layout.addWidget(self.decrypt_hex_input_check)

        # 互斥选择
        self.decrypt_base64_input_check.toggled.connect(
            lambda checked: (
                self.decrypt_hex_input_check.setChecked(False) if checked else None
            )
        )
        self.decrypt_hex_input_check.toggled.connect(
            lambda checked: (
                self.decrypt_base64_input_check.setChecked(False) if checked else None
            )
        )

        text_layout.addLayout(format_layout)

        # 输出编码选项
        encoding_layout = QHBoxLayout()
        encoding_layout.addWidget(QLabel("输出文本编码:"))
        self.decrypt_encoding_combo = QComboBox()
        self.decrypt_encoding_combo.addItems(
            ["UTF-8", "ASCII", "ISO-8859-1", "GBK", "GB18030", "UTF-16"]
        )
        encoding_layout.addWidget(self.decrypt_encoding_combo)
        text_layout.addLayout(encoding_layout)

        input_layout.addWidget(self.decrypt_text_widget)

        # 文件输入相关控件
        self.decrypt_file_widget = QWidget()
        file_layout = QVBoxLayout(self.decrypt_file_widget)
        file_layout.setContentsMargins(0, 0, 0, 0)

        # 文件选择
        file_input_layout = QHBoxLayout()
        self.decrypt_file_path = QLineEdit()
        self.decrypt_file_path.setPlaceholderText("选择要解密的文件")
        file_input_layout.addWidget(self.decrypt_file_path)
        self.decrypt_browse_btn = QPushButton("浏览...")
        self.decrypt_browse_btn.clicked.connect(self.browse_decrypt_file)
        file_input_layout.addWidget(self.decrypt_browse_btn)
        file_layout.addLayout(file_input_layout)

        # 文件信息标签
        self.decrypt_file_info = QLabel()
        self.decrypt_file_info.setWordWrap(True)
        file_layout.addWidget(self.decrypt_file_info)

        # 输出文件路径
        output_file_layout = QHBoxLayout()
        output_file_layout.addWidget(QLabel("输出文件:"))
        self.decrypt_output_file_path = QLineEdit()
        self.decrypt_output_file_path.setPlaceholderText("解密后的输出文件路径")
        output_file_layout.addWidget(self.decrypt_output_file_path)
        self.decrypt_output_browse_btn = QPushButton("浏览...")
        self.decrypt_output_browse_btn.clicked.connect(self.browse_decrypt_output_file)
        output_file_layout.addWidget(self.decrypt_output_browse_btn)
        file_layout.addLayout(output_file_layout)

        input_layout.addWidget(self.decrypt_file_widget)

        # 连接单选按钮信号
        self.decrypt_text_radio.toggled.connect(self.toggle_decrypt_input_mode)
        self.decrypt_file_radio.toggled.connect(self.toggle_decrypt_input_mode)

        # 初始状态
        self.decrypt_file_widget.hide()

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 解密按钮
        btn_layout = QHBoxLayout()
        self.decrypt_btn = QPushButton("解密")
        self.decrypt_btn.clicked.connect(self.perform_decryption)
        btn_layout.addWidget(self.decrypt_btn)

        # 复制按钮
        self.decrypt_copy_btn = QPushButton("复制结果")
        self.decrypt_copy_btn.clicked.connect(self.copy_decrypt_result)
        btn_layout.addWidget(self.decrypt_copy_btn)

        # 清除按钮
        self.decrypt_clear_btn = QPushButton("清除")
        self.decrypt_clear_btn.clicked.connect(self.clear_decrypt_fields)
        btn_layout.addWidget(self.decrypt_clear_btn)

        layout.addLayout(btn_layout)

        # 结果显示
        result_group = QGroupBox("解密结果")
        result_layout = QVBoxLayout()
        self.decrypt_result = QTextEdit()
        self.decrypt_result.setReadOnly(True)
        result_layout.addWidget(self.decrypt_result)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 保存最后计算的结果
        self.last_decrypt_result = ""

        self.decrypt_tab.setLayout(layout)

        # 初始化算法选项
        self.update_decrypt_algorithm_options()

    def handle_key_format_change(self, checkbox):
        """处理密钥格式选择的互斥"""
        if checkbox.isChecked():
            if checkbox == self.key_hex_check:
                self.key_b64_check.setChecked(False)
            elif checkbox == self.key_b64_check:
                self.key_hex_check.setChecked(False)
        else:
            # 确保至少有一个选中
            if not (self.key_hex_check.isChecked() or self.key_b64_check.isChecked()):
                checkbox.setChecked(True)

    def handle_iv_format_change(self, checkbox):
        """处理IV格式选择的互斥"""
        if checkbox.isChecked():
            if checkbox == self.iv_hex_check:
                self.iv_b64_check.setChecked(False)
            elif checkbox == self.iv_b64_check:
                self.iv_hex_check.setChecked(False)
        else:
            # 确保至少有一个选中
            if not (self.iv_hex_check.isChecked() or self.iv_b64_check.isChecked()):
                checkbox.setChecked(True)

    def handle_decrypt_key_format_change(self, checkbox):
        """处理解密密钥格式选择的互斥"""
        if checkbox.isChecked():
            if checkbox == self.decrypt_key_hex_check:
                self.decrypt_key_b64_check.setChecked(False)
            elif checkbox == self.decrypt_key_b64_check:
                self.decrypt_key_hex_check.setChecked(False)
        else:
            # 确保至少有一个选中
            if not (
                self.decrypt_key_hex_check.isChecked()
                or self.decrypt_key_b64_check.isChecked()
            ):
                checkbox.setChecked(True)

    def handle_decrypt_iv_format_change(self, checkbox):
        """处理解密IV格式选择的互斥"""
        if checkbox.isChecked():
            if checkbox == self.decrypt_iv_hex_check:
                self.decrypt_iv_b64_check.setChecked(False)
            elif checkbox == self.decrypt_iv_b64_check:
                self.decrypt_iv_hex_check.setChecked(False)
        else:
            # 确保至少有一个选中
            if not (
                self.decrypt_iv_hex_check.isChecked()
                or self.decrypt_iv_b64_check.isChecked()
            ):
                checkbox.setChecked(True)

    def update_algorithm_options(self):
        """根据选择的算法更新UI选项"""
        algorithm = self.algo_combo.currentText()

        # 更新密钥长度选项可用性
        key_size_visible = True  # 始终可见
        key_size_enabled = algorithm == "AES"  # 只有AES时可用

        self.key_size_combo.setVisible(key_size_visible)
        self.key_size_combo.setEnabled(key_size_enabled)

        parent_layout = self.key_size_combo.parentWidget().layout()
        if (
            parent_layout
            and parent_layout.count() > 0
            and parent_layout.itemAt(0).widget()
        ):
            parent_layout.itemAt(0).widget().setVisible(key_size_visible)
            parent_layout.itemAt(0).widget().setEnabled(key_size_enabled)

        # 根据算法设置密钥长度
        if algorithm == "SM4":
            # SM4固定使用128位密钥
            self.key_size_combo.setCurrentText("128")
        elif algorithm in ["ChaCha20", "Salsa20"]:
            # ChaCha20和Salsa20使用256位密钥
            self.key_size_combo.setCurrentText("256")
        # AES保持用户选择的密钥长度

        # 更新模式和填充方式可见性
        is_block_cipher = algorithm in ["AES", "SM4"]
        self.mode_combo.setEnabled(is_block_cipher)
        self.padding_combo.setEnabled(is_block_cipher)

        # 如果是SM4，移除GCM模式
        if algorithm == "SM4":
            # 保存当前选择
            current_mode = self.mode_combo.currentText()
            # 清空并重新添加除GCM外的所有模式
            self.mode_combo.clear()
            for mode in self.all_modes:
                if mode != "GCM":
                    self.mode_combo.addItem(mode)
            # 尝试恢复之前的选择，如果不是GCM的话
            if current_mode != "GCM":
                index = self.mode_combo.findText(current_mode)
                if index >= 0:
                    self.mode_combo.setCurrentIndex(index)
        else:
            # 恢复所有模式
            current_mode = self.mode_combo.currentText()
            self.mode_combo.clear()
            self.mode_combo.addItems(self.all_modes)
            # 尝试恢复之前的选择
            index = self.mode_combo.findText(current_mode)
            if index >= 0:
                self.mode_combo.setCurrentIndex(index)

        # 更新模式相关选项
        self.update_mode_options()

        # 流密码特殊处理
        is_stream_cipher = algorithm in ["ChaCha20", "Salsa20"]
        if is_stream_cipher:
            self.mode_combo.setEnabled(False)
            self.padding_combo.setEnabled(False)
            self.iv_input.setEnabled(True)
            self.gen_iv_btn.setEnabled(True)
            self.iv_hex_check.setEnabled(True)
            self.iv_b64_check.setEnabled(True)

    def update_mode_options(self):
        """根据选择的模式更新UI选项"""
        mode = self.mode_combo.currentText()

        # 更新AAD输入可见性
        is_gcm_mode = mode == "GCM"
        self.aad_input.setEnabled(is_gcm_mode)

        # 更新IV输入可见性
        needs_iv = mode in ["CBC", "CFB", "OFB", "CTR", "GCM"]
        self.iv_input.setEnabled(needs_iv)
        self.gen_iv_btn.setEnabled(needs_iv)
        self.iv_hex_check.setEnabled(needs_iv)
        self.iv_b64_check.setEnabled(needs_iv)

    def update_decrypt_algorithm_options(self):
        """根据选择的解密算法更新UI选项"""
        algorithm = self.decrypt_algo_combo.currentText()

        # 更新密钥长度选项可用性
        key_size_visible = True  # 始终可见
        key_size_enabled = algorithm == "AES"  # 只有AES时可用

        self.decrypt_key_size_combo.setVisible(key_size_visible)
        self.decrypt_key_size_combo.setEnabled(key_size_enabled)

        parent_layout = self.decrypt_key_size_combo.parentWidget().layout()
        if (
            parent_layout
            and parent_layout.count() > 0
            and parent_layout.itemAt(0).widget()
        ):
            parent_layout.itemAt(0).widget().setVisible(key_size_visible)
            parent_layout.itemAt(0).widget().setEnabled(key_size_enabled)

        # 根据算法设置密钥长度
        if algorithm == "SM4":
            # SM4固定使用128位密钥
            self.decrypt_key_size_combo.setCurrentText("128")
        elif algorithm in ["ChaCha20", "Salsa20"]:
            # ChaCha20和Salsa20使用256位密钥
            self.decrypt_key_size_combo.setCurrentText("256")
        # AES保持用户选择的密钥长度

        # 更新模式和填充方式可见性
        is_block_cipher = algorithm in ["AES", "SM4"]
        self.decrypt_mode_combo.setEnabled(is_block_cipher)
        self.decrypt_padding_combo.setEnabled(is_block_cipher)

        # 如果是SM4，移除GCM模式
        if algorithm == "SM4":
            # 保存当前选择
            current_mode = self.decrypt_mode_combo.currentText()
            # 清空并重新添加除GCM外的所有模式
            self.decrypt_mode_combo.clear()
            for mode in self.all_modes:
                if mode != "GCM":
                    self.decrypt_mode_combo.addItem(mode)
            # 尝试恢复之前的选择，如果不是GCM的话
            if current_mode != "GCM":
                index = self.decrypt_mode_combo.findText(current_mode)
                if index >= 0:
                    self.decrypt_mode_combo.setCurrentIndex(index)
        else:
            # 恢复所有模式
            current_mode = self.decrypt_mode_combo.currentText()
            self.decrypt_mode_combo.clear()
            self.decrypt_mode_combo.addItems(self.all_modes)
            # 尝试恢复之前的选择
            index = self.decrypt_mode_combo.findText(current_mode)
            if index >= 0:
                self.decrypt_mode_combo.setCurrentIndex(index)

        # 更新模式相关选项
        self.update_decrypt_mode_options()

        # 流密码特殊处理
        is_stream_cipher = algorithm in ["ChaCha20", "Salsa20"]
        if is_stream_cipher:
            self.decrypt_mode_combo.setEnabled(False)
            self.decrypt_padding_combo.setEnabled(False)
            self.decrypt_iv_input.setEnabled(True)
            self.decrypt_iv_hex_check.setEnabled(True)
            self.decrypt_iv_b64_check.setEnabled(True)

    def update_decrypt_mode_options(self):
        """根据选择的解密模式更新UI选项"""
        mode = self.decrypt_mode_combo.currentText()

        # 更新AAD输入可见性
        is_gcm_mode = mode == "GCM"
        self.decrypt_aad_input.setEnabled(is_gcm_mode)

        # 更新IV输入可见性
        needs_iv = mode in ["CBC", "CFB", "OFB", "CTR", "GCM"]
        self.decrypt_iv_input.setEnabled(needs_iv)
        self.decrypt_iv_hex_check.setEnabled(needs_iv)
        self.decrypt_iv_b64_check.setEnabled(needs_iv)

    def on_algorithm_changed(self, index):
        self.update_algorithm_options()

    def on_decrypt_algorithm_changed(self, index):
        self.update_decrypt_algorithm_options()

    def toggle_input_mode(self):
        text_mode = self.text_radio.isChecked()
        if text_mode:
            self.text_widget.show()
            self.file_widget.hide()
        else:
            self.text_widget.hide()
            self.file_widget.show()

    def toggle_decrypt_input_mode(self):
        text_mode = self.decrypt_text_radio.isChecked()
        if text_mode:
            self.decrypt_text_widget.show()
            self.decrypt_file_widget.hide()
        else:
            self.decrypt_text_widget.hide()
            self.decrypt_file_widget.show()

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if file_path:
            self.file_path.setText(file_path)
            self.update_file_info(file_path, self.file_info)

            # 自动生成输出文件路径
            output_path = file_path + ".enc"
            self.output_file_path.setText(output_path)

    def browse_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "保存加密文件")
        if file_path:
            self.output_file_path.setText(file_path)

    def browse_decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择加密文件")
        if file_path:
            self.decrypt_file_path.setText(file_path)
            self.update_file_info(file_path, self.decrypt_file_info)

            # 自动生成输出文件路径 (去除.enc后缀如果有)
            output_path = file_path
            if output_path.endswith(".enc"):
                output_path = output_path[:-4]
            else:
                output_path += ".dec"
            self.decrypt_output_file_path.setText(output_path)

    def browse_decrypt_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "保存解密文件")
        if file_path:
            self.decrypt_output_file_path.setText(file_path)

    def update_file_info(self, file_path, info_label):
        try:
            # 获取文件状态
            file_stats = os.stat(file_path)
            size_bytes = file_stats.st_size
            size_str = self.format_file_size(size_bytes)
            info_label.setText(
                f"文件名: {os.path.basename(file_path)}\n大小: {size_str}"
            )
        except Exception as e:
            info_label.setText(f"无法获取文件信息: {str(e)}")

    def format_file_size(self, size_bytes):
        """格式化文件大小"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0 or unit == "TB":
                break
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} {unit}"

    def generate_random_key(self):
        """生成随机密钥"""
        try:
            algorithm = self.algo_combo.currentText()

            # 根据不同算法确定密钥长度
            if algorithm == "AES":
                key_size_bits = int(self.key_size_combo.currentText())
                key_size = key_size_bits // 8
            elif algorithm == "SM4":
                key_size = 16
            elif algorithm in ["ChaCha20", "Salsa20"]:
                key_size = 32
            else:
                key_size = 32

            import os

            random_key = os.urandom(key_size)

            # 根据选择的格式显示
            if self.key_hex_check.isChecked():
                self.key_input.setText(random_key.hex())
            elif self.key_b64_check.isChecked():
                self.key_input.setText(base64.b64encode(random_key).decode("ascii"))
            else:
                # 默认使用十六进制
                self.key_input.setText(random_key.hex())
                self.key_hex_check.setChecked(True)
        except Exception as e:
            QMessageBox.warning(self, "错误", f"生成随机密钥失败: {str(e)}")

    def generate_random_iv(self):
        """生成随机IV"""
        try:
            algorithm = self.algo_combo.currentText()
            mode = self.mode_combo.currentText()

            # 确定IV大小
            if algorithm in ["AES", "SM4"]:
                if mode == "GCM":
                    iv_size = 12
                else:
                    iv_size = 16
            elif algorithm == "ChaCha20":
                iv_size = 12
            elif algorithm == "Salsa20":
                iv_size = 8
            else:
                iv_size = 16

            import os

            random_iv = os.urandom(iv_size)

            # 根据选择的格式显示
            if self.iv_hex_check.isChecked():
                self.iv_input.setText(random_iv.hex())
            elif self.iv_b64_check.isChecked():
                self.iv_input.setText(base64.b64encode(random_iv).decode("ascii"))
            else:
                # 默认使用十六进制
                self.iv_input.setText(random_iv.hex())
                self.iv_hex_check.setChecked(True)
        except Exception as e:
            QMessageBox.warning(self, "错误", f"生成随机IV失败: {str(e)}")

    def get_key_bytes(self):
        """获取密钥的字节表示"""
        key_text = self.key_input.text().strip()
        if not key_text:
            raise ValueError("密钥不能为空")

        if self.key_hex_check.isChecked():
            return bytes.fromhex(key_text)
        elif self.key_b64_check.isChecked():
            return base64.b64decode(key_text)
        else:
            # 默认当作十六进制处理
            return bytes.fromhex(key_text)

    def get_iv_bytes(self):
        """获取IV的字节表示"""
        iv_text = self.iv_input.text().strip()
        if not iv_text:
            return None

        if self.iv_hex_check.isChecked():
            return bytes.fromhex(iv_text)
        elif self.iv_b64_check.isChecked():
            return base64.b64decode(iv_text)
        else:
            # 默认当作十六进制处理
            return bytes.fromhex(iv_text)

    def get_decrypt_key_bytes(self):
        """获取解密密钥的字节表示"""
        key_text = self.decrypt_key_input.text().strip()
        if not key_text:
            raise ValueError("密钥不能为空")

        if self.decrypt_key_hex_check.isChecked():
            return bytes.fromhex(key_text)
        elif self.decrypt_key_b64_check.isChecked():
            return base64.b64decode(key_text)
        else:
            # 默认当作十六进制处理
            return bytes.fromhex(key_text)

    def get_decrypt_iv_bytes(self):
        """获取解密IV的字节表示"""
        iv_text = self.decrypt_iv_input.text().strip()
        if not iv_text:
            return None

        if self.decrypt_iv_hex_check.isChecked():
            return bytes.fromhex(iv_text)
        elif self.decrypt_iv_b64_check.isChecked():
            return base64.b64decode(iv_text)
        else:
            # 默认当作十六进制处理
            return bytes.fromhex(iv_text)

    def perform_encryption(self):
        """执行加密操作"""
        try:
            # 获取算法参数
            algorithm = SymmetricAlgorithm(self.algo_combo.currentText())

            # 构建kwargs字典
            kwargs = {}

            # 只有块密码才添加模式和填充
            if algorithm in [SymmetricAlgorithm.AES, SymmetricAlgorithm.SM4]:
                kwargs["mode"] = Mode(self.mode_combo.currentText())
                kwargs["padding"] = Padding(self.padding_combo.currentText())

            # 只有AES才添加密钥大小
            if algorithm == SymmetricAlgorithm.AES:
                kwargs["key_size"] = int(self.key_size_combo.currentText())

            # 获取密钥和IV
            key = self.get_key_bytes()
            iv = self.get_iv_bytes()

            # 获取AAD（如果适用）
            if self.aad_input.isEnabled() and self.aad_input.text():
                kwargs["associated_data"] = self.aad_input.text().encode("utf-8")

            # 检查是文本还是文件加密
            if self.text_radio.isChecked():
                # 文本加密
                if self.hex_input_check.isChecked():
                    plaintext = bytes.fromhex(self.text_input.toPlainText().strip())
                else:
                    encoding = self.encoding_combo.currentText()
                    plaintext = self.text_input.toPlainText().encode(encoding)

                # 执行加密
                if self.base64_output_check.isChecked():
                    # 使用Base64输出
                    result = encrypt_to_base64(algorithm, plaintext, key, iv, **kwargs)
                    self.result.setText(result)
                    self.last_result = result.encode("ascii")
                else:
                    # 使用十六进制输出
                    ciphertext = encrypt(algorithm, plaintext, key, iv, **kwargs)
                    self.result.setText(ciphertext.hex())
                    self.last_result = ciphertext
            else:
                # 文件加密
                input_path = self.file_path.text()
                output_path = self.output_file_path.text()

                if not input_path or not output_path:
                    raise ValueError("请指定输入和输出文件路径")

                with open(input_path, "rb") as f:
                    plaintext = f.read()

                # 执行加密
                ciphertext = encrypt(algorithm, plaintext, key, iv, **kwargs)

                with open(output_path, "wb") as f:
                    f.write(ciphertext)

                self.result.setText(f"文件加密完成，已保存到: {output_path}")
                self.last_result = ciphertext

        except Exception as e:
            QMessageBox.warning(self, "加密错误", f"加密失败: {str(e)}")
            import traceback

            traceback.print_exc()

    def perform_decryption(self):
        """执行解密操作"""
        try:
            # 获取算法参数
            algorithm = SymmetricAlgorithm(self.decrypt_algo_combo.currentText())

            # 构建kwargs字典
            kwargs = {}

            # 只有块密码才添加模式和填充
            if algorithm in [SymmetricAlgorithm.AES, SymmetricAlgorithm.SM4]:
                kwargs["mode"] = Mode(self.decrypt_mode_combo.currentText())
                kwargs["padding"] = Padding(self.decrypt_padding_combo.currentText())

            # 只有AES才添加密钥大小
            if algorithm == SymmetricAlgorithm.AES:
                kwargs["key_size"] = int(self.decrypt_key_size_combo.currentText())

            # 获取密钥和IV
            key = self.get_decrypt_key_bytes()
            iv = self.get_decrypt_iv_bytes()

            # 获取AAD（如果适用）
            if self.decrypt_aad_input.isEnabled() and self.decrypt_aad_input.text():
                kwargs["associated_data"] = self.decrypt_aad_input.text().encode(
                    "utf-8"
                )

            # 检查是文本还是文件解密
            if self.decrypt_text_radio.isChecked():
                # 文本解密
                cipher_text = self.decrypt_text_input.toPlainText().strip()
                if not cipher_text:
                    raise ValueError("请输入要解密的密文")

                if self.decrypt_base64_input_check.isChecked():
                    # 从Base64解密
                    plaintext = decrypt_from_base64(
                        algorithm, cipher_text, key, iv, **kwargs
                    )
                elif self.decrypt_hex_input_check.isChecked():
                    # 从十六进制解密
                    ciphertext = bytes.fromhex(cipher_text)
                    plaintext = decrypt(algorithm, ciphertext, key, iv, **kwargs)
                else:
                    raise ValueError("请选择密文格式 (Base64 或十六进制)")

                # 显示结果
                try:
                    encoding = self.decrypt_encoding_combo.currentText()
                    result_text = plaintext.decode(encoding)
                    self.decrypt_result.setText(result_text)
                    self.last_decrypt_result = result_text
                except UnicodeDecodeError:
                    # 如果无法解码为文本，显示十六进制
                    self.decrypt_result.setText(
                        f"无法以{encoding}解码结果，显示十六进制:\n{plaintext.hex()}"
                    )
                    self.last_decrypt_result = plaintext.hex()
            else:
                # 文件解密
                input_path = self.decrypt_file_path.text()
                output_path = self.decrypt_output_file_path.text()

                if not input_path or not output_path:
                    raise ValueError("请指定输入和输出文件路径")

                with open(input_path, "rb") as f:
                    ciphertext = f.read()

                # 执行解密
                plaintext = decrypt(algorithm, ciphertext, key, iv, **kwargs)

                with open(output_path, "wb") as f:
                    f.write(plaintext)

                self.decrypt_result.setText(f"文件解密完成，已保存到: {output_path}")
                self.last_decrypt_result = f"文件解密完成，已保存到: {output_path}"

        except Exception as e:
            QMessageBox.warning(self, "解密错误", f"解密失败: {str(e)}")
            import traceback

            traceback.print_exc()

    def copy_result(self):
        """复制加密结果到剪贴板"""
        if hasattr(self, "last_result") and self.last_result:
            if isinstance(self.last_result, bytes):
                if self.base64_output_check.isChecked():
                    QApplication.clipboard().setText(self.result.toPlainText())
                else:
                    QApplication.clipboard().setText(self.last_result.hex())
            else:
                QApplication.clipboard().setText(self.result.toPlainText())
            QMessageBox.information(self, "复制成功", "结果已复制到剪贴板")
        else:
            QMessageBox.warning(self, "复制失败", "没有可复制的结果")

    def copy_decrypt_result(self):
        """复制解密结果到剪贴板"""
        if hasattr(self, "last_decrypt_result") and self.last_decrypt_result:
            QApplication.clipboard().setText(self.decrypt_result.toPlainText())
            QMessageBox.information(self, "复制成功", "结果已复制到剪贴板")
        else:
            QMessageBox.warning(self, "复制失败", "没有可复制的结果")

    def clear_fields(self):
        """清除加密选项卡的所有字段"""
        self.key_input.clear()
        self.iv_input.clear()
        self.aad_input.clear()
        self.text_input.clear()
        self.result.clear()
        self.file_path.clear()
        self.output_file_path.clear()
        self.file_info.clear()
        self.last_result = b""

    def clear_decrypt_fields(self):
        """清除解密选项卡的所有字段"""
        self.decrypt_key_input.clear()
        self.decrypt_iv_input.clear()
        self.decrypt_aad_input.clear()
        self.decrypt_text_input.clear()
        self.decrypt_result.clear()
        self.decrypt_file_path.clear()
        self.decrypt_output_file_path.clear()
        self.decrypt_file_info.clear()
        self.last_decrypt_result = ""
