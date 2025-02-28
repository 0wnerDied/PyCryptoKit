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
)
import os

from core import (
    create_hash,
    list_hash_algorithms,
    get_hash_algorithm_info,
    SECURE_ALGORITHMS,
    INSECURE_ALGORITHMS,
)


class HashView(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # 算法选择
        algo_group = QGroupBox("哈希算法")
        algo_layout = QVBoxLayout()

        # 获取所有可用算法
        self.algorithms = list_hash_algorithms()

        # 按安全性分组算法
        self.secure_algos = [
            algo for algo in self.algorithms if algo in SECURE_ALGORITHMS
        ]
        self.insecure_algos = [
            algo for algo in self.algorithms if algo in INSECURE_ALGORITHMS
        ]

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.algo_combo = QComboBox()

        # 添加所有算法（不使用分组标题）
        for algo in self.algorithms:
            self.algo_combo.addItem(algo)

        # 默认选择 SHA-256
        if "SHA256" in self.algorithms:
            index = self.algo_combo.findText("SHA256")
            if index >= 0:
                self.algo_combo.setCurrentIndex(index)

        self.algo_combo.currentIndexChanged.connect(self.on_algorithm_changed)
        algo_selector.addWidget(self.algo_combo)
        algo_layout.addLayout(algo_selector)

        # 算法信息
        self.algo_info = QLabel()
        self.algo_info.setWordWrap(True)
        algo_layout.addWidget(self.algo_info)

        # 更新算法信息
        self.update_algorithm_info()

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 输入选择
        input_group = QGroupBox("输入")
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
        self.text_input.setPlaceholderText("在此输入要计算哈希的文本")
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
        self.file_path.setPlaceholderText("选择要计算哈希的文件")
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

        # 计算按钮
        btn_layout = QHBoxLayout()
        self.calc_btn = QPushButton("计算哈希")
        self.calc_btn.clicked.connect(self.calculate_hash)
        btn_layout.addWidget(self.calc_btn)

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
        result_group = QGroupBox("哈希结果")
        result_layout = QVBoxLayout()
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        result_layout.addWidget(self.result)

        # 显示格式选项
        format_layout = QHBoxLayout()
        self.uppercase_check = QCheckBox("大写显示")
        self.uppercase_check.toggled.connect(self.update_result_format)
        format_layout.addWidget(self.uppercase_check)

        result_layout.addLayout(format_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 保存最后计算的结果
        self.last_result = ""

        self.setLayout(layout)

    def toggle_input_mode(self):
        text_mode = self.text_radio.isChecked()
        if text_mode:
            self.text_widget.show()
            self.file_widget.hide()
        else:
            self.text_widget.hide()
            self.file_widget.show()

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if file_path:
            self.file_path.setText(file_path)
            self.update_file_info(file_path)

    def on_file_path_changed(self):
        file_path = self.file_path.text()
        if os.path.exists(file_path):
            self.update_file_info(file_path)
        else:
            self.file_info.setText("")

    def update_file_info(self, file_path):
        try:
            # 获取文件状态
            file_stats = os.stat(file_path)
            size_bytes = file_stats.st_size
            size_str = self.format_file_size(size_bytes)
            self.file_info.setText(
                f"文件名: {os.path.basename(file_path)}\n大小: {size_str}"
            )
        except Exception as e:
            self.file_info.setText(f"无法获取文件信息: {str(e)}")

    def format_file_size(self, size_bytes):
        """格式化文件大小"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0 or unit == "TB":
                break
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} {unit}"

    def on_algorithm_changed(self, index):
        self.update_algorithm_info()

    def update_algorithm_info(self):
        algorithm = self.algo_combo.currentText()
        if not algorithm:
            self.algo_info.setText("")
            return

        try:
            info = get_hash_algorithm_info(algorithm)
            is_secure = (
                "安全"
                if algorithm in SECURE_ALGORITHMS
                else "不安全（已过时，仅用于兼容）"
            )
            self.algo_info.setText(
                f"算法: {algorithm}\n安全性: {is_secure}\n描述: {info.get('description', '')}"
            )
        except Exception as e:
            self.algo_info.setText(f"无法获取算法信息: {str(e)}")

    def calculate_hash(self):
        algorithm = self.algo_combo.currentText()

        if not algorithm:
            self.result.setText("请选择有效的哈希算法")
            return

        try:
            hash_obj = create_hash(algorithm)

            if self.text_radio.isChecked():
                text = self.text_input.toPlainText()
                if not text:
                    self.result.setText("请输入要计算哈希的文本")
                    return

                try:
                    # 处理十六进制输入
                    if self.hex_input_check.isChecked():
                        # 移除所有空白字符
                        text = "".join(text.split())
                        # 转换十六进制为字节
                        data = bytes.fromhex(text)
                        self.last_result = hash_obj.hash_data(data).hex()
                    else:
                        # 使用选定的编码
                        encoding = self.encoding_combo.currentText()
                        self.last_result = hash_obj.hash_data(text, encoding).hex()

                    self.update_result_format()
                except ValueError as e:
                    self.result.setText(f"十六进制格式错误: {str(e)}")
                    return
                except UnicodeEncodeError as e:
                    self.result.setText(f"编码错误: {str(e)}")
                    return

            else:  # 文件模式
                file_path = self.file_path.text()
                if not file_path:
                    self.result.setText("请选择要计算哈希的文件")
                    return

                try:
                    # 直接使用 hash_file 方法替代手动实现的文件读取逻辑
                    self.last_result = hash_obj.hash_file(file_path).hex()
                    self.update_result_format()
                except Exception as e:
                    self.result.setText(f"文件读取错误: {str(e)}")

        except Exception as e:
            self.result.setText(f"计算错误: {str(e)}")

    def update_result_format(self):
        if not self.last_result:
            return

        if self.uppercase_check.isChecked():
            self.result.setText(self.last_result.upper())
        else:
            self.result.setText(self.last_result.lower())

    def copy_result(self):
        result_text = self.result.toPlainText()
        if (
            result_text
            and not result_text.startswith("请")
            and not result_text.startswith("计算错误")
        ):
            clipboard = QApplication.clipboard()
            clipboard.setText(result_text)
            self.result.append("\n(已复制到剪贴板)")

    def clear_fields(self):
        self.text_input.clear()
        self.file_path.clear()
        self.file_info.clear()
        self.result.clear()
        self.last_result = ""
