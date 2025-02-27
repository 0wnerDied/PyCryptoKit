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
)
from core import create_hash, list_hash_algorithms


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

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(self.algorithms)
        # 默认选择 SHA-256
        if "sha256" in self.algorithms:
            self.algo_combo.setCurrentText("sha256")
        algo_selector.addWidget(self.algo_combo)
        algo_layout.addLayout(algo_selector)

        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)

        # 输入选择
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 输入方式选择
        self.text_radio = QRadioButton("文本输入")
        self.file_radio = QRadioButton("文件输入")
        self.text_radio.setChecked(True)

        input_type_layout = QHBoxLayout()
        input_type_layout.addWidget(self.text_radio)
        input_type_layout.addWidget(self.file_radio)
        input_layout.addLayout(input_type_layout)

        # 文本输入
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("在此输入要计算哈希的文本")
        input_layout.addWidget(self.text_input)

        # 文件选择
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("选择要计算哈希的文件")
        file_layout.addWidget(self.file_path)
        self.browse_btn = QPushButton("浏览...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        input_layout.addLayout(file_layout)

        # 连接单选按钮信号
        self.text_radio.toggled.connect(self.toggle_input_mode)
        self.file_radio.toggled.connect(self.toggle_input_mode)

        # 初始状态
        self.file_path.setEnabled(False)
        self.browse_btn.setEnabled(False)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 计算按钮
        self.calc_btn = QPushButton("计算哈希")
        self.calc_btn.clicked.connect(self.calculate_hash)
        layout.addWidget(self.calc_btn)

        # 结果显示
        result_group = QGroupBox("哈希结果")
        result_layout = QVBoxLayout()
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        result_layout.addWidget(self.result)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        self.setLayout(layout)

    def toggle_input_mode(self):
        text_mode = self.text_radio.isChecked()
        self.text_input.setEnabled(text_mode)
        self.file_path.setEnabled(not text_mode)
        self.browse_btn.setEnabled(not text_mode)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if file_path:
            self.file_path.setText(file_path)

    def calculate_hash(self):
        algorithm = self.algo_combo.currentText()

        try:
            hash_obj = create_hash(algorithm)

            if self.text_radio.isChecked():
                text = self.text_input.toPlainText()
                if not text:
                    self.result.setText("请输入要计算哈希的文本")
                    return

                hash_obj.update(text.encode("utf-8"))
                result = hash_obj.hexdigest()
                self.result.setText(result)

            else:  # 文件模式
                file_path = self.file_path.text()
                if not file_path:
                    self.result.setText("请选择要计算哈希的文件")
                    return

                try:
                    with open(file_path, "rb") as f:
                        while chunk := f.read(8192):  # 分块读取大文件
                            hash_obj.update(chunk)

                    result = hash_obj.hexdigest()
                    self.result.setText(result)
                except Exception as e:
                    self.result.setText(f"文件读取错误: {str(e)}")

        except Exception as e:
            self.result.setText(f"计算错误: {str(e)}")
