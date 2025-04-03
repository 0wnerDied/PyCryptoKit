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
    QApplication,
    QMessageBox,
    QScrollArea,
    QFormLayout,
)
import os

from core import AsymmetricCipherFactory


class AsymmetricView(QWidget):
    def __init__(self):
        super().__init__()

        # OpenSSH格式支持的ECC曲线列表
        self.openssh_supported_curves = ["SECP256R1", "SECP384R1", "SECP521R1"]

        # 所有支持的ECC曲线列表
        self.all_ecc_curves = [
            "SECP192R1",
            "SECP224R1",
            "SECP256R1",
            "SECP384R1",
            "SECP521R1",
            "SECP256K1",
            "SECT163K1",
            "SECT233K1",
            "SECT283K1",
            "SECT409K1",
            "SECT571K1",
            "SECT163R2",
            "SECT233R1",
            "SECT283R1",
            "SECT409R1",
            "SECT571R1",
            "BRAINPOOLP256R1",
            "BRAINPOOLP384R1",
            "BRAINPOOLP512R1",
        ]

        # Edwards曲线列表
        self.edwards_curves = ["Ed25519", "Ed448"]

        # OpenSSH格式支持的Edwards曲线
        self.openssh_supported_edwards = ["Ed25519"]

        # OpenSSH格式不支持的算法列表
        self.openssh_unsupported_algorithms = ["ElGamal"]

        self.current_key_pair = None

        # 初始化UI组件为None, 以便在setup_ui中创建
        self.key_format_combo = None
        self.algo_combo = None

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # 创建滚动区域
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        # 创建内容容器
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        # 算法选择
        algo_group = QGroupBox("非对称加密算法")
        algo_layout = QVBoxLayout()

        # 获取所有可用算法
        self.algorithms = AsymmetricCipherFactory.list_algorithms()

        # 算法选择组合框
        algo_selector = QHBoxLayout()
        algo_selector.addWidget(QLabel("选择算法:"))
        self.algo_combo = QComboBox()

        # 添加所有算法
        for algo in self.algorithms:
            self.algo_combo.addItem(algo)

        # 默认选择 RSA
        if "RSA" in self.algorithms:
            index = self.algo_combo.findText("RSA")
            if index >= 0:
                self.algo_combo.setCurrentIndex(index)

        self.algo_combo.currentIndexChanged.connect(self.on_algorithm_changed)
        algo_selector.addWidget(self.algo_combo)
        algo_layout.addLayout(algo_selector)

        # 算法信息
        self.algo_info = QLabel()
        self.algo_info.setWordWrap(True)
        algo_layout.addWidget(self.algo_info)

        # 算法参数配置区域
        self.params_form = QFormLayout()

        # 创建参数标签
        self.key_size_label = QLabel("密钥大小:")
        self.curve_label = QLabel("ECC曲线:")
        self.edwards_curve_label = QLabel("Edwards曲线:")

        # 密钥大小
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["1024", "2048", "3072", "4096"])
        self.key_size_combo.setCurrentText("2048")  # 默认选择2048位
        self.params_form.addRow(self.key_size_label, self.key_size_combo)

        # ECC 曲线选择
        self.curve_combo = QComboBox()
        # 初始添加所有曲线
        self.curve_combo.addItems(self.all_ecc_curves)
        self.params_form.addRow(self.curve_label, self.curve_combo)

        # Edwards 曲线选择
        self.edwards_curve_combo = QComboBox()
        self.edwards_curve_combo.addItems(self.edwards_curves)
        self.params_form.addRow(self.edwards_curve_label, self.edwards_curve_combo)

        algo_layout.addLayout(self.params_form)
        algo_group.setLayout(algo_layout)
        content_layout.addWidget(algo_group)

        # 密钥保护密码
        password_group = QGroupBox("密钥保护")
        password_layout = QVBoxLayout()
        password_input_layout = QHBoxLayout()
        password_input_layout.addWidget(QLabel("密码:"))
        self.key_password = QLineEdit()
        self.key_password.setPlaceholderText("为私钥设置密码保护 (可选) ")
        self.key_password.setEchoMode(QLineEdit.Password)
        password_input_layout.addWidget(self.key_password)
        password_layout.addLayout(password_input_layout)

        # 密码确认
        confirm_layout = QHBoxLayout()
        confirm_layout.addWidget(QLabel("确认密码:"))
        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("再次输入密码")
        self.confirm_password.setEchoMode(QLineEdit.Password)
        confirm_layout.addWidget(self.confirm_password)
        password_layout.addLayout(confirm_layout)

        # XML格式密码限制提示
        self.password_warning = QLabel("XML格式不支持密码加密")
        self.password_warning.setStyleSheet("color: yellow;")
        self.password_warning.setVisible(False)
        password_layout.addWidget(self.password_warning)

        password_group.setLayout(password_layout)
        content_layout.addWidget(password_group)

        # 密钥格式选择
        format_group = QGroupBox("密钥格式")
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("选择格式:"))
        self.key_format_combo = QComboBox()
        self.key_format_combo.addItems(["PEM", "DER", "OpenSSH", "XML"])
        self.key_format_combo.currentIndexChanged.connect(self.on_format_changed)
        format_layout.addWidget(self.key_format_combo)
        format_group.setLayout(format_layout)
        content_layout.addWidget(format_group)

        # 密钥生成按钮
        btn_layout = QHBoxLayout()
        self.generate_btn = QPushButton("生成密钥对")
        self.generate_btn.clicked.connect(self.generate_key_pair)
        btn_layout.addWidget(self.generate_btn)
        content_layout.addLayout(btn_layout)

        # 密钥保存按钮
        save_layout = QHBoxLayout()
        self.save_private_btn = QPushButton("保存私钥")
        self.save_private_btn.clicked.connect(self.save_private_key)
        self.save_private_btn.setEnabled(False)
        save_layout.addWidget(self.save_private_btn)

        self.save_public_btn = QPushButton("保存公钥")
        self.save_public_btn.clicked.connect(self.save_public_key)
        self.save_public_btn.setEnabled(False)
        save_layout.addWidget(self.save_public_btn)

        self.save_both_btn = QPushButton("保存密钥对")
        self.save_both_btn.clicked.connect(self.save_key_pair)
        self.save_both_btn.setEnabled(False)
        save_layout.addWidget(self.save_both_btn)
        content_layout.addLayout(save_layout)

        # 结果显示
        result_group = QGroupBox("生成结果")
        result_layout = QVBoxLayout()

        # 公钥显示
        public_key_layout = QVBoxLayout()
        public_key_layout.addWidget(QLabel("公钥:"))
        self.public_key_display = QTextEdit()
        self.public_key_display.setReadOnly(True)
        self.public_key_display.setPlaceholderText("生成的公钥将显示在这里")
        public_key_layout.addWidget(self.public_key_display)
        result_layout.addLayout(public_key_layout)

        # 私钥显示
        private_key_layout = QVBoxLayout()
        private_key_layout.addWidget(QLabel("私钥:"))
        self.private_key_display = QTextEdit()
        self.private_key_display.setReadOnly(True)
        self.private_key_display.setPlaceholderText("生成的私钥将显示在这里")
        private_key_layout.addWidget(self.private_key_display)
        result_layout.addLayout(private_key_layout)

        # 复制按钮
        copy_layout = QHBoxLayout()
        self.copy_public_btn = QPushButton("复制公钥")
        self.copy_public_btn.clicked.connect(self.copy_public_key)
        self.copy_public_btn.setEnabled(False)
        copy_layout.addWidget(self.copy_public_btn)

        self.copy_private_btn = QPushButton("复制私钥")
        self.copy_private_btn.clicked.connect(self.copy_private_key)
        self.copy_private_btn.setEnabled(False)
        copy_layout.addWidget(self.copy_private_btn)

        result_layout.addLayout(copy_layout)
        result_group.setLayout(result_layout)
        content_layout.addWidget(result_group)

        # 设置滚动区域
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)
        self.setLayout(layout)

        # 在所有UI组件初始化完成后, 再更新算法信息和参数
        self.update_algorithm_info()
        self.update_algorithm_params()
        self.update_display_state()

    def update_algorithm_info(self):
        """更新算法信息"""
        algorithm = self.algo_combo.currentText()
        if algorithm:
            try:
                if algorithm == "RSA":
                    info_text = "RSA是一种非对称加密算法, 基于大整数因子分解的数学难题。\n支持密钥大小: 1024, 2048, 3072, 4096位"
                elif algorithm == "ECC":
                    info_text = "ECC是一种基于椭圆曲线数学的非对称加密算法, 提供与RSA相同的安全性但使用更短的密钥。\n支持多种椭圆曲线。"
                elif algorithm == "ElGamal":
                    info_text = "ElGamal是一种基于离散对数问题的非对称加密算法。\n支持密钥大小: 1024, 2048, 3072, 4096位"
                elif algorithm == "Edwards":
                    info_text = "Edwards是一种特殊形式的椭圆曲线, 提供高效的数字签名功能。\n支持Ed25519和Ed448曲线, 广泛用于现代密码协议。"
                else:
                    info_text = f"{algorithm}是一种非对称加密算法。"

                self.algo_info.setText(info_text)
            except Exception as e:
                self.algo_info.setText(f"获取算法信息失败: {str(e)}")

    def update_algorithm_params(self):
        """更新算法参数显示"""
        algorithm = self.algo_combo.currentText()

        # 默认隐藏所有参数
        self.key_size_label.setVisible(False)
        self.key_size_combo.setVisible(False)
        self.curve_label.setVisible(False)
        self.curve_combo.setVisible(False)
        self.edwards_curve_label.setVisible(False)
        self.edwards_curve_combo.setVisible(False)

        # 根据算法显示相关参数
        if algorithm == "RSA" or algorithm == "ElGamal":
            # 显示密钥大小
            self.key_size_label.setVisible(True)
            self.key_size_combo.setVisible(True)
        elif algorithm == "ECC":
            # 显示ECC曲线选择
            self.curve_label.setVisible(True)
            self.curve_combo.setVisible(True)
            # 更新可用的曲线列表
            self.update_available_curves()
        elif algorithm == "Edwards":
            # 显示Edwards曲线选择
            self.edwards_curve_label.setVisible(True)
            self.edwards_curve_combo.setVisible(True)
            # 更新可用的Edwards曲线
            self.update_available_edwards_curves()

        # 更新格式选项
        self.update_format_options()

        # 更新密码输入框状态
        self.update_password_field_state()

    def update_available_curves(self):
        """根据当前选择的密钥格式更新可用的ECC曲线"""
        # 确保key_format_combo已经初始化
        if self.key_format_combo is None:
            return

        current_format = self.key_format_combo.currentText().lower()
        current_curve = self.curve_combo.currentText()

        # 清空曲线选择框
        self.curve_combo.clear()

        if current_format == "openssh":
            # 如果是OpenSSH格式, 只添加支持的曲线
            self.curve_combo.addItems(self.openssh_supported_curves)

            # 如果之前选择的曲线在支持列表中, 则保持选择
            if current_curve in self.openssh_supported_curves:
                self.curve_combo.setCurrentText(current_curve)
            else:
                # 否则默认选择第一个支持的曲线
                self.curve_combo.setCurrentIndex(0)
        else:
            # 其他格式添加所有支持的曲线
            self.curve_combo.addItems(self.all_ecc_curves)

            # 尝试恢复之前的选择
            if current_curve in self.all_ecc_curves:
                self.curve_combo.setCurrentText(current_curve)

    def update_available_edwards_curves(self):
        """根据当前选择的密钥格式更新可用的Edwards曲线"""
        # 确保key_format_combo已经初始化
        if self.key_format_combo is None:
            return

        current_format = self.key_format_combo.currentText().lower()
        current_curve = self.edwards_curve_combo.currentText()

        # 清空曲线选择框
        self.edwards_curve_combo.clear()

        if current_format == "openssh":
            # 如果是OpenSSH格式, 只添加支持的Edwards曲线
            self.edwards_curve_combo.addItems(self.openssh_supported_edwards)

            # 如果之前选择的曲线在支持列表中, 则保持选择
            if current_curve in self.openssh_supported_edwards:
                self.edwards_curve_combo.setCurrentText(current_curve)
            else:
                # 否则默认选择第一个支持的曲线
                self.edwards_curve_combo.setCurrentIndex(0)
        else:
            # 其他格式添加所有支持的Edwards曲线
            self.edwards_curve_combo.addItems(self.edwards_curves)

            # 尝试恢复之前的选择
            if current_curve in self.edwards_curves:
                self.edwards_curve_combo.setCurrentText(current_curve)

    def update_format_options(self):
        """根据当前选择的算法更新可用的格式选项"""
        if self.key_format_combo is None or self.algo_combo is None:
            return

        current_algorithm = self.algo_combo.currentText()
        current_format = self.key_format_combo.currentText()

        # 暂时断开信号连接, 避免触发事件
        self.key_format_combo.blockSignals(True)

        # 清空并重新添加格式选项
        self.key_format_combo.clear()

        # 如果是ElGamal算法, 不添加OpenSSH选项
        if current_algorithm in self.openssh_unsupported_algorithms:
            self.key_format_combo.addItems(["PEM", "DER", "XML"])

            # 如果之前选择的是OpenSSH, 则默认选择PEM
            if current_format == "OpenSSH":
                self.key_format_combo.setCurrentText("PEM")
        else:
            # 其他算法添加所有格式
            self.key_format_combo.addItems(["PEM", "DER", "OpenSSH", "XML"])

            # 尝试恢复之前的选择
            if current_format in ["PEM", "DER", "OpenSSH", "XML"]:
                self.key_format_combo.setCurrentText(current_format)

        # 恢复信号连接
        self.key_format_combo.blockSignals(False)

        # 更新密码输入框状态
        self.update_password_field_state()

        # 如果当前算法是Edwards，更新可用的Edwards曲线
        if current_algorithm == "Edwards":
            self.update_available_edwards_curves()

    def update_password_field_state(self):
        """根据当前格式更新密码输入框状态"""
        if self.key_format_combo is None:
            return

        key_format = self.key_format_combo.currentText().lower()

        if key_format == "xml":
            # XML格式不支持密码，禁用密码输入框
            self.key_password.setEnabled(False)
            self.confirm_password.setEnabled(False)

            # 如果已经输入了密码，清空它们
            if self.key_password.text() or self.confirm_password.text():
                self.key_password.clear()
                self.confirm_password.clear()

            # 显示警告
            self.password_warning.setVisible(True)
        else:
            # 其他格式支持密码，启用密码输入框
            self.key_password.setEnabled(True)
            self.confirm_password.setEnabled(True)

            # 隐藏警告
            self.password_warning.setVisible(False)

    def on_algorithm_changed(self, index):
        """算法变更处理"""
        self.update_algorithm_info()
        self.update_algorithm_params()

    def on_format_changed(self, index):
        """密钥格式变更处理"""
        # 如果当前算法是ECC, 需要更新可用的曲线
        if self.algo_combo.currentText() == "ECC":
            self.update_available_curves()
        # 如果当前算法是Edwards, 需要更新可用的Edwards曲线
        elif self.algo_combo.currentText() == "Edwards":
            self.update_available_edwards_curves()

        # 更新密码输入框状态
        self.update_password_field_state()

        # 更新显示区域状态
        self.update_display_state()

    def update_display_state(self):
        """根据当前选择的格式更新显示区域状态"""
        if self.key_format_combo is None:
            return

        key_format = self.key_format_combo.currentText().lower()

        if key_format == "der":
            # DER格式是二进制的，禁用显示和复制功能
            self.public_key_display.setEnabled(False)
            self.private_key_display.setEnabled(False)
            self.copy_public_btn.setEnabled(False)
            self.copy_private_btn.setEnabled(False)

            # 设置提示信息
            self.public_key_display.setText(
                "DER格式的二进制数据不适合显示, 请使用保存功能将密钥保存到文件。"
            )
            self.private_key_display.setText(
                "DER格式的二进制数据不适合显示, 请使用保存功能将密钥保存到文件。"
            )
        else:
            # 其他格式可以显示和复制
            self.public_key_display.setEnabled(True)
            self.private_key_display.setEnabled(True)

            # 如果已经生成了密钥对，则启用复制按钮
            if self.current_key_pair:
                self.copy_public_btn.setEnabled(True)
                self.copy_private_btn.setEnabled(True)

            # 清空显示区域，等待生成新的密钥
            if not self.current_key_pair:
                self.public_key_display.setText("")
                self.private_key_display.setText("")
                self.public_key_display.setPlaceholderText("生成的公钥将显示在这里")
                self.private_key_display.setPlaceholderText("生成的私钥将显示在这里")

    def generate_key_pair(self):
        """生成密钥对"""
        algorithm = self.algo_combo.currentText()
        if not algorithm:
            QMessageBox.warning(self, "错误", "请选择加密算法")
            return

        try:
            # 获取密码
            password = self.key_password.text()
            confirm_password = self.confirm_password.text()
            key_format = self.key_format_combo.currentText().lower()

            # XML格式不使用密码
            if key_format == "xml":
                password = ""
                confirm_password = ""

            if password and password != confirm_password:
                QMessageBox.warning(self, "错误", "两次输入的密码不一致")
                return

            password_bytes = password.encode("utf-8") if password else None

            # 根据算法获取参数
            if algorithm == "RSA" or algorithm == "ElGamal":
                key_size = int(self.key_size_combo.currentText())
                key_pair = AsymmetricCipherFactory.create_key_pair(
                    algorithm, key_size=key_size, password=password_bytes
                )
            elif algorithm == "ECC":
                curve = self.curve_combo.currentText()
                key_pair = AsymmetricCipherFactory.create_key_pair(
                    algorithm, curve=curve, password=password_bytes
                )
            elif algorithm == "Edwards":
                curve = self.edwards_curve_combo.currentText()
                key_pair = AsymmetricCipherFactory.create_key_pair(
                    algorithm, curve=curve, password=password_bytes
                )
            else:
                # 默认参数
                key_pair = AsymmetricCipherFactory.create_key_pair(
                    algorithm, password=password_bytes
                )

            # 保存生成的密钥对
            self.current_key_pair = key_pair

            # 显示密钥
            if key_format == "pem":
                public_key_str = key_pair.public_key.to_pem().decode("utf-8")
                private_key_str = key_pair.private_key.to_pem().decode("utf-8")

                self.public_key_display.setText(public_key_str)
                self.private_key_display.setText(private_key_str)

                # 启用复制按钮
                self.copy_public_btn.setEnabled(True)
                self.copy_private_btn.setEnabled(True)

            elif key_format == "der":
                # DER格式不显示内容，只提示用户保存
                self.public_key_display.setText(
                    "DER格式的二进制数据不适合显示, 请使用保存功能将密钥保存到文件。"
                )
                self.private_key_display.setText(
                    "DER格式的二进制数据不适合显示, 请使用保存功能将密钥保存到文件。"
                )

                # 禁用复制按钮
                self.copy_public_btn.setEnabled(False)
                self.copy_private_btn.setEnabled(False)

            elif key_format == "openssh":
                public_key_str = key_pair.public_key.to_openssh().decode("utf-8")
                private_key_str = key_pair.private_key.to_openssh().decode("utf-8")

                self.public_key_display.setText(public_key_str)
                self.private_key_display.setText(private_key_str)

                # 启用复制按钮
                self.copy_public_btn.setEnabled(True)
                self.copy_private_btn.setEnabled(True)

            elif key_format == "xml":
                public_key_str = key_pair.public_key.to_xml()
                private_key_str = key_pair.private_key.to_xml()

                self.public_key_display.setText(public_key_str)
                self.private_key_display.setText(private_key_str)

                # 启用复制按钮
                self.copy_public_btn.setEnabled(True)
                self.copy_private_btn.setEnabled(True)

            else:
                public_key_str = "未知格式"
                private_key_str = "未知格式"

                self.public_key_display.setText(public_key_str)
                self.private_key_display.setText(private_key_str)

                # 禁用复制按钮
                self.copy_public_btn.setEnabled(False)
                self.copy_private_btn.setEnabled(False)

            # 启用保存按钮
            self.save_private_btn.setEnabled(True)
            self.save_public_btn.setEnabled(True)
            self.save_both_btn.setEnabled(True)

            QMessageBox.information(self, "成功", f"成功生成{algorithm}密钥对")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成密钥对失败: {str(e)}")

    def save_private_key(self):
        """保存私钥到文件"""
        if not self.current_key_pair:
            QMessageBox.warning(self, "错误", "没有可保存的私钥")
            return

        # 检查密码
        password = self.key_password.text()
        confirm_password = self.confirm_password.text()
        key_format = self.key_format_combo.currentText().lower()

        # XML格式不使用密码
        if key_format == "xml":
            password = ""

        if password and password != confirm_password:
            QMessageBox.warning(self, "错误", "两次输入的密码不一致")
            return

        password_bytes = password.encode("utf-8") if password else None

        # 根据格式确定文件扩展名
        if key_format == "pem":
            ext = "pem"
        elif key_format == "der":
            ext = "der"
        elif key_format == "openssh":
            ext = "key"
        elif key_format == "xml":
            ext = "xml"
        else:
            ext = "key"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存私钥", "", f"密钥文件 (*.{ext});;所有文件 (*.*)"
        )

        if file_path:
            try:
                self.current_key_pair.private_key.save_to_file(
                    file_path, key_format, password_bytes
                )
                QMessageBox.information(self, "保存成功", f"私钥已保存到 {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "保存失败", f"保存私钥时发生错误: {str(e)}")

    def save_public_key(self):
        """保存公钥到文件"""
        if not self.current_key_pair:
            QMessageBox.warning(self, "错误", "没有可保存的公钥")
            return

        # 获取格式
        key_format = self.key_format_combo.currentText().lower()

        # 根据格式确定文件扩展名
        if key_format == "pem":
            ext = "pem"
        elif key_format == "der":
            ext = "der"
        elif key_format == "openssh":
            ext = "pub"
        elif key_format == "xml":
            ext = "xml"
        else:
            ext = "pub"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存公钥", "", f"公钥文件 (*.{ext});;所有文件 (*.*)"
        )

        if file_path:
            try:
                self.current_key_pair.public_key.save_to_file(file_path, key_format)
                QMessageBox.information(self, "保存成功", f"公钥已保存到 {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "保存失败", f"保存公钥时发生错误: {str(e)}")

    def save_key_pair(self):
        """保存密钥对到文件"""
        if not self.current_key_pair:
            QMessageBox.warning(self, "错误", "没有可保存的密钥对")
            return

        # 检查密码
        password = self.key_password.text()
        confirm_password = self.confirm_password.text()
        key_format = self.key_format_combo.currentText().lower()

        # XML格式不使用密码
        if key_format == "xml":
            password = ""

        if password and password != confirm_password:
            QMessageBox.warning(self, "错误", "两次输入的密码不一致")
            return

        password_bytes = password.encode("utf-8") if password else None

        # 根据格式确定文件扩展名
        if key_format == "pem":
            ext_priv = "pem"
            ext_pub = "pem"
        elif key_format == "der":
            ext_priv = "der"
            ext_pub = "der"
        elif key_format == "openssh":
            ext_priv = "key"
            ext_pub = "pub"
        elif key_format == "xml":
            ext_priv = "xml"
            ext_pub = "xml"
        else:
            ext_priv = "key"
            ext_pub = "pub"

        # 选择目录
        directory = QFileDialog.getExistingDirectory(self, "选择保存密钥对的目录", "")

        if directory:
            try:
                algorithm = self.algo_combo.currentText()
                private_key_path = os.path.join(
                    directory, f"{algorithm.lower()}_private.{ext_priv}"
                )
                public_key_path = os.path.join(
                    directory, f"{algorithm.lower()}_public.{ext_pub}"
                )

                self.current_key_pair.save_to_files(
                    private_key_path, public_key_path, key_format, password_bytes
                )

                QMessageBox.information(
                    self,
                    "保存成功",
                    f"密钥对已保存:\n私钥: {private_key_path}\n公钥: {public_key_path}",
                )
            except Exception as e:
                QMessageBox.critical(
                    self, "保存失败", f"保存密钥对时发生错误: {str(e)}"
                )

    def copy_public_key(self):
        """复制公钥到剪贴板"""
        public_key_text = self.public_key_display.toPlainText()
        if public_key_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(public_key_text)
            QMessageBox.information(self, "复制成功", "公钥已复制到剪贴板")
        else:
            QMessageBox.warning(self, "复制失败", "没有可复制的公钥")

    def copy_private_key(self):
        """复制私钥到剪贴板"""
        private_key_text = self.private_key_display.toPlainText()
        if private_key_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(private_key_text)
            QMessageBox.information(self, "复制成功", "私钥已复制到剪贴板")
        else:
            QMessageBox.warning(self, "复制失败", "没有可复制的私钥")
