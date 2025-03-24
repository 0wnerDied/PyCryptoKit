"""
ECC (椭圆曲线加密) 模块
提供ECC密钥对生成功能
"""

import logging
import xml.etree.ElementTree as ET
import base64
from typing import Union, Optional, BinaryIO, List

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)

# 支持的曲线类型
_ECC_CURVES = {
    "SECP192R1": ec.SECP192R1(),
    "SECP224R1": ec.SECP224R1(),
    "SECP256R1": ec.SECP256R1(),
    "SECP384R1": ec.SECP384R1(),
    "SECP521R1": ec.SECP521R1(),
    "SECP256K1": ec.SECP256K1(),
    "SECT163K1": ec.SECT163K1(),
    "SECT233K1": ec.SECT233K1(),
    "SECT283K1": ec.SECT283K1(),
    "SECT409K1": ec.SECT409K1(),
    "SECT571K1": ec.SECT571K1(),
    "SECT163R2": ec.SECT163R2(),
    "SECT233R1": ec.SECT233R1(),
    "SECT283R1": ec.SECT283R1(),
    "SECT409R1": ec.SECT409R1(),
    "SECT571R1": ec.SECT571R1(),
    "BRAINPOOLP256R1": ec.BrainpoolP256R1(),
    "BRAINPOOLP384R1": ec.BrainpoolP384R1(),
    "BRAINPOOLP512R1": ec.BrainpoolP512R1(),
}


class ECCKey(AsymmetricKey):
    """椭圆曲线密钥类, 包装Cryptography库的ECC密钥"""

    def __init__(self, key_data, key_type: str):
        super().__init__(key_data, key_type, ECC.algorithm_name())
        # 存储曲线信息
        if key_type == "public":
            self.curve = key_data.curve
        else:
            self.curve = key_data.curve

    def to_pem(self) -> bytes:
        """将密钥转换为PEM格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            return self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                encryption_algorithm=serialization.NoEncryption(),
            )

    def to_der(self) -> bytes:
        """将密钥转换为DER格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            return self.key_data.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                encryption_algorithm=serialization.NoEncryption(),
            )

    def to_openssh(self) -> bytes:
        """将密钥转换为OpenSSH格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        else:
            return self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def to_xml(self) -> str:
        """将密钥转换为XML格式"""
        curve_name = self._get_curve_name()

        if self.key_type == "public":
            # 获取公钥点坐标
            public_numbers = self.key_data.public_numbers()
            x = public_numbers.x
            y = public_numbers.y

            root = ET.Element("ECCKeyValue")

            # 添加曲线信息
            curve_elem = ET.SubElement(root, "Curve")
            curve_elem.text = curve_name

            # 添加公钥点坐标
            x_elem = ET.SubElement(root, "X")
            x_elem.text = base64.b64encode(
                x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            y_elem = ET.SubElement(root, "Y")
            y_elem.text = base64.b64encode(
                y.to_bytes((y.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

        else:
            # 获取私钥
            private_numbers = self.key_data.private_numbers()
            private_value = private_numbers.private_value
            public_numbers = private_numbers.public_numbers
            x = public_numbers.x
            y = public_numbers.y

            root = ET.Element("ECCKeyValue")

            # 添加曲线信息
            curve_elem = ET.SubElement(root, "Curve")
            curve_elem.text = curve_name

            # 添加私钥
            d_elem = ET.SubElement(root, "D")
            d_elem.text = base64.b64encode(
                private_value.to_bytes(
                    (private_value.bit_length() + 7) // 8, byteorder="big"
                )
            ).decode("utf-8")

            # 添加公钥点坐标
            x_elem = ET.SubElement(root, "X")
            x_elem.text = base64.b64encode(
                x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            y_elem = ET.SubElement(root, "Y")
            y_elem.text = base64.b64encode(
                y.to_bytes((y.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

        return ET.tostring(root, encoding="unicode")

    def _get_curve_name(self) -> str:
        """获取曲线名称"""
        curve = self.curve

        # 根据曲线对象获取名称
        for name, curve_obj in _ECC_CURVES.items():
            if isinstance(curve, type(curve_obj)):
                return name

        # 如果找不到匹配的曲线, 返回曲线的字符串表示
        return str(curve).split(".")[-1].strip(">").strip("'")

    def save_to_file(
        self, filepath: str, format: str = "pem", password: Optional[bytes] = None
    ) -> None:
        """
        将密钥保存到文件

        Args:
            filepath: 文件路径
            format: 文件格式 ('pem', 'der', 'openssh', 'xml')
            password: 加密密码 (仅适用于私钥)
        """
        try:
            if format.lower() == "pem":
                if self.key_type == "public":
                    key_bytes = self.key_data.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                else:
                    encryption_algorithm = serialization.NoEncryption()
                    if password:
                        encryption_algorithm = serialization.BestAvailableEncryption(
                            password
                        )
                    key_bytes = self.key_data.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                        encryption_algorithm=encryption_algorithm,
                    )
            elif format.lower() == "der":
                if self.key_type == "public":
                    key_bytes = self.key_data.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                else:
                    encryption_algorithm = serialization.NoEncryption()
                    if password:
                        encryption_algorithm = serialization.BestAvailableEncryption(
                            password
                        )
                    key_bytes = self.key_data.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                        encryption_algorithm=encryption_algorithm,
                    )
            elif format.lower() == "openssh":
                if self.key_type == "public":
                    key_bytes = self.key_data.public_bytes(
                        encoding=serialization.Encoding.OpenSSH,
                        format=serialization.PublicFormat.OpenSSH,
                    )
                else:
                    encryption_algorithm = serialization.NoEncryption()
                    if password:
                        encryption_algorithm = serialization.BestAvailableEncryption(
                            password
                        )
                    key_bytes = self.key_data.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.OpenSSH,
                        encryption_algorithm=encryption_algorithm,
                    )
            elif format.lower() == "xml":
                key_bytes = self.to_xml().encode("utf-8")
            else:
                raise ValueError(f"不支持的格式: {format}")

            with open(filepath, "wb") as f:
                f.write(key_bytes)

            logger.info(f"密钥已保存到 {filepath}")

        except Exception as e:
            logger.error(f"保存密钥失败: {e}")
            raise ValueError(f"保存密钥失败: {e}")


class ECC(AsymmetricCipher):
    """椭圆曲线加密算法实现, 包装Cryptography库"""

    @staticmethod
    def algorithm_name() -> str:
        return "ECC"

    @staticmethod
    def supported_curves() -> List[str]:
        """返回支持的椭圆曲线列表"""
        global _ECC_CURVES
        return list(_ECC_CURVES.keys())

    @staticmethod
    def get_supported_key_sizes() -> List[str]:
        """获取支持的密钥大小列表 (对于ECC, 返回支持的曲线名称)"""
        return ECC.supported_curves()

    @staticmethod
    def generate_key_pair(curve: str = "SECP256R1", **kwargs) -> KeyPair:
        """
        生成ECC密钥对

        Args:
            curve: 椭圆曲线类型, 默认为SECP256R1

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        global _ECC_CURVES
        try:
            # 验证曲线类型
            if curve not in _ECC_CURVES:
                raise ValueError(
                    f"不支持的曲线类型: {curve}, 支持的类型: {', '.join(_ECC_CURVES.keys())}"
                )

            curve_obj = _ECC_CURVES[curve]

            # 生成私钥
            private_key = ec.generate_private_key(
                curve=curve_obj, backend=default_backend()
            )

            # 获取公钥
            public_key = private_key.public_key()

            logger.info(f"成功生成ECC密钥对, 使用曲线: {curve}")

            # 创建并返回密钥对
            return KeyPair(ECCKey(public_key, "public"), ECCKey(private_key, "private"))
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")

    @staticmethod
    def load_public_key(
        key_data: Union[bytes, str, BinaryIO], format: str = "pem"
    ) -> AsymmetricKey:
        """
        加载公钥

        Args:
            key_data: 密钥数据
            format: 格式 ('pem', 'der', 'openssh', 'xml')

        Returns:
            公钥对象
        """
        try:
            if isinstance(key_data, str):
                if format.lower() == "xml":
                    # 解析XML格式
                    root = ET.fromstring(key_data)
                    curve_name = root.find("Curve").text
                    x_b64 = root.find("X").text
                    y_b64 = root.find("Y").text

                    # 解码坐标
                    x_bytes = base64.b64decode(x_b64)
                    y_bytes = base64.b64decode(y_b64)

                    x = int.from_bytes(x_bytes, byteorder="big")
                    y = int.from_bytes(y_bytes, byteorder="big")

                    # 获取曲线
                    if curve_name not in _ECC_CURVES:
                        raise ValueError(f"不支持的曲线: {curve_name}")
                    curve = _ECC_CURVES[curve_name]

                    # 创建公钥
                    public_numbers = ec.EllipticCurvePublicNumbers(
                        x=x, y=y, curve=curve
                    )
                    key_obj = public_numbers.public_key(default_backend())
                    return ECCKey(key_obj, "public")
                else:
                    key_data = key_data.encode("utf-8")
            elif hasattr(key_data, "read"):  # 如果是文件对象
                key_data = key_data.read()
                if isinstance(key_data, str):
                    key_data = key_data.encode("utf-8")

            if format.lower() == "pem":
                key_obj = serialization.load_pem_public_key(
                    key_data, backend=default_backend()
                )
            elif format.lower() == "der":
                key_obj = serialization.load_der_public_key(
                    key_data, backend=default_backend()
                )
            elif format.lower() == "openssh":
                key_obj = serialization.load_ssh_public_key(
                    key_data, backend=default_backend()
                )
            else:
                raise ValueError(f"不支持的格式: {format}")

            # 验证密钥类型
            if not isinstance(key_obj, ec.EllipticCurvePublicKey):
                raise ValueError("提供的密钥不是有效的椭圆曲线公钥")

            return ECCKey(key_obj, "public")

        except Exception as e:
            logger.error(f"加载公钥失败: {e}")
            raise ValueError(f"加载公钥失败: {e}")

    @staticmethod
    def load_private_key(
        key_data: Union[bytes, str, BinaryIO],
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> AsymmetricKey:
        """
        加载私钥

        Args:
            key_data: 密钥数据
            format: 格式 ('pem', 'der', 'openssh', 'xml')
            password: 密码 (如果有)

        Returns:
            私钥对象
        """
        try:
            if isinstance(key_data, str):
                if format.lower() == "xml":
                    # 解析XML格式
                    root = ET.fromstring(key_data)
                    curve_name = root.find("Curve").text
                    d_b64 = root.find("D").text
                    x_b64 = root.find("X").text
                    y_b64 = root.find("Y").text

                    # 解码私钥和坐标
                    d_bytes = base64.b64decode(d_b64)
                    x_bytes = base64.b64decode(x_b64)
                    y_bytes = base64.b64decode(y_b64)

                    d = int.from_bytes(d_bytes, byteorder="big")
                    x = int.from_bytes(x_bytes, byteorder="big")
                    y = int.from_bytes(y_bytes, byteorder="big")

                    # 获取曲线
                    if curve_name not in _ECC_CURVES:
                        raise ValueError(f"不支持的曲线: {curve_name}")
                    curve = _ECC_CURVES[curve_name]

                    # 创建私钥
                    public_numbers = ec.EllipticCurvePublicNumbers(
                        x=x, y=y, curve=curve
                    )
                    private_numbers = ec.EllipticCurvePrivateNumbers(
                        private_value=d, public_numbers=public_numbers
                    )
                    key_obj = private_numbers.private_key(default_backend())
                    return ECCKey(key_obj, "private")
                else:
                    key_data = key_data.encode("utf-8")
            elif hasattr(key_data, "read"):  # 如果是文件对象
                key_data = key_data.read()
                if isinstance(key_data, str):
                    key_data = key_data.encode("utf-8")

            if format.lower() == "pem":
                key_obj = serialization.load_pem_private_key(
                    key_data, password=password, backend=default_backend()
                )
            elif format.lower() == "der":
                key_obj = serialization.load_der_private_key(
                    key_data, password=password, backend=default_backend()
                )
            elif format.lower() == "openssh":
                key_obj = serialization.load_ssh_private_key(
                    key_data, password=password, backend=default_backend()
                )
            else:
                raise ValueError(f"不支持的格式: {format}")

            # 验证密钥类型
            if not isinstance(key_obj, ec.EllipticCurvePrivateKey):
                raise ValueError("提供的密钥不是有效的椭圆曲线私钥")

            return ECCKey(key_obj, "private")

        except Exception as e:
            logger.error(f"加载私钥失败: {e}")
            raise ValueError(f"加载私钥失败: {e}")
