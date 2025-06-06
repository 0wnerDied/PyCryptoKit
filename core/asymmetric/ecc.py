"""
ECC (椭圆曲线加密) 模块
提供ECC密钥对生成功能
"""

import logging
import xml.etree.ElementTree as ET
import base64
from typing import Optional, List

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

    def __init__(self, key_data, key_type: str, password: Optional[bytes] = None):
        super().__init__(key_data, key_type, ECC.algorithm_name())
        # 存储曲线信息
        if key_type == "public":
            self.curve = key_data.curve
        else:
            self.curve = key_data.curve
        # 存储密码
        self.password = password

    def to_pem(self) -> bytes:
        """将密钥转换为PEM格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
            if self.password:
                encryption_algorithm = serialization.BestAvailableEncryption(
                    self.password
                )

            return self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

    def to_der(self) -> bytes:
        """将密钥转换为DER格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
            if self.password:
                encryption_algorithm = serialization.BestAvailableEncryption(
                    self.password
                )

            return self.key_data.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

    def to_openssh(self) -> bytes:
        """将密钥转换为OpenSSH格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
            if self.password:
                encryption_algorithm = serialization.BestAvailableEncryption(
                    self.password
                )

            return self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=encryption_algorithm,
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
            # 如果没有提供密码，但密钥对象有密码，则使用密钥对象的密码
            if not password and self.password:
                password = self.password

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
                        format=serialization.PrivateFormat.PKCS8,
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
                        format=serialization.PrivateFormat.PKCS8,
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
            **kwargs: 其他参数
                - password: 私钥加密密码 (可选)

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

            # 获取密码
            password = kwargs.get("password")

            curve_obj = _ECC_CURVES[curve]

            # 生成私钥
            private_key = ec.generate_private_key(
                curve=curve_obj, backend=default_backend()
            )

            # 获取公钥
            public_key = private_key.public_key()

            logger.info(f"成功生成ECC密钥对, 使用曲线: {curve}")

            # 创建并返回密钥对，将密码传递给私钥
            return KeyPair(
                ECCKey(public_key, "public"), ECCKey(private_key, "private", password)
            )
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")
