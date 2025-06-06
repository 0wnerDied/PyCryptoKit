"""
RSA加密模块
提供RSA密钥对生成功能
"""

import logging
import xml.etree.ElementTree as ET
import base64
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)

# 支持的RSA密钥大小
_RSA_KEY_SIZES = [1024, 2048, 3072, 4096, 8192]


class RSAKey(AsymmetricKey):
    """RSA密钥类, 包装Cryptography库的RSA密钥"""

    def __init__(self, key_data, key_type: str, password: Optional[bytes] = None):
        super().__init__(key_data, key_type, RSA.algorithm_name())
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
        if self.key_type == "public":
            numbers = self.key_data.public_numbers()
            root = ET.Element("RSAKeyValue")
            modulus = ET.SubElement(root, "Modulus")
            modulus.text = base64.b64encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")
            exponent = ET.SubElement(root, "Exponent")
            exponent.text = base64.b64encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")
        else:
            numbers = self.key_data.private_numbers()
            root = ET.Element("RSAKeyValue")
            modulus = ET.SubElement(root, "Modulus")
            modulus.text = base64.b64encode(
                numbers.public_numbers.n.to_bytes(
                    (numbers.public_numbers.n.bit_length() + 7) // 8, byteorder="big"
                )
            ).decode("utf-8")
            exponent = ET.SubElement(root, "Exponent")
            exponent.text = base64.b64encode(
                numbers.public_numbers.e.to_bytes(
                    (numbers.public_numbers.e.bit_length() + 7) // 8, byteorder="big"
                )
            ).decode("utf-8")
            d = ET.SubElement(root, "D")
            d.text = base64.b64encode(
                numbers.d.to_bytes((numbers.d.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")
            p = ET.SubElement(root, "P")
            p.text = base64.b64encode(
                numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")
            q = ET.SubElement(root, "Q")
            q.text = base64.b64encode(
                numbers.q.to_bytes((numbers.q.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")
            dp = ET.SubElement(root, "DP")
            dp.text = base64.b64encode(
                numbers.dmp1.to_bytes(
                    (numbers.dmp1.bit_length() + 7) // 8, byteorder="big"
                )
            ).decode("utf-8")
            dq = ET.SubElement(root, "DQ")
            dq.text = base64.b64encode(
                numbers.dmq1.to_bytes(
                    (numbers.dmq1.bit_length() + 7) // 8, byteorder="big"
                )
            ).decode("utf-8")
            inverse_q = ET.SubElement(root, "InverseQ")
            inverse_q.text = base64.b64encode(
                numbers.iqmp.to_bytes(
                    (numbers.iqmp.bit_length() + 7) // 8, byteorder="big"
                )
            ).decode("utf-8")

        return ET.tostring(root, encoding="unicode")

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
                        # 使用与OpenSSL相同的加密方式
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


class RSA(AsymmetricCipher):
    """RSA加密算法实现, 包装Cryptography库"""

    @staticmethod
    def algorithm_name() -> str:
        return "RSA"

    @staticmethod
    def get_supported_key_sizes() -> List[int]:
        """获取支持的密钥大小列表"""
        return _RSA_KEY_SIZES

    @staticmethod
    def generate_key_pair(key_size: int = 2048, **kwargs) -> KeyPair:
        """
        生成RSA密钥对

        Args:
            key_size: 密钥大小, 默认2048位
            **kwargs: 其他参数
                - public_exponent: 公钥指数, 默认65537
                - password: 私钥加密密码 (可选)

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        try:
            # 验证密钥大小
            if key_size not in _RSA_KEY_SIZES:
                raise ValueError(
                    f"不支持的密钥大小: {key_size}, 支持的大小: {', '.join(map(str, _RSA_KEY_SIZES))}"
                )

            # 获取公钥指数
            public_exponent = kwargs.get("public_exponent", 65537)
            # 获取密码
            password = kwargs.get("password")

            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size,
                backend=default_backend(),
            )

            # 获取公钥
            public_key = private_key.public_key()

            logger.info(f"成功生成RSA密钥对, 密钥大小: {key_size}位")

            # 创建并返回密钥对
            return KeyPair(
                RSAKey(public_key, "public"), RSAKey(private_key, "private", password)
            )
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")
