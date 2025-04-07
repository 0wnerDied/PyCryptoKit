"""
Edwards曲线加密模块
提供Edwards曲线(Ed25519, Ed448)密钥对生成功能
"""

import logging
import xml.etree.ElementTree as ET
import base64
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)

# 支持的Edwards曲线类型
_EDWARDS_CURVES = {"Ed25519": "ed25519", "Ed448": "ed448"}


class EdwardsKey(AsymmetricKey):
    """Edwards曲线密钥类, 包装Cryptography库的Edwards曲线密钥"""

    def __init__(
        self, key_data, key_type: str, curve_type: str, password: Optional[bytes] = None
    ):
        super().__init__(key_data, key_type, Edwards.algorithm_name())
        # 存储曲线信息
        self.curve_type = curve_type
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
        root = ET.Element("EdwardsKeyValue")

        # 添加曲线信息
        curve_elem = ET.SubElement(root, "Curve")
        curve_elem.text = self.curve_type

        if self.key_type == "public":
            # 获取公钥字节
            public_bytes = self.key_data.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # 添加公钥数据
            public_elem = ET.SubElement(root, "PublicKey")
            public_elem.text = base64.b64encode(public_bytes).decode("utf-8")

        else:
            # 获取私钥字节
            private_bytes = self.key_data.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # 添加私钥数据
            private_elem = ET.SubElement(root, "PrivateKey")
            private_elem.text = base64.b64encode(private_bytes).decode("utf-8")

            # 获取公钥
            public_key = self.key_data.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # 添加公钥数据
            public_elem = ET.SubElement(root, "PublicKey")
            public_elem.text = base64.b64encode(public_bytes).decode("utf-8")

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


class Edwards(AsymmetricCipher):
    """Edwards曲线加密算法实现, 包装Cryptography库"""

    @staticmethod
    def algorithm_name() -> str:
        return "Edwards"

    @staticmethod
    def supported_curves() -> List[str]:
        """返回支持的Edwards曲线列表"""
        global _EDWARDS_CURVES
        return list(_EDWARDS_CURVES.keys())

    @staticmethod
    def get_supported_key_sizes() -> List[str]:
        """获取支持的密钥大小列表 (对于Edwards曲线, 返回支持的曲线名称)"""
        return Edwards.supported_curves()

    @staticmethod
    def generate_key_pair(curve: str = "Ed25519", **kwargs) -> KeyPair:
        """
        生成Edwards曲线密钥对

        Args:
            curve: Edwards曲线类型, 默认为Ed25519
            **kwargs: 其他参数
                - password: 私钥加密密码 (可选)

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        global _EDWARDS_CURVES
        try:
            # 验证曲线类型
            if curve not in _EDWARDS_CURVES:
                raise ValueError(
                    f"不支持的曲线类型: {curve}, 支持的类型: {', '.join(_EDWARDS_CURVES.keys())}"
                )

            # 获取密码
            password = kwargs.get("password")

            # 根据曲线类型生成密钥对
            if curve == "Ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
                public_key = private_key.public_key()
            elif curve == "Ed448":
                private_key = ed448.Ed448PrivateKey.generate()
                public_key = private_key.public_key()
            else:
                raise ValueError(f"不支持的曲线类型: {curve}")

            logger.info(f"成功生成Edwards曲线密钥对, 使用曲线: {curve}")

            # 创建并返回密钥对，将密码传递给私钥
            return KeyPair(
                EdwardsKey(public_key, "public", curve),
                EdwardsKey(private_key, "private", curve, password),
            )
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")
