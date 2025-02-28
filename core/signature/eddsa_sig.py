from typing import Union, Tuple, Optional
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .base import SignatureBase


class EdDSASignature(SignatureBase):
    """EdDSA 签名实现类（使用 Ed25519 算法）"""

    def __init__(self):
        """初始化 EdDSA 签名类

        注意：与 ECDSA 不同, Ed25519 不需要指定曲线和哈希算法参数
        """
        pass

    def generate_key_pair(self, **kwargs) -> Tuple:
        """生成 EdDSA 密钥对

        Returns:
            Tuple: (私钥, 公钥)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        **kwargs
    ) -> bytes:
        """使用 EdDSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: EdDSA 私钥或私钥字节数据
            password: 私钥密码（如果私钥是字节数据且已加密）

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 如果 private_key 是字节数据，则加载它
        if isinstance(private_key, bytes):
            private_key = serialization.load_pem_private_key(
                private_key, password=password
            )

        signature = private_key.sign(data)
        return signature

    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用 EdDSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: EdDSA 公钥或公钥字节数据

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 如果 public_key 是字节数据，则加载它
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key)

        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def save_key_pair(
        self,
        private_key,
        public_key,
        private_path: str,
        public_path: str,
        password: Optional[bytes] = None,
    ) -> Tuple[str, str]:
        """保存 EdDSA 密钥对到文件

        Args:
            private_key: EdDSA 私钥
            public_key: EdDSA 公钥
            private_path: 私钥保存路径
            public_path: 公钥保存路径
            password: 私钥加密密码，可选

        Returns:
            Tuple[str, str]: 保存的私钥和公钥路径
        """
        # 确保目录存在
        os.makedirs(os.path.dirname(private_path), exist_ok=True)
        os.makedirs(os.path.dirname(public_path), exist_ok=True)

        # 序列化私钥
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        # 序列化公钥
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 写入文件
        with open(private_path, "wb") as f:
            f.write(private_bytes)

        with open(public_path, "wb") as f:
            f.write(public_bytes)

        return private_path, public_path

    def load_private_key(self, path: str, password: Optional[bytes] = None):
        """从文件加载 EdDSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码，如果有加密

        Returns:
            EdDSA 私钥对象
        """
        with open(path, "rb") as f:
            private_bytes = f.read()

        private_key = serialization.load_pem_private_key(
            private_bytes, password=password
        )
        return private_key

    def load_public_key(self, path: str, **kwargs):
        """从文件加载 EdDSA 公钥

        Args:
            path: 公钥文件路径

        Returns:
            EdDSA 公钥对象
        """
        with open(path, "rb") as f:
            public_bytes = f.read()

        public_key = serialization.load_pem_public_key(public_bytes)
        return public_key

    def _ensure_bytes(self, data: Union[bytes, str]) -> bytes:
        """确保数据为字节类型

        Args:
            data: 输入数据，可以是字符串或字节

        Returns:
            bytes: 字节类型的数据
        """
        if isinstance(data, str):
            return data.encode("utf-8")
        return data
