from typing import Union, Tuple, Optional
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from .base import SignatureBase


class RSASignature(SignatureBase):
    """RSA 签名实现类"""

    def __init__(self, hash_algorithm=hashes.SHA256()):
        """初始化 RSA 签名类

        Args:
            hash_algorithm: 哈希算法，默认为 SHA256
        """
        self.hash_algorithm = hash_algorithm

    def generate_key_pair(self, key_size: int = 2048) -> Tuple:
        """生成 RSA 密钥对

        Args:
            key_size: 密钥大小，默认 2048 位

        Returns:
            Tuple: (私钥, 公钥)
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        **kwargs
    ) -> bytes:
        """使用 RSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: RSA 私钥或私钥字节数据
            password: 私钥密码（如果私钥是字节数据且已加密）

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 如果 private_key 是字节数据，则加载它
        if isinstance(private_key, bytes):
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )

            private_key = load_pem_private_key(private_key, password=password)

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            self.hash_algorithm,
        )
        return signature

    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用 RSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self.hash_algorithm,
            )
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
        """保存 RSA 密钥对到文件

        Args:
            private_key: RSA 私钥
            public_key: RSA 公钥
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
        """从文件加载 RSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码，如果有加密

        Returns:
            RSA 私钥对象
        """
        with open(path, "rb") as f:
            private_bytes = f.read()

        private_key = serialization.load_pem_private_key(
            private_bytes, password=password
        )
        return private_key

    def load_public_key(self, path: str, **kwargs):
        """从文件加载 RSA 公钥

        Args:
            path: 公钥文件路径

        Returns:
            RSA 公钥对象
        """
        with open(path, "rb") as f:
            public_bytes = f.read()

        public_key = serialization.load_pem_public_key(public_bytes)
        return public_key
