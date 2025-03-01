from typing import Union, Tuple, Optional, Literal
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from .base import SignatureBase


class RSASignature(SignatureBase):
    """RSA 签名实现类，支持 PKCS#1 v1.5 和 PSS 两种填充方式"""

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
        padding_mode: Literal["pkcs1v15", "pss"] = "pkcs1v15",
        pss_salt_length: int = 32,
        **kwargs
    ) -> bytes:
        """使用 RSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: RSA 私钥或私钥字节数据
            password: 私钥密码（如果私钥是字节数据且已加密）
            padding_mode: 填充模式，可选 "pkcs1v15"（传统RSA）或 "pss"（RSA-PSS）
            pss_salt_length: PSS 模式的盐长度，仅在 padding_mode="pss" 时使用

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

        # 根据填充模式选择不同的填充算法
        if padding_mode == "pss":
            padding_algorithm = padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm),
                salt_length=pss_salt_length,
            )
        else:  # 默认使用 pkcs1v15
            padding_algorithm = padding.PKCS1v15()

        # 执行签名
        signature = private_key.sign(
            data,
            padding_algorithm,
            self.hash_algorithm,
        )
        return signature

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        padding_mode: Literal["pkcs1v15", "pss"] = "pkcs1v15",
        pss_salt_length: int = 32,
        **kwargs
    ) -> bool:
        """使用 RSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥或公钥字节数据
            padding_mode: 填充模式，可选 "pkcs1v15"（传统RSA）或 "pss"（RSA-PSS）
            pss_salt_length: PSS 模式的盐长度，仅在 padding_mode="pss" 时使用

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 如果 public_key 是字节数据，则加载它
        if isinstance(public_key, bytes):
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            public_key = load_pem_public_key(public_key)

        # 根据填充模式选择不同的填充算法
        if padding_mode == "pss":
            padding_algorithm = padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm),
                salt_length=pss_salt_length,
            )
        else:  # 默认使用 pkcs1v15
            padding_algorithm = padding.PKCS1v15()

        try:
            public_key.verify(
                signature,
                data,
                padding_algorithm,
                self.hash_algorithm,
            )
            return True
        except InvalidSignature:
            return False

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

    def load_public_key(self, path: str):
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


class RSA_PKCS1v15Signature(RSASignature):
    """传统 RSA 签名实现类（使用 PKCS#1 v1.5 填充）"""

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        **kwargs
    ) -> bytes:
        """使用传统 RSA 签名（PKCS#1 v1.5 填充）

        Args:
            data: 要签名的数据
            private_key: RSA 私钥或私钥字节数据
            password: 私钥密码（如果私钥是字节数据且已加密）

        Returns:
            bytes: 签名结果
        """
        return super().sign(
            data=data,
            private_key=private_key,
            password=password,
            padding_mode="pkcs1v15",
            **kwargs
        )

    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用传统 RSA 验证签名（PKCS#1 v1.5 填充）

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥或公钥字节数据

        Returns:
            bool: 验证是否通过
        """
        return super().verify(
            data=data,
            signature=signature,
            public_key=public_key,
            padding_mode="pkcs1v15",
            **kwargs
        )


class RSA_PSSSignature(RSASignature):
    """RSA-PSS 签名实现类"""

    def __init__(self, hash_algorithm=hashes.SHA256(), salt_length: int = 32):
        """初始化 RSA-PSS 签名类

        Args:
            hash_algorithm: 哈希算法，默认为 SHA256
            salt_length: PSS 盐长度，默认为 32 字节
        """
        super().__init__(hash_algorithm=hash_algorithm)
        self.salt_length = salt_length

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        **kwargs
    ) -> bytes:
        """使用 RSA-PSS 签名

        Args:
            data: 要签名的数据
            private_key: RSA 私钥或私钥字节数据
            password: 私钥密码（如果私钥是字节数据且已加密）

        Returns:
            bytes: 签名结果
        """
        return super().sign(
            data=data,
            private_key=private_key,
            password=password,
            padding_mode="pss",
            pss_salt_length=self.salt_length,
            **kwargs
        )

    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用 RSA-PSS 验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥或公钥字节数据

        Returns:
            bool: 验证是否通过
        """
        return super().verify(
            data=data,
            signature=signature,
            public_key=public_key,
            padding_mode="pss",
            pss_salt_length=self.salt_length,
            **kwargs
        )
