from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Optional, Tuple, Union

from .base import SignatureBase


class ECDSASignature(SignatureBase):
    """ECDSA 签名实现类"""

    def __init__(self, curve=ec.SECP256R1(), hash_algorithm=hashes.SHA256()):
        """初始化 ECDSA 签名类

        Args:
            curve: 椭圆曲线，默认为 SECP256R1
            hash_algorithm: 哈希算法，默认为 SHA256
        """
        self.curve = curve
        self.hash_algorithm = hash_algorithm

    def generate_key_pair(self, **kwargs) -> Tuple:
        """生成 ECDSA 密钥对

        Returns:
            Tuple: (私钥, 公钥)
        """
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        **kwargs
    ) -> bytes:
        """使用 ECDSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: ECDSA 私钥或私钥字节数据
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

        signature = private_key.sign(data, ec.ECDSA(self.hash_algorithm))
        return signature

    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用 ECDSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: ECDSA 公钥或公钥字节数据

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 如果 public_key 是字节数据，则加载它
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key)

        try:
            public_key.verify(signature, data, ec.ECDSA(self.hash_algorithm))
            return True
        except InvalidSignature:
            return False

    def load_private_key(self, path: str, password: Optional[bytes] = None):
        """从文件加载 ECDSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码，如果有加密

        Returns:
            ECDSA 私钥对象
        """
        with open(path, "rb") as f:
            private_bytes = f.read()

        private_key = serialization.load_pem_private_key(
            private_bytes, password=password
        )
        return private_key

    def load_public_key(self, path: str, **kwargs):
        """从文件加载 ECDSA 公钥

        Args:
            path: 公钥文件路径

        Returns:
            ECDSA 公钥对象
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
