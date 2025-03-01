from typing import Union, Tuple, Optional
import os
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import eddsa
from Cryptodome.Hash import SHA512, SHAKE256

from .base import SignatureBase


class EdDSASignature(SignatureBase):
    """EdDSA 签名实现类（支持 Ed25519 和 Ed448 算法）"""

    def __init__(self, curve: str = "Ed25519"):
        """初始化 EdDSA 签名类

        Args:
            curve: 曲线类型，可选 "Ed25519"（默认）或 "Ed448"
        """
        if curve not in ("Ed25519", "Ed448"):
            raise ValueError("曲线类型必须是 Ed25519 或 Ed448")
        self.curve = curve
        self.context = b""  # RFC8032 上下文，默认为空

    def set_context(self, context: bytes) -> None:
        """设置签名上下文

        Args:
            context: 最多 255 字节的上下文数据，用于区分不同协议或应用
        """
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")
        self.context = context

    def generate_key_pair(self, **kwargs) -> Tuple:
        """生成 EdDSA 密钥对

        Returns:
            Tuple: (私钥, 公钥)
        """
        key = ECC.generate(curve=self.curve)
        return key, key.public_key()

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        **kwargs,
    ) -> bytes:
        """使用 EdDSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: EdDSA 私钥对象或 PEM 格式的私钥字节数据
            password: 私钥密码（如果私钥是 PEM 格式且已加密）

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 如果 private_key 是字节数据，则加载它
        if isinstance(private_key, bytes):
            private_key = ECC.import_key(private_key, passphrase=password)

        # 创建签名对象并签名
        signer = eddsa.new(private_key, mode="rfc8032", context=self.context)
        signature = signer.sign(data)
        return signature

    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用 EdDSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: EdDSA 公钥对象或 PEM 格式的公钥字节数据

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 如果 public_key 是字节数据，则加载它
        if isinstance(public_key, bytes):
            public_key = ECC.import_key(public_key)

        # 创建验证对象并验证
        verifier = eddsa.new(public_key, mode="rfc8032", context=self.context)
        try:
            verifier.verify(data, signature)
            return True
        except ValueError:
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
        if password:
            private_bytes = private_key.export_key(
                format="PEM",
                passphrase=password,
                protection="PBKDF2WithHMAC-SHA1AndAES256-CBC",
            )
        else:
            private_bytes = private_key.export_key(format="PEM")

        # 序列化公钥
        public_bytes = public_key.export_key(format="PEM")

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

        private_key = ECC.import_key(private_bytes, passphrase=password)

        # 验证曲线类型
        if private_key.curve != self.curve:
            raise ValueError(
                f"导入的密钥曲线类型 {private_key.curve} 与当前设置的 {self.curve} 不匹配"
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

        public_key = ECC.import_key(public_bytes)

        # 验证曲线类型
        if public_key.curve != self.curve:
            raise ValueError(
                f"导入的密钥曲线类型 {public_key.curve} 与当前设置的 {self.curve} 不匹配"
            )

        return public_key

    def export_private_key(
        self, private_key, password: Optional[bytes] = None
    ) -> bytes:
        """导出私钥为 PEM 格式

        Args:
            private_key: EdDSA 私钥对象
            password: 加密密码，可选

        Returns:
            bytes: PEM 格式的私钥
        """
        if password:
            return private_key.export_key(
                format="PEM",
                passphrase=password,
                protection="PBKDF2WithHMAC-SHA1AndAES256-CBC",
            )
        else:
            return private_key.export_key(format="PEM")

    def export_public_key(self, public_key) -> bytes:
        """导出公钥为 PEM 格式

        Args:
            public_key: EdDSA 公钥对象

        Returns:
            bytes: PEM 格式的公钥
        """
        return public_key.export_key(format="PEM")

    def export_private_key_raw(self, private_key) -> bytes:
        """导出私钥为原始字节格式（RFC8032）

        Args:
            private_key: EdDSA 私钥对象

        Returns:
            bytes: 原始格式的私钥
        """
        return private_key.export_key(format="raw")

    def export_public_key_raw(self, public_key) -> bytes:
        """导出公钥为原始字节格式（RFC8032）

        Args:
            public_key: EdDSA 公钥对象

        Returns:
            bytes: 原始格式的公钥
        """
        return public_key.export_key(format="raw")

    def import_private_key_raw(self, key_data: bytes):
        """从原始字节导入私钥（RFC8032）

        Args:
            key_data: 私钥的原始字节
                      Ed25519 为 32 字节
                      Ed448 为 57 字节

        Returns:
            EdDSA 私钥对象
        """
        private_key = eddsa.import_private_key(key_data)

        # 验证曲线类型
        if private_key.curve != self.curve:
            raise ValueError(
                f"导入的密钥曲线类型 {private_key.curve} 与当前设置的 {self.curve} 不匹配"
            )

        return private_key

    def import_public_key_raw(self, key_data: bytes):
        """从原始字节导入公钥（RFC8032）

        Args:
            key_data: 公钥的原始字节
                      Ed25519 为 32 字节
                      Ed448 为 57 字节

        Returns:
            EdDSA 公钥对象
        """
        public_key = eddsa.import_public_key(key_data)

        # 验证曲线类型
        if public_key.curve != self.curve:
            raise ValueError(
                f"导入的密钥曲线类型 {public_key.curve} 与当前设置的 {self.curve} 不匹配"
            )

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
