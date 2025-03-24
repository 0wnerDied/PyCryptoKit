from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from typing import Dict, Optional, Tuple, Union, Any

from .base import SignatureBase


class EdDSASignature(SignatureBase):
    """EdDSA 签名实现类 (支持 Ed25519 和 Ed448 算法)"""

    # 支持的曲线
    SUPPORTED_CURVES = {"Ed25519", "Ed448"}
    DEFAULT_CURVE = "Ed25519"

    def __init__(self, curve: str = "Ed25519"):
        """初始化 EdDSA 签名类

        Args:
            curve: 曲线类型, 可选 "Ed25519" (默认) 或 "Ed448"
        """
        if curve not in self.SUPPORTED_CURVES:
            raise ValueError(f"曲线类型必须是 {' 或 '.join(self.SUPPORTED_CURVES)}")
        self.curve = curve
        self.context = b""  # RFC8032 上下文, 默认为空

    def set_context(self, context: bytes) -> None:
        """设置签名上下文

        Args:
            context: 最多 255 字节的上下文数据, 用于区分不同协议或应用
        """
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")
        self.context = context

    def set_hash_algorithm(self, hash_algorithm: Any) -> None:
        """设置哈希算法

        EdDSA 使用固定的哈希算法 (Ed25519 使用 SHA-512, Ed448 使用 SHAKE256)

        Args:
            hash_algorithm: 哈希算法对象或算法名称

        Raises:
            NotImplementedError: EdDSA 使用固定的哈希算法, 不能更改
        """
        raise NotImplementedError("EdDSA 使用固定的哈希算法, 不能更改")

    def set_curve(self, curve: str) -> None:
        """设置曲线类型

        Args:
            curve: 曲线类型, "Ed25519" 或 "Ed448"

        Raises:
            ValueError: 如果曲线类型不受支持
        """
        if curve not in self.SUPPORTED_CURVES:
            raise ValueError(f"曲线类型必须是 {' 或 '.join(self.SUPPORTED_CURVES)}")
        self.curve = curve

    def get_supported_key_sizes(self) -> Dict[str, Any]:
        """获取支持的密钥长度

        注意: EdDSA密钥长度由曲线决定, 不能直接指定

        Returns:
            Dict[str, Any]: 密钥长度名称和对应的位数
        """
        return {
            "注意": "EdDSA密钥长度由曲线决定, 不能直接指定",
            "Ed25519": 256,  # 实际密钥长度为32字节(256位)
            "Ed448": 448,  # 实际密钥长度为57字节(456位)
            "支持的曲线": list(self.SUPPORTED_CURVES),
        }

    def get_supported_hash_algorithms(self) -> Dict[str, Any]:
        """获取支持的哈希算法

        Returns:
            Dict[str, Any]: 哈希算法名称和对应的算法对象
        """
        return {
            "注意": "EdDSA 使用固定的哈希算法",
            "Ed25519": "SHA-512",
            "Ed448": "SHAKE256",
        }

    def generate_key_pair(self, key_size: Optional[int] = None, **kwargs) -> Tuple:
        """生成 EdDSA 密钥对

        Args:
            key_size: 密钥长度(位), 对于EdDSA此参数被忽略, 密钥长度由曲线决定
            **kwargs: 其他参数, 可以包含'curve'来指定曲线

        Returns:
            Tuple: (私钥, 公钥)
        """
        # 检查是否提供了curve参数
        if "curve" in kwargs:
            curve = kwargs["curve"]
            if curve not in self.SUPPORTED_CURVES:
                raise ValueError(f"曲线类型必须是 {' 或 '.join(self.SUPPORTED_CURVES)}")
        else:
            curve = self.curve

        key = ECC.generate(curve=curve)
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
            password: 私钥密码 (如果私钥是 PEM 格式且已加密)
            **kwargs: 其他参数, 可以包含'context'来指定上下文

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 检查是否提供了context参数
        context = kwargs.get("context", self.context)
        if isinstance(context, str):
            context = context.encode("utf-8")
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")

        # 如果 private_key 是字节数据, 则加载它
        if isinstance(private_key, bytes):
            private_key = ECC.import_key(private_key, passphrase=password)

        # 创建签名对象并签名
        signer = eddsa.new(private_key, mode="rfc8032", context=context)
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
            **kwargs: 其他参数, 可以包含'context'来指定上下文

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 检查是否提供了context参数
        context = kwargs.get("context", self.context)
        if isinstance(context, str):
            context = context.encode("utf-8")
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")

        # 如果 public_key 是字节数据, 则加载它
        if isinstance(public_key, bytes):
            public_key = ECC.import_key(public_key)

        # 创建验证对象并验证
        verifier = eddsa.new(public_key, mode="rfc8032", context=context)
        try:
            verifier.verify(data, signature)
            return True
        except ValueError:
            return False

    def load_private_key(self, path: str, password: Optional[bytes] = None):
        """从文件加载 EdDSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码, 如果有加密

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

    def import_private_key_raw(self, key_data: bytes):
        """从原始字节导入私钥 (RFC8032)

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
        """从原始字节导入公钥 (RFC8032)

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
            data: 输入数据, 可以是字符串或字节

        Returns:
            bytes: 字节类型的数据
        """
        if isinstance(data, str):
            return data.encode("utf-8")
        return data
