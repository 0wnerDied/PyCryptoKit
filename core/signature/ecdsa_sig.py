from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Dict, Optional, Tuple, Union, Any

from .base import SignatureBase


class ECDSASignature(SignatureBase):
    """ECDSA 签名实现类"""

    # 支持的椭圆曲线
    SUPPORTED_CURVES = {
        "PRIME192V1": ec.SECP192R1(),
        "PRIME256V1": ec.SECP256R1(),
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
    DEFAULT_CURVE = "SECP256R1"

    # 支持的哈希算法
    SUPPORTED_HASH_ALGORITHMS = {
        "MD5": hashes.MD5(),
        "SHA1": hashes.SHA1(),
        "SHA3_224": hashes.SHA3_224(),
        "SHA3_256": hashes.SHA3_256(),
        "SHA3_384": hashes.SHA3_384(),
        "SHA3_512": hashes.SHA3_512(),
        "SHA224": hashes.SHA224(),
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
        "SHA512_224": hashes.SHA512_224(),
        "SHA512_256": hashes.SHA512_256(),
        "SM3": hashes.SM3(),
    }
    DEFAULT_HASH = "SHA256"

    def __init__(self, curve=None, hash_algorithm=None):
        """初始化 ECDSA 签名类

        Args:
            curve: 椭圆曲线, 默认为 SECP256R1
            hash_algorithm: 哈希算法, 默认为 SHA256
        """
        # 设置曲线
        if curve is None:
            self.curve = self.SUPPORTED_CURVES[self.DEFAULT_CURVE]
        elif isinstance(curve, str):
            curve_name = curve.upper()
            if curve_name in self.SUPPORTED_CURVES:
                self.curve = self.SUPPORTED_CURVES[curve_name]
            else:
                raise ValueError(f"不支持的椭圆曲线: {curve}")
        else:
            # 假设已经是曲线实例
            self.curve = curve

        # 设置哈希算法
        if hash_algorithm is None:
            self.hash_algorithm = self.SUPPORTED_HASH_ALGORITHMS[self.DEFAULT_HASH]
        elif isinstance(hash_algorithm, str):
            hash_name = hash_algorithm.upper()
            if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                self.hash_algorithm = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
            else:
                raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
        else:
            # 假设已经是哈希算法实例
            self.hash_algorithm = hash_algorithm

    def set_hash_algorithm(self, hash_algorithm: Any) -> None:
        """设置哈希算法

        Args:
            hash_algorithm: 哈希算法对象或算法名称
        """
        if isinstance(hash_algorithm, str):
            hash_name = hash_algorithm.upper()
            if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                self.hash_algorithm = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
            else:
                raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
        else:
            # 假设已经是哈希算法实例
            self.hash_algorithm = hash_algorithm

    def set_curve(self, curve: Any) -> None:
        """设置椭圆曲线

        Args:
            curve: 椭圆曲线对象或曲线名称
        """
        if isinstance(curve, str):
            curve_name = curve.upper()
            if curve_name in self.SUPPORTED_CURVES:
                self.curve = self.SUPPORTED_CURVES[curve_name]
            else:
                raise ValueError(f"不支持的椭圆曲线: {curve}")
        else:
            # 假设已经是曲线实例
            self.curve = curve

    def get_supported_key_sizes(self) -> Dict[str, int]:
        """获取支持的密钥长度

        注意: ECDSA密钥长度由曲线决定, 不能直接指定

        Returns:
            Dict[str, int]: 密钥长度名称和对应的位数
        """
        return {
            "注意": "ECDSA密钥长度由曲线决定, 请使用set_curve方法设置曲线",
            "支持的曲线": list(self.SUPPORTED_CURVES.keys()),
        }

    def get_supported_hash_algorithms(self) -> Dict[str, Any]:
        """获取支持的哈希算法

        Returns:
            Dict[str, Any]: 哈希算法名称和对应的算法对象
        """
        return self.SUPPORTED_HASH_ALGORITHMS.copy()

    def generate_key_pair(self, **kwargs) -> Tuple:
        """生成 ECDSA 密钥对

        Args:
            **kwargs: 其他参数, 可以包含'curve'来指定曲线

        Returns:
            Tuple: (私钥, 公钥)
        """
        # 检查是否提供了curve参数
        if "curve" in kwargs:
            curve = kwargs["curve"]
            if isinstance(curve, str):
                curve_name = curve.upper()
                if curve_name in self.SUPPORTED_CURVES:
                    curve = self.SUPPORTED_CURVES[curve_name]
                else:
                    raise ValueError(f"不支持的椭圆曲线: {curve}")
        else:
            curve = self.curve

        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        hash_algorithm: Any = None,
        **kwargs,
    ) -> bytes:
        """使用 ECDSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: ECDSA 私钥或私钥字节数据
            password: 私钥密码 (如果私钥是字节数据且已加密)
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 使用提供的哈希算法或默认值
        hash_alg = self.hash_algorithm
        if hash_algorithm is not None:
            if isinstance(hash_algorithm, str):
                hash_name = hash_algorithm.upper()
                if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                    hash_alg = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
                else:
                    raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
            else:
                hash_alg = hash_algorithm

        # 如果 private_key 是字节数据, 则加载它
        if isinstance(private_key, bytes):
            private_key = serialization.load_pem_private_key(
                private_key, password=password
            )

        signature = private_key.sign(data, ec.ECDSA(hash_alg))
        return signature

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        hash_algorithm: Any = None,
        **kwargs,
    ) -> bool:
        """使用 ECDSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: ECDSA 公钥或公钥字节数据
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 使用提供的哈希算法或默认值
        hash_alg = self.hash_algorithm
        if hash_algorithm is not None:
            if isinstance(hash_algorithm, str):
                hash_name = hash_algorithm.upper()
                if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                    hash_alg = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
                else:
                    raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
            else:
                hash_alg = hash_algorithm

        # 如果 public_key 是字节数据, 则加载它
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key)

        try:
            public_key.verify(signature, data, ec.ECDSA(hash_alg))
            return True
        except InvalidSignature:
            return False

    def load_private_key(self, path: str, password: Optional[bytes] = None):
        """从文件加载 ECDSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码, 如果有加密

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
            data: 输入数据, 可以是字符串或字节

        Returns:
            bytes: 字节类型的数据
        """
        if isinstance(data, str):
            return data.encode("utf-8")
        return data
