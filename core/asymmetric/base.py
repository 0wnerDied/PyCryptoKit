from abc import ABC, abstractmethod
from typing import Any, Optional, Union, BinaryIO


class AsymmetricKey:
    """非对称密钥基类"""

    def __init__(self, key_data: Any, key_type: str, algorithm: str):
        self.key_data = key_data  # 实际密钥对象(来自底层库)
        self.key_type = key_type  # 'public' 或 'private'
        self.algorithm = algorithm

    def to_bytes(self) -> bytes:
        """将密钥转换为字节格式"""
        # 这个方法应该在子类中实现, 根据具体库的API
        raise NotImplementedError("Must be implemented by subclass")

    def to_pem(self) -> bytes:
        """将密钥转换为PEM格式"""
        # 这个方法应该在子类中实现, 根据具体库的API
        raise NotImplementedError("Must be implemented by subclass")

    @classmethod
    def from_bytes(cls, data: bytes, key_type: str, algorithm: str) -> "AsymmetricKey":
        """从字节创建密钥"""
        # 这个方法应该在子类中实现, 根据具体库的API
        raise NotImplementedError("Must be implemented by subclass")

    @classmethod
    def from_pem(
        cls, pem_data: bytes, key_type: str, algorithm: str
    ) -> "AsymmetricKey":
        """从PEM格式创建密钥"""
        # 这个方法应该在子类中实现, 根据具体库的API
        raise NotImplementedError("Must be implemented by subclass")


class KeyPair:
    """密钥对类"""

    def __init__(self, public_key: AsymmetricKey, private_key: AsymmetricKey):
        if public_key.algorithm != private_key.algorithm:
            raise ValueError("Public and private keys must use the same algorithm")
        self.public_key = public_key
        self.private_key = private_key
        self.algorithm = public_key.algorithm

    def save(self, public_path: str, private_path: str, format: str = "pem") -> None:
        """保存密钥对到文件"""
        if format == "pem":
            with open(public_path, "wb") as f:
                f.write(self.public_key.to_pem())
            with open(private_path, "wb") as f:
                f.write(self.private_key.to_pem())
        elif format == "bytes":
            with open(public_path, "wb") as f:
                f.write(self.public_key.to_bytes())
            with open(private_path, "wb") as f:
                f.write(self.private_key.to_bytes())
        else:
            raise ValueError(f"Unsupported format: {format}")

    @property
    def algorithm_name(self) -> str:
        return self.algorithm


class AsymmetricCipher(ABC):
    """非对称加密算法基类"""

    @classmethod
    @abstractmethod
    def algorithm_name(cls) -> str:
        """返回算法名称"""
        pass

    @classmethod
    @abstractmethod
    def generate_key_pair(cls, key_size: int = 2048, **kwargs) -> KeyPair:
        """生成密钥对"""
        pass

    @classmethod
    @abstractmethod
    def encrypt(cls, data: bytes, public_key: AsymmetricKey) -> bytes:
        """使用公钥加密数据"""
        pass

    @classmethod
    @abstractmethod
    def decrypt(cls, encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
        """使用私钥解密数据"""
        pass

    @classmethod
    @abstractmethod
    def load_public_key(
        cls, key_data: Union[bytes, str, BinaryIO], format: str = "pem"
    ) -> AsymmetricKey:
        """加载公钥"""
        pass

    @classmethod
    @abstractmethod
    def load_private_key(
        cls,
        key_data: Union[bytes, str, BinaryIO],
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> AsymmetricKey:
        """加载私钥"""
        pass

    @classmethod
    def validate_key(cls, key: AsymmetricKey) -> bool:
        """验证密钥是否有效且属于此算法"""
        return key.algorithm == cls.algorithm_name()
