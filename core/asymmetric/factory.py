from typing import Dict, Type, Optional, Union, BinaryIO
from .base import AsymmetricCipher, AsymmetricKey, KeyPair


class AsymmetricCipherFactory:
    """非对称加密算法工厂类"""

    _algorithms: Dict[str, Type[AsymmetricCipher]] = {}
    _default_algorithm = None

    @classmethod
    def register_algorithm(
        cls, algorithm_class: Type[AsymmetricCipher], set_default: bool = False
    ) -> None:
        """
        注册加密算法

        Args:
            algorithm_class: 算法类
            set_default: 是否设为默认算法
        """
        algorithm_name = algorithm_class.algorithm_name()
        cls._algorithms[algorithm_name] = algorithm_class

        if set_default or cls._default_algorithm is None:
            cls._default_algorithm = algorithm_name

    @classmethod
    def get_algorithm(cls, name: Optional[str] = None) -> Type[AsymmetricCipher]:
        """
        获取指定名称的加密算法

        Args:
            name: 算法名称，如果为None则返回默认算法

        Returns:
            算法类
        """
        if name is None:
            if cls._default_algorithm is None:
                raise ValueError("No default algorithm set")
            name = cls._default_algorithm

        if name not in cls._algorithms:
            raise ValueError(f"Algorithm '{name}' is not registered")
        return cls._algorithms[name]

    @classmethod
    def list_algorithms(cls) -> list:
        """列出所有已注册的算法"""
        return list(cls._algorithms.keys())

    @classmethod
    def create_key_pair(
        cls, algorithm: Optional[str] = None, key_size: int = 2048, **kwargs
    ) -> KeyPair:
        """
        使用指定算法创建密钥对

        Args:
            algorithm: 算法名称，如果为None则使用默认算法
            key_size: 密钥大小
            **kwargs: 其他参数

        Returns:
            密钥对
        """
        cipher = cls.get_algorithm(algorithm)
        return cipher.generate_key_pair(key_size, **kwargs)

    @classmethod
    def encrypt(cls, data: bytes, public_key: AsymmetricKey) -> bytes:
        """
        使用公钥加密数据

        Args:
            data: 待加密数据
            public_key: 公钥

        Returns:
            加密后的数据
        """
        algorithm = public_key.algorithm
        cipher = cls.get_algorithm(algorithm)
        return cipher.encrypt(data, public_key)

    @classmethod
    def decrypt(cls, encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
        """
        使用私钥解密数据

        Args:
            encrypted_data: 加密数据
            private_key: 私钥

        Returns:
            解密后的数据
        """
        algorithm = private_key.algorithm
        cipher = cls.get_algorithm(algorithm)
        return cipher.decrypt(encrypted_data, private_key)

    @classmethod
    def load_public_key(
        cls,
        key_data: Union[bytes, str, BinaryIO],
        algorithm: Optional[str] = None,
        format: str = "pem",
    ) -> AsymmetricKey:
        """
        加载公钥

        Args:
            key_data: 密钥数据
            algorithm: 算法名称
            format: 格式('pem', 'der', 'bytes')

        Returns:
            公钥对象
        """
        cipher = cls.get_algorithm(algorithm)
        return cipher.load_public_key(key_data, format)

    @classmethod
    def load_private_key(
        cls,
        key_data: Union[bytes, str, BinaryIO],
        algorithm: Optional[str] = None,
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> AsymmetricKey:
        """
        加载私钥

        Args:
            key_data: 密钥数据
            algorithm: 算法名称
            format: 格式('pem', 'der', 'bytes')
            password: 密码(如果有)

        Returns:
            私钥对象
        """
        cipher = cls.get_algorithm(algorithm)
        return cipher.load_private_key(key_data, format, password)
