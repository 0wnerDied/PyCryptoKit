from typing import Dict, Type, Optional, Union, BinaryIO, List
from .base import AsymmetricCipher, AsymmetricKey, KeyPair

_ALGORITHMS: Dict[str, Type[AsymmetricCipher]] = {}
_DEFAULT_ALGORITHM = None


class AsymmetricCipherFactory:
    """非对称加密算法工厂类"""

    @staticmethod
    def register_algorithm(
        algorithm_class: Type[AsymmetricCipher], set_default: bool = False
    ) -> None:
        """
        注册加密算法

        Args:
            algorithm_class: 算法类
            set_default: 是否设为默认算法
        """
        global _ALGORITHMS, _DEFAULT_ALGORITHM
        algorithm_name = algorithm_class.algorithm_name()
        _ALGORITHMS[algorithm_name] = algorithm_class

        if set_default or _DEFAULT_ALGORITHM is None:
            _DEFAULT_ALGORITHM = algorithm_name

    @staticmethod
    def get_algorithm(name: Optional[str] = None) -> Type[AsymmetricCipher]:
        """
        获取指定名称的加密算法

        Args:
            name: 算法名称, 如果为None则返回默认算法

        Returns:
            算法类
        """
        global _ALGORITHMS, _DEFAULT_ALGORITHM
        if name is None:
            if _DEFAULT_ALGORITHM is None:
                raise ValueError("No default algorithm set")
            name = _DEFAULT_ALGORITHM

        if name not in _ALGORITHMS:
            raise ValueError(f"Algorithm '{name}' is not registered")
        return _ALGORITHMS[name]

    @staticmethod
    def list_algorithms() -> list:
        """列出所有已注册的算法"""
        global _ALGORITHMS
        return list(_ALGORITHMS.keys())

    @staticmethod
    def get_supported_key_sizes(algorithm: Optional[str] = None) -> List:
        """
        获取指定算法支持的密钥大小列表

        Args:
            algorithm: 算法名称, 如果为None则使用默认算法

        Returns:
            支持的密钥大小列表
        """
        cipher = AsymmetricCipherFactory.get_algorithm(algorithm)
        return cipher.get_supported_key_sizes()

    @staticmethod
    def create_key_pair(algorithm: Optional[str] = None, **kwargs) -> KeyPair:
        """
        使用指定算法创建密钥对

        Args:
            algorithm: 算法名称, 如果为None则使用默认算法
            **kwargs: 算法特定参数, 如 key_size, curve 等

        Returns:
            密钥对
        """
        cipher = AsymmetricCipherFactory.get_algorithm(algorithm)
        return cipher.generate_key_pair(**kwargs)

    @staticmethod
    def load_public_key(
        key_data: Union[bytes, str, BinaryIO],
        algorithm: Optional[str] = None,
        format: str = "pem",
    ) -> AsymmetricKey:
        """
        加载公钥

        Args:
            key_data: 密钥数据
            algorithm: 算法名称
            format: 格式('pem', 'der', 'openssh', 'xml')

        Returns:
            公钥对象
        """
        cipher = AsymmetricCipherFactory.get_algorithm(algorithm)
        return cipher.load_public_key(key_data, format)

    @staticmethod
    def load_private_key(
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
            format: 格式('pem', 'der', 'openssh', 'xml')
            password: 密码(如果有)

        Returns:
            私钥对象
        """
        cipher = AsymmetricCipherFactory.get_algorithm(algorithm)
        return cipher.load_private_key(key_data, format, password)

    @staticmethod
    def save_key_to_file(
        key: AsymmetricKey,
        filepath: str,
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> None:
        """
        将密钥保存到文件

        Args:
            key: 密钥对象
            filepath: 文件路径
            format: 格式('pem', 'der', 'openssh', 'xml')
            password: 密码(如果有)
        """
        key.save_to_file(filepath, format, password)

    @staticmethod
    def save_key_pair_to_files(
        key_pair: KeyPair,
        private_key_path: str,
        public_key_path: str,
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> None:
        """
        将密钥对保存到文件

        Args:
            key_pair: 密钥对
            private_key_path: 私钥文件路径
            public_key_path: 公钥文件路径
            format: 格式('pem', 'der', 'openssh', 'xml')
            password: 密码(如果有)
        """
        key_pair.save_to_files(private_key_path, public_key_path, format, password)
