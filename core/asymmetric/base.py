"""
非对称加密基础模块
提供非对称加密的基础类和接口
"""

import abc
from typing import Optional


class AsymmetricKey:
    """非对称密钥基类"""

    def __init__(self, key_data, key_type: str, algorithm: str):
        """
        初始化非对称密钥

        Args:
            key_data: 密钥数据
            key_type: 密钥类型 ('public' 或 'private')
            algorithm: 算法名称
        """
        self.key_data = key_data
        self.key_type = key_type
        self.algorithm = algorithm

    @abc.abstractmethod
    def to_pem(self) -> bytes:
        """将密钥转换为PEM格式"""
        pass

    @abc.abstractmethod
    def to_der(self) -> bytes:
        """将密钥转换为DER格式"""
        pass

    @abc.abstractmethod
    def to_openssh(self) -> bytes:
        """将密钥转换为OpenSSH格式"""
        pass

    @abc.abstractmethod
    def to_xml(self) -> str:
        """将密钥转换为XML格式"""
        pass

    @abc.abstractmethod
    def save_to_file(
        self, filepath: str, format: str = "pem", password: Optional[bytes] = None
    ) -> None:
        """
        将密钥保存到文件

        Args:
            filepath: 文件路径
            format: 文件格式 ('pem', 'der', 'openssh', 'xml')
            password: 加密密码 (仅适用于私钥)
        """
        pass


class KeyPair:
    """密钥对类, 包含公钥和私钥"""

    def __init__(self, public_key: AsymmetricKey, private_key: AsymmetricKey):
        """
        初始化密钥对

        Args:
            public_key: 公钥
            private_key: 私钥
        """
        self.public_key = public_key
        self.private_key = private_key

    def save_to_files(
        self,
        private_key_path: str,
        public_key_path: str,
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> None:
        """
        将密钥对保存到文件

        Args:
            private_key_path: 私钥文件路径
            public_key_path: 公钥文件路径
            format: 文件格式 ('pem', 'der', 'openssh', 'xml')
            password: 私钥加密密码
        """
        self.private_key.save_to_file(private_key_path, format, password)
        self.public_key.save_to_file(public_key_path, format)


class AsymmetricCipher(abc.ABC):
    """非对称加密算法基类"""

    @staticmethod
    @abc.abstractmethod
    def algorithm_name() -> str:
        """返回算法名称"""
        pass

    @staticmethod
    @abc.abstractmethod
    def generate_key_pair(**kwargs) -> KeyPair:
        """
        生成密钥对

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        pass

    @staticmethod
    @abc.abstractmethod
    def get_supported_key_sizes() -> list:
        """
        获取支持的密钥大小列表

        Returns:
            支持的密钥大小列表
        """
        pass
