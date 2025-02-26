from abc import ABC, abstractmethod
from typing import Union, Tuple


class SignatureBase(ABC):
    """数字签名基类，定义所有签名算法的通用接口"""

    @abstractmethod
    def generate_key_pair(self, **kwargs) -> Tuple:
        """生成密钥对

        Returns:
            Tuple: (私钥, 公钥)
        """
        pass

    @abstractmethod
    def sign(self, data: Union[bytes, str], private_key, **kwargs) -> bytes:
        """使用私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: 私钥

        Returns:
            bytes: 签名结果
        """
        pass

    @abstractmethod
    def verify(
        self, data: Union[bytes, str], signature: bytes, public_key, **kwargs
    ) -> bool:
        """使用公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: 公钥

        Returns:
            bool: 验证是否通过
        """
        pass

    @abstractmethod
    def save_key_pair(
        self, private_key, public_key, private_path: str, public_path: str, **kwargs
    ) -> Tuple[str, str]:
        """保存密钥对到文件

        Args:
            private_key: 私钥
            public_key: 公钥
            private_path: 私钥保存路径
            public_path: 公钥保存路径

        Returns:
            Tuple[str, str]: 保存的私钥和公钥路径
        """
        pass

    @abstractmethod
    def load_private_key(self, path: str, **kwargs):
        """从文件加载私钥

        Args:
            path: 私钥文件路径

        Returns:
            私钥对象
        """
        pass

    @abstractmethod
    def load_public_key(self, path: str, **kwargs):
        """从文件加载公钥

        Args:
            path: 公钥文件路径

        Returns:
            公钥对象
        """
        pass

    def _ensure_bytes(self, data: Union[bytes, str]) -> bytes:
        """确保数据为字节类型

        Args:
            data: 输入数据

        Returns:
            bytes: 字节类型数据
        """
        if isinstance(data, str):
            return data.encode("utf-8")
        return data
