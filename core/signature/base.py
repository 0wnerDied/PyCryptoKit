from abc import ABC, abstractmethod
from typing import Any, Dict, Union


class SignatureBase(ABC):
    """数字签名基类, 定义所有签名算法的通用接口"""

    @abstractmethod
    def sign(self, data: Union[bytes, str], private_key, **kwargs) -> bytes:
        """使用私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: 私钥
            **kwargs: 其他算法特定参数, 如哈希算法

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
            **kwargs: 其他算法特定参数, 如哈希算法

        Returns:
            bool: 验证是否通过
        """
        pass

    @abstractmethod
    def load_private_key(self, path: str, **kwargs):
        """从文件加载私钥

        Args:
            path: 私钥文件路径
            **kwargs: 其他参数, 如密码

        Returns:
            私钥对象
        """
        pass

    @abstractmethod
    def load_public_key(self, path: str, **kwargs):
        """从文件加载公钥

        Args:
            path: 公钥文件路径
            **kwargs: 其他参数

        Returns:
            公钥对象
        """
        pass

    @abstractmethod
    def set_hash_algorithm(self, hash_algorithm: Any) -> None:
        """设置哈希算法

        Args:
            hash_algorithm: 哈希算法对象或算法名称
        """
        pass

    @abstractmethod
    def get_supported_key_sizes(self) -> Dict[str, int]:
        """获取支持的密钥长度

        Returns:
            Dict[str, int]: 密钥长度名称和对应的位数, 如 {"最小": 1024, "默认": 2048, "最大": 4096}
        """
        pass

    @abstractmethod
    def get_supported_hash_algorithms(self) -> Dict[str, Any]:
        """获取支持的哈希算法

        Returns:
            Dict[str, Any]: 哈希算法名称和对应的算法对象
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
