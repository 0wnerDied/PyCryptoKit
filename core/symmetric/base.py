from abc import ABC, abstractmethod
from enum import Enum
from typing import Union, Optional


class Mode(Enum):
    """加密模式枚举"""

    ECB = "ECB"  # 电子密码本模式
    CBC = "CBC"  # 密码块链接模式
    CFB = "CFB"  # 密码反馈模式
    OFB = "OFB"  # 输出反馈模式
    CTR = "CTR"  # 计数器模式
    GCM = "GCM"  # 伽罗瓦/计数器模式


class Padding(Enum):
    """填充方式枚举"""

    PKCS7 = "PKCS7"
    ZERO = "ZERO"
    NONE = "NONE"


class Algorithm(Enum):
    """加密算法枚举"""

    AES = "AES"
    SM4 = "SM4"
    CHACHA20 = "CHACHA20"
    SALSA20 = "SALSA20"


class SymmetricCipher(ABC):
    """对称加密基类"""

    @abstractmethod
    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        **kwargs
    ) -> bytes:
        """
        加密数据

        Args:
            plaintext: 明文，字符串或字节
            key: 密钥，字符串或字节
            iv: 初始向量，字符串或字节（部分模式需要）
            **kwargs: 其他参数

        Returns:
            bytes: 加密后的密文
        """
        pass

    @abstractmethod
    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        **kwargs
    ) -> bytes:
        """
        解密数据

        Args:
            ciphertext: 密文
            key: 密钥，字符串或字节
            iv: 初始向量，字符串或字节（部分模式需要）
            **kwargs: 其他参数

        Returns:
            bytes: 解密后的明文
        """
        pass

    @staticmethod
    def normalize_key(key: Union[str, bytes], required_length: int) -> bytes:
        """
        标准化密钥格式和长度

        Args:
            key: 输入的密钥
            required_length: 需要的密钥长度(字节)

        Returns:
            bytes: 处理后的密钥
        """
        if isinstance(key, str):
            key = key.encode("utf-8")

        # 如果密钥长度正确，直接返回
        if len(key) == required_length:
            return key

        # 如果密钥过长，截断
        if len(key) > required_length:
            return key[:required_length]

        # 如果密钥过短，重复使用密钥直到达到所需长度
        return (key * (required_length // len(key) + 1))[:required_length]
