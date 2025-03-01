from Crypto.Cipher import ChaCha20
from typing import Union, Optional
import os

from .base import SymmetricCipher


class ChaCha20Cipher(SymmetricCipher):
    """ChaCha20 加密实现类"""

    def __init__(self):
        """初始化 ChaCha20 加密器"""
        self.key_length = 32  # ChaCha20 使用 256 位密钥 (32 字节)
        self.nonce_length = 12

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        nonce: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        ChaCha20 加密

        Args:
            plaintext: 明文
            key: 密钥 (32 字节)
            nonce: 随机数 (12 字节)
                   如果为 None, 则自动生成
            **kwargs:
                - counter: ChaCha20 初始计数值 (默认为 0)

        Returns:
            bytes: 加密后的密文
        """
        # 处理输入
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        key = self.normalize_key(key, self.key_length)

        # 处理 nonce
        if nonce is None:
            nonce = os.urandom(self.nonce_length)
        elif isinstance(nonce, str):
            nonce = nonce.encode("utf-8")

        # 确保 nonce 长度正确
        if len(nonce) < self.nonce_length:
            nonce = nonce.ljust(self.nonce_length, b"\0")
        else:
            nonce = nonce[: self.nonce_length]

        try:
            # 获取计数器值
            counter = kwargs.get("counter", 0)  # 默认计数器值为 0

            # 在 PyCryptodome 中，counter 参数需要通过 cipher.seek() 设置
            cipher = ChaCha20.new(key=key, nonce=nonce)

            # 如果计数器不是0，使用 seek() 设置位置
            if counter > 0:
                cipher.seek(counter)

            ciphertext = cipher.encrypt(plaintext)

            # 返回密文
            return ciphertext

        except ValueError as e:
            raise ValueError(f"ChaCha20 加密参数错误: {str(e)}")
        except TypeError as e:
            raise TypeError(f"ChaCha20 加密类型错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"ChaCha20 加密未知错误: {str(e)}")

    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        nonce: Union[str, bytes],
        **kwargs,
    ) -> bytes:
        """
        ChaCha20 解密

        Args:
            ciphertext: 密文
            key: 密钥 (32 字节)
            nonce: 随机数 (12 字节)
            **kwargs:
                - counter: ChaCha20 初始计数值 (默认为 0)

        Returns:
            bytes: 解密后的明文
        """
        key = self.normalize_key(key, self.key_length)

        # 处理 nonce
        if isinstance(nonce, str):
            nonce = nonce.encode("utf-8")

        # 确保 nonce 长度正确
        if len(nonce) < self.nonce_length:
            nonce = nonce.ljust(self.nonce_length, b"\0")
        else:
            nonce = nonce[: self.nonce_length]

        try:
            # 获取计数器值
            counter = kwargs.get("counter", 0)  # 默认计数器值为 0

            # 创建解密器
            cipher = ChaCha20.new(key=key, nonce=nonce)

            # 如果计数器不是0，使用 seek() 设置位置
            if counter > 0:
                cipher.seek(counter)

            plaintext = cipher.decrypt(ciphertext)
            return plaintext

        except ValueError as e:
            raise ValueError(f"ChaCha20 解密参数错误: {str(e)}")
        except TypeError as e:
            raise TypeError(f"ChaCha20 解密类型错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"ChaCha20 解密未知错误: {str(e)}")

    def normalize_key(self, key: Union[str, bytes], length: int) -> bytes:
        """标准化密钥长度"""
        if isinstance(key, str):
            key = key.encode("utf-8")

        # 如果密钥长度不足，使用填充；如果过长，则截断
        if len(key) < length:
            return key.ljust(length, b"\0")  # 使用0填充
        return key[:length]  # 截断到指定长度
