from Crypto.Cipher import Salsa20
from typing import Union, Optional
import os

from .base import SymmetricCipher


class Salsa20Cipher(SymmetricCipher):
    """Salsa20 加密实现类"""

    def __init__(self):
        """
        初始化 Salsa20 加密器
        """
        self.key_length = 32  # Salsa20 使用 256 位密钥 (32 字节)
        self.nonce_length = 8  # Salsa20 使用 8 字节 nonce

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        nonce: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        Salsa20 加密

        Args:
            plaintext: 明文
            key: 密钥 (32 字节，也支持 16 字节)
            nonce: 随机数 (8 字节)，如果为 None，则自动生成
            **kwargs: 额外参数

        Returns:
            bytes: 加密后的密文 (nonce + ciphertext)
        """
        # 处理输入
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # 处理密钥 (Salsa20 支持 16 或 32 字节密钥)
        if isinstance(key, str):
            key = key.encode("utf-8")

        # 调整密钥长度为 16 或 32 字节
        if len(key) <= 16:
            key = key.ljust(16, b"\0")[:16]  # 16 字节密钥
        else:
            key = key.ljust(32, b"\0")[:32]  # 32 字节密钥

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
            # 创建 Salsa20 加密器
            cipher = Salsa20.new(key=key, nonce=nonce)

            # 加密数据
            ciphertext = cipher.encrypt(plaintext)

            return ciphertext

        except ValueError as e:
            raise ValueError(f"Salsa20 加密参数错误: {str(e)}")
        except TypeError as e:
            raise TypeError(f"Salsa20 加密类型错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Salsa20 加密未知错误: {str(e)}")

    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        nonce: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        Salsa20 解密

        Args:
            ciphertext: 密文
            key: 密钥 (32 字节，也支持 16 字节)
            nonce: 随机数 (如果已包含在密文中则可为 None)
            **kwargs: 额外参数

        Returns:
            bytes: 解密后的明文
        """
        # 处理密钥 (Salsa20 支持 16 或 32 字节密钥)
        if isinstance(key, str):
            key = key.encode("utf-8")

        # 调整密钥长度为 16 或 32 字节
        if len(key) <= 16:
            key = key.ljust(16, b"\0")[:16]  # 16 字节密钥
        else:
            key = key.ljust(32, b"\0")[:32]  # 32 字节密钥

        try:
            # 处理 nonce
            if nonce is None:
                # 从密文中提取 nonce
                if len(ciphertext) <= self.nonce_length:
                    raise ValueError(
                        f"密文长度不足，无法提取 {self.nonce_length} 字节的 nonce"
                    )

                nonce = ciphertext[: self.nonce_length]
                ciphertext = ciphertext[self.nonce_length :]
            elif isinstance(nonce, str):
                nonce = nonce.encode("utf-8")
                nonce = nonce[: self.nonce_length].ljust(self.nonce_length, b"\0")

            # 创建 Salsa20 解密器
            cipher = Salsa20.new(key=key, nonce=nonce)

            # 解密数据 (Salsa20 的加密和解密操作相同)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext

        except ValueError as e:
            raise ValueError(f"Salsa20 解密参数错误: {str(e)}")
        except TypeError as e:
            raise TypeError(f"Salsa20 解密类型错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Salsa20 解密未知错误: {str(e)}")
