from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from typing import Union, Optional
import os

from .base import SymmetricCipher


class ChaCha20Cipher(SymmetricCipher):
    """ChaCha20 和 ChaCha20-Poly1305 加密实现类"""

    def __init__(
        self,
        use_poly1305: bool = False,
    ):
        """
        初始化 ChaCha20 加密器

        Args:
            use_poly1305: 是否使用 Poly1305 认证 (ChaCha20-Poly1305)
        """
        self.use_poly1305 = use_poly1305
        self.key_length = 32  # ChaCha20 使用 256 位密钥 (32 字节)
        self.nonce_length = 12 if use_poly1305 else 8  # ChaCha20-Poly1305 使用 12 字节 nonce，普通 ChaCha20 使用 8 字节

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        nonce: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        ChaCha20/ChaCha20-Poly1305 加密

        Args:
            plaintext: 明文
            key: 密钥 (32 字节)
            nonce: 随机数 (ChaCha20: 8 字节, ChaCha20-Poly1305: 12 字节)
                   如果为 None，则自动生成
            **kwargs: 
                - counter: ChaCha20 初始计数值 (默认为 0)
                - associated_data: ChaCha20-Poly1305 的附加认证数据

        Returns:
            bytes: 加密后的密文
                  对于 ChaCha20: nonce (8 bytes) + ciphertext
                  对于 ChaCha20-Poly1305: nonce (12 bytes) + tag (16 bytes) + ciphertext
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
            nonce = nonce[:self.nonce_length]

        try:
            if self.use_poly1305:
                # ChaCha20-Poly1305 模式
                cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                
                # 处理附加认证数据
                associated_data = kwargs.get("associated_data")
                if associated_data is not None:
                    if isinstance(associated_data, str):
                        associated_data = associated_data.encode("utf-8")
                    cipher.update(associated_data)
                
                # 加密并生成认证标签
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                
                # 返回 nonce + tag + ciphertext
                return b"".join([nonce, tag, ciphertext])
            else:
                # 普通 ChaCha20 模式
                counter = kwargs.get("counter", 0)  # 默认计数器值为 0
                cipher = ChaCha20.new(key=key, nonce=nonce, counter=counter)
                ciphertext = cipher.encrypt(plaintext)
                
                # 返回 nonce + ciphertext
                return b"".join([nonce, ciphertext])
                
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
        nonce: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        ChaCha20/ChaCha20-Poly1305 解密

        Args:
            ciphertext: 密文
            key: 密钥 (32 字节)
            nonce: 随机数 (如果已包含在密文中则可为 None)
            **kwargs:
                - counter: ChaCha20 初始计数值 (默认为 0)
                - associated_data: ChaCha20-Poly1305 的附加认证数据

        Returns:
            bytes: 解密后的明文
        """
        key = self.normalize_key(key, self.key_length)

        try:
            if self.use_poly1305:
                # ChaCha20-Poly1305 模式
                min_length = self.nonce_length + 16  # nonce + tag
                if len(ciphertext) < min_length:
                    raise ValueError(f"ChaCha20-Poly1305 密文格式不正确，长度至少为 {min_length} 字节")
                
                if nonce is None:
                    # 从密文中提取 nonce 和 tag
                    nonce = ciphertext[:self.nonce_length]
                    tag = ciphertext[self.nonce_length:self.nonce_length + 16]
                    ciphertext = ciphertext[self.nonce_length + 16:]
                else:
                    # 使用提供的 nonce，从密文中提取 tag
                    if isinstance(nonce, str):
                        nonce = nonce.encode("utf-8")
                        nonce = nonce[:self.nonce_length].ljust(self.nonce_length, b"\0")
                    tag = ciphertext[:16]
                    ciphertext = ciphertext[16:]
                
                cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                
                # 处理附加认证数据
                associated_data = kwargs.get("associated_data")
                if associated_data is not None:
                    if isinstance(associated_data, str):
                        associated_data = associated_data.encode("utf-8")
                    cipher.update(associated_data)
                
                # 解密并验证
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    return plaintext
                except ValueError:
                    raise ValueError("ChaCha20-Poly1305 认证标签验证失败，数据可能被篡改")
            else:
                # 普通 ChaCha20 模式
                if nonce is None:
                    # 从密文中提取 nonce
                    nonce = ciphertext[:self.nonce_length]
                    ciphertext = ciphertext[self.nonce_length:]
                elif isinstance(nonce, str):
                    nonce = nonce.encode("utf-8")
                    nonce = nonce[:self.nonce_length].ljust(self.nonce_length, b"\0")
                
                counter = kwargs.get("counter", 0)  # 默认计数器值为 0
                cipher = ChaCha20.new(key=key, nonce=nonce, counter=counter)
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
