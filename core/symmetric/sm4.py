from typing import Union, Optional
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .base import SymmetricCipher, Mode, Padding


class SM4Cipher(SymmetricCipher):
    """SM4加密实现类 (OpenSSL后端)"""

    def __init__(self, mode: Mode = Mode.CBC, padding: Padding = Padding.PKCS7):
        """
        初始化SM4加密器

        Args:
            mode: 加密模式
            padding: 填充方式
        """
        self.mode = mode
        self.padding = padding
        self.key_length = 16  # SM4固定16字节密钥
        self.block_size = 16  # SM4块大小为16字节

        # 检查模式支持
        self.supported_modes = [Mode.ECB, Mode.CBC, Mode.CTR, Mode.OFB, Mode.CFB]
        if mode not in self.supported_modes:
            supported_str = ", ".join([m.value for m in self.supported_modes])
            raise ValueError(f"SM4当前支持{supported_str}模式, 不支持{mode.value}")

    def _get_openssl_mode(self, mode_value, iv=None):
        """获取OpenSSL对应的加密模式"""
        if mode_value == Mode.ECB:
            return modes.ECB()
        elif mode_value == Mode.CBC:
            return modes.CBC(iv)
        elif mode_value == Mode.CTR:
            return modes.CTR(iv)
        elif mode_value == Mode.OFB:
            return modes.OFB(iv)
        elif mode_value == Mode.CFB:
            return modes.CFB(iv)
        else:
            raise ValueError(f"不支持的加密模式: {mode_value}")

    def _pad_data(self, data: bytes) -> bytes:
        """根据填充模式对数据进行填充"""
        if self.padding == Padding.NONE:
            if len(data) % self.block_size != 0:
                raise ValueError(
                    f"无填充模式下，数据长度必须是{self.block_size}的整数倍"
                )
            return data

        elif self.padding == Padding.PKCS7:
            padding_length = self.block_size - (len(data) % self.block_size)
            if padding_length == 0:
                padding_length = self.block_size
            return data + bytes([padding_length]) * padding_length

        elif self.padding == Padding.ZERO:
            padding_length = self.block_size - (len(data) % self.block_size)
            if padding_length != self.block_size:  # 只有在需要填充时才填充
                return data + b"\x00" * padding_length
            return data

    def _unpad_data(self, data: bytes) -> bytes:
        """根据填充模式对数据进行去填充"""
        if self.padding == Padding.NONE:
            return data

        elif self.padding == Padding.PKCS7:
            padding_length = data[-1]
            # 验证填充
            if padding_length > 0 and padding_length <= self.block_size:
                padding = data[-padding_length:]
                if all(p == padding_length for p in padding):
                    return data[:-padding_length]
                else:
                    raise ValueError("PKCS7填充验证失败")
            return data

        elif self.padding == Padding.ZERO:
            return data.rstrip(b"\x00")

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        SM4加密

        Args:
            plaintext: 明文
            key: 密钥
            iv: 初始向量(除ECB外的模式需要)
            **kwargs: 其他参数

        Returns:
            bytes: 加密后的密文
        """
        # 处理输入
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        key = self.normalize_key(key, self.key_length)

        # 处理IV
        original_iv = None
        if self.mode != Mode.ECB:
            if iv is None:
                iv = os.urandom(16)  # 生成随机IV
            elif isinstance(iv, str):
                iv = iv.encode("utf-8")
            # 确保IV长度为16字节
            iv = iv[:16].ljust(16, b"\0")
            original_iv = iv  # 保存原始IV用于返回

        # 填充处理
        if self.mode in [Mode.ECB, Mode.CBC]:  # 只有这些模式需要填充
            plaintext = self._pad_data(plaintext)

        # 创建加密器
        try:
            cipher_mode = self._get_openssl_mode(self.mode, iv)
            cipher = Cipher(algorithms.SM4(key), cipher_mode, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # 对于需要IV的模式，将IV与密文一起返回
            if self.mode != Mode.ECB and original_iv:
                ciphertext = original_iv + ciphertext

            return ciphertext
        except Exception as e:
            raise ValueError(f"SM4加密失败: {str(e)}")

    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        SM4解密

        Args:
            ciphertext: 密文
            key: 密钥
            iv: 初始向量(如果加密时未包含在密文中)
            **kwargs: 其他参数

        Returns:
            bytes: 解密后的明文
        """
        key = self.normalize_key(key, self.key_length)

        # 处理IV
        if self.mode != Mode.ECB:
            if iv is None:
                # 从密文中提取IV
                iv, ciphertext = ciphertext[:16], ciphertext[16:]
            elif isinstance(iv, str):
                iv = iv.encode("utf-8")
                # 确保IV长度为16字节
                iv = iv[:16].ljust(16, b"\0")

        # 创建解密器
        try:
            cipher_mode = self._get_openssl_mode(self.mode, iv)
            cipher = Cipher(algorithms.SM4(key), cipher_mode, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # 去除填充
            if self.mode in [Mode.ECB, Mode.CBC]:  # 只有这些模式需要去填充
                plaintext = self._unpad_data(plaintext)

            return plaintext
        except Exception as e:
            raise ValueError(f"SM4解密失败: {str(e)}")
