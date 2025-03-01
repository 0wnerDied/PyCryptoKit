from typing import Union, Optional, Tuple
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
            if padding_length == self.block_size:  # 如果数据长度正好是块大小的整数倍
                return data
            return data + b"\x00" * padding_length

    def _unpad_data(self, data: bytes) -> bytes:
        """根据填充模式对数据进行去填充"""
        if self.padding == Padding.NONE:
            return data

        elif self.padding == Padding.PKCS7:
            if not data:
                return data

            padding_length = data[-1]
            # 验证填充
            if padding_length > 0 and padding_length <= self.block_size:
                if len(data) >= padding_length:
                    padding = data[-padding_length:]
                    if all(p == padding_length for p in padding):
                        return data[:-padding_length]
            # 如果验证失败，返回原始数据
            return data

        elif self.padding == Padding.ZERO:
            # 从末尾开始查找非零字节
            i = len(data) - 1
            while i >= 0 and data[i] == 0:
                i -= 1
            return data[: i + 1]

    def normalize_key(self, key: Union[str, bytes], length: int) -> bytes:
        """标准化密钥长度"""
        if isinstance(key, str):
            key = key.encode("utf-8")

        # 如果密钥长度不足，使用填充；如果过长，则截断
        if len(key) < length:
            return key.ljust(length, b"\0")  # 使用0填充
        return key[:length]  # 截断到指定长度

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        include_iv: bool = False,
        **kwargs,
    ) -> Union[bytes, Tuple[bytes, bytes]]:
        """
        SM4加密

        Args:
            plaintext: 明文
            key: 密钥
            iv: 初始向量(除ECB外的模式需要)
            include_iv: 是否在返回的密文中包含IV
            **kwargs: 其他参数

        Returns:
            bytes: 如果include_iv为False，返回加密后的密文
            Tuple[bytes, bytes]: 如果include_iv为True，返回(iv, 密文)元组
        """
        # 处理输入
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        key = self.normalize_key(key, self.key_length)

        # 处理IV
        needs_iv = self.mode != Mode.ECB
        used_iv = None

        if needs_iv:
            if iv is None:
                used_iv = os.urandom(16)  # 生成随机IV
            elif isinstance(iv, str):
                used_iv = iv.encode("utf-8")
            else:
                used_iv = iv

            # 确保IV长度为16字节
            if len(used_iv) < 16:
                used_iv = used_iv.ljust(16, b"\0")
            elif len(used_iv) > 16:
                used_iv = used_iv[:16]

        if self.padding != Padding.NONE:  # 只要不是NONE，都进行填充
            padded_plaintext = self._pad_data(plaintext)
        else:
            # 无填充模式
            if len(plaintext) % self.block_size != 0:
                raise ValueError(
                    f"无填充模式下，数据长度必须是{self.block_size}的整数倍"
                )
            padded_plaintext = plaintext

        # 创建加密器
        try:
            if needs_iv:
                cipher_mode = self._get_openssl_mode(self.mode, used_iv)
                cipher = Cipher(
                    algorithms.SM4(key), cipher_mode, backend=default_backend()
                )
            else:
                cipher_mode = self._get_openssl_mode(self.mode)
                cipher = Cipher(
                    algorithms.SM4(key), cipher_mode, backend=default_backend()
                )

            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

            # 根据include_iv参数决定返回格式
            if include_iv and needs_iv:
                # 将IV与密文合并：IV长度(2字节) + IV + 密文
                iv_length = len(used_iv).to_bytes(2, byteorder="big")
                return iv_length + used_iv + ciphertext
            else:
                return ciphertext

        except Exception as e:
            raise ValueError(f"SM4加密失败: {str(e)}")

    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        iv_included: bool = False,
        **kwargs,
    ) -> bytes:
        """
        SM4解密

        Args:
            ciphertext: 密文
            key: 密钥
            iv: 初始向量(除ECB外的模式需要)，如果iv_included为True且密文包含IV，则此参数可选
            iv_included: 密文中是否包含IV
            **kwargs: 其他参数

        Returns:
            bytes: 解密后的明文
        """
        if not ciphertext:
            return b""

        key = self.normalize_key(key, self.key_length)

        # 处理IV
        needs_iv = self.mode != Mode.ECB
        used_iv = None
        actual_ciphertext = ciphertext

        # 如果需要IV且密文中包含IV
        if needs_iv and iv_included:
            try:
                # 从密文中提取IV长度
                if len(ciphertext) < 2:
                    raise ValueError("密文长度不足，无法提取IV信息")

                iv_length = int.from_bytes(ciphertext[:2], byteorder="big")

                if iv_length > 0:
                    # 检查密文长度是否足够
                    if len(ciphertext) < 2 + iv_length:
                        raise ValueError("密文长度不足，无法提取完整IV")

                    # 从密文中提取IV
                    used_iv = ciphertext[2 : 2 + iv_length]
                    # 剩余部分是实际密文
                    actual_ciphertext = ciphertext[2 + iv_length :]
                else:
                    # IV长度为0，使用用户提供的IV
                    actual_ciphertext = ciphertext[2:]  # 跳过IV长度字段
                    if iv is None:
                        raise ValueError(f"{self.mode.value}模式解密需要提供IV")
                    used_iv = iv
            except Exception as e:
                # 如果提取IV失败，假设密文不包含IV，使用用户提供的IV
                actual_ciphertext = ciphertext
                if iv is None:
                    raise ValueError(f"{self.mode.value}模式解密需要提供IV")
                used_iv = iv
        elif needs_iv:
            # 需要IV但密文不包含IV，使用用户提供的IV
            if iv is None:
                raise ValueError(f"{self.mode.value}模式解密需要提供IV")

            if isinstance(iv, str):
                used_iv = iv.encode("utf-8")
            else:
                used_iv = iv

            # 确保IV长度为16字节
            if len(used_iv) < 16:
                used_iv = used_iv.ljust(16, b"\0")
            elif len(used_iv) > 16:
                used_iv = used_iv[:16]

        # 创建解密器
        try:
            if needs_iv:
                cipher_mode = self._get_openssl_mode(self.mode, used_iv)
                cipher = Cipher(
                    algorithms.SM4(key), cipher_mode, backend=default_backend()
                )
            else:
                cipher_mode = self._get_openssl_mode(self.mode)
                cipher = Cipher(
                    algorithms.SM4(key), cipher_mode, backend=default_backend()
                )

            decryptor = cipher.decryptor()
            plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

            if self.padding != Padding.NONE:  # 只要不是NONE填充，都需要去填充
                plaintext = self._unpad_data(plaintext)

            return plaintext

        except Exception as e:
            raise ValueError(f"SM4解密失败: {str(e)}")
