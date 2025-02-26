from typing import Union, Optional
import gmssl.sm4 as sm4

from .base import SymmetricCipher, Mode, Padding


class SM4Cipher(SymmetricCipher):
    """SM4加密实现类"""

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
        if mode not in [Mode.ECB, Mode.CBC]:
            raise ValueError(f"SM4当前仅支持ECB和CBC模式, 不支持{mode.value}")

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
            iv: 初始向量(CBC模式需要)
            **kwargs: 其他参数

        Returns:
            bytes: 加密后的密文
        """
        # 处理输入
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        key = self.normalize_key(key, self.key_length)

        # 处理IV
        if self.mode == Mode.CBC:
            if iv is None:
                raise ValueError("CBC模式需要提供初始向量(IV)")
            if isinstance(iv, str):
                iv = iv.encode("utf-8")
            # 确保IV长度为16字节
            iv = iv[:16].ljust(16, b"\0")

        # 填充处理
        if self.padding == Padding.PKCS7:
            padding_length = self.block_size - (len(plaintext) % self.block_size)
            if padding_length == 0:
                padding_length = self.block_size
            plaintext = plaintext + bytes([padding_length]) * padding_length
        elif self.padding == Padding.ZERO:
            padding_length = self.block_size - (len(plaintext) % self.block_size)
            if padding_length != self.block_size:  # 只有在需要填充时才填充
                plaintext = plaintext + b"\x00" * padding_length

        # 创建加密器
        if self.mode == Mode.ECB:
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
            ciphertext = crypt_sm4.crypt_ecb(plaintext)
        else:  # CBC模式
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
            ciphertext = crypt_sm4.crypt_cbc(iv, plaintext)
            # 将IV与密文一起返回
            ciphertext = b"".join([iv, ciphertext])

        return ciphertext

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
        if self.mode == Mode.CBC:
            if iv is None:
                # 从密文中提取IV
                iv, ciphertext = ciphertext[:16], ciphertext[16:]
            elif isinstance(iv, str):
                iv = iv.encode("utf-8")
                # 确保IV长度为16字节
                iv = iv[:16].ljust(16, b"\0")

        # 创建解密器
        if self.mode == Mode.ECB:
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
            plaintext = crypt_sm4.crypt_ecb(ciphertext)
        else:  # CBC模式
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
            plaintext = crypt_sm4.crypt_cbc(iv, ciphertext)

        # 去除填充
        if self.padding == Padding.PKCS7:
            padding_length = plaintext[-1]
            # 验证填充
            if padding_length > 0 and padding_length <= self.block_size:
                padding = plaintext[-padding_length:]
                if all(p == padding_length for p in padding):
                    plaintext = plaintext[:-padding_length]
        elif self.padding == Padding.ZERO:
            plaintext = plaintext.rstrip(b"\x00")

        return plaintext
