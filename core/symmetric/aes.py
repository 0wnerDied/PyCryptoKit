from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import Union, Optional

from .base import SymmetricCipher, Mode, Padding


class AESCipher(SymmetricCipher):
    """AES加密实现类"""

    def __init__(
        self,
        key_size: int = 256,
        mode: Mode = Mode.CBC,
        padding: Padding = Padding.PKCS7,
    ):
        """
        初始化AES加密器

        Args:
            key_size: 密钥长度, 可选128、192、256位
            mode: 加密模式
            padding: 填充方式
        """
        self.key_size = key_size
        self.key_length = key_size // 8  # 转换为字节长度
        self.mode = mode
        self.padding = padding

        # 加密模式映射
        self.mode_map = {
            Mode.ECB: AES.MODE_ECB,
            Mode.CBC: AES.MODE_CBC,
            Mode.CFB: AES.MODE_CFB,
            Mode.OFB: AES.MODE_OFB,
            Mode.CTR: AES.MODE_CTR,
            Mode.GCM: AES.MODE_GCM,
        }

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        AES加密

        Args:
            plaintext: 明文
            key: 密钥
            iv: 初始向量(CBC、CFB、OFB、CTR模式需要)
            **kwargs: 其他参数, 如GCM模式的associated_data

        Returns:
            bytes: 加密后的密文
        """
        # 处理输入
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        key = self.normalize_key(key, self.key_length)

        # 处理IV
        iv_required = self.mode != Mode.ECB
        if iv_required:
            if iv is None:
                raise ValueError(f"{self.mode.value}模式需要提供初始向量(IV)")
            if isinstance(iv, str):
                iv = iv.encode("utf-8")
            # 确保IV长度为16字节
            iv = iv[:16].ljust(16, b"\0")

        # 创建加密器
        mode_value = self.mode_map[self.mode]
        if self.mode == Mode.ECB:
            cipher = AES.new(key, mode_value)
        else:
            cipher = AES.new(key, mode_value, iv=iv)

        # 填充处理
        if self.mode in [Mode.ECB, Mode.CBC]:
            if self.padding == Padding.PKCS7:
                plaintext = pad(plaintext, AES.block_size)
            elif self.padding == Padding.ZERO:
                # 零填充
                padding_length = AES.block_size - (len(plaintext) % AES.block_size)
                if padding_length != AES.block_size:  # 只有在需要填充时才填充
                    plaintext = plaintext + b"\x00" * padding_length

        # 特殊模式处理
        if self.mode == Mode.GCM:
            associated_data = kwargs.get("associated_data")
            if isinstance(associated_data, str):
                associated_data = associated_data.encode("utf-8")
            if associated_data:
                cipher.update(associated_data)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            return b"".join([cipher.nonce, tag, ciphertext])

        # 普通加密
        ciphertext = cipher.encrypt(plaintext)

        # 对于需要IV的模式，将IV与密文一起返回
        if iv_required and self.mode != Mode.GCM:
            return b"".join([iv, ciphertext])

        return ciphertext

    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        **kwargs,
    ) -> bytes:
        """
        AES解密

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
        iv_required = self.mode != Mode.ECB
        if iv_required and self.mode != Mode.GCM:
            if iv is None:
                # 从密文中提取IV
                iv, ciphertext = ciphertext[:16], ciphertext[16:]
            elif isinstance(iv, str):
                iv = iv.encode("utf-8")
                # 确保IV长度为16字节
                iv = iv[:16].ljust(16, b"\0")

        # 特殊模式处理
        if self.mode == Mode.GCM:
            nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
            cipher = AES.new(key, self.mode_map[self.mode], nonce=nonce)

            associated_data = kwargs.get("associated_data")
            if associated_data:
                if isinstance(associated_data, str):
                    associated_data = associated_data.encode("utf-8")
                cipher.update(associated_data)

            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext

        # 创建解密器
        mode_value = self.mode_map[self.mode]
        if self.mode == Mode.ECB:
            cipher = AES.new(key, mode_value)
        else:
            cipher = AES.new(key, mode_value, iv=iv)

        # 解密
        plaintext = cipher.decrypt(ciphertext)

        # 去除填充
        if self.mode in [Mode.ECB, Mode.CBC]:
            if self.padding == Padding.PKCS7:
                plaintext = unpad(plaintext, AES.block_size)
            elif self.padding == Padding.ZERO:
                # 移除零填充
                plaintext = plaintext.rstrip(b"\x00")

        return plaintext
