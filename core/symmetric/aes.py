from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import Union, Optional
import os

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
        # 验证密钥长度
        if key_size not in [128, 192, 256]:
            raise ValueError(f"AES密钥长度必须是128、192或256位，不支持{key_size}位")

        self.key_size = key_size
        self.key_length = key_size // 8  # 转换为字节长度
        self.mode = mode
        self.padding = padding
        self.block_size = AES.block_size

        # 加密模式映射
        self.mode_map = {
            Mode.ECB: AES.MODE_ECB,
            Mode.CBC: AES.MODE_CBC,
            Mode.CFB: AES.MODE_CFB,
            Mode.OFB: AES.MODE_OFB,
            Mode.CTR: AES.MODE_CTR,
            Mode.GCM: AES.MODE_GCM,
        }

        # 验证模式支持
        if mode not in self.mode_map:
            supported_str = ", ".join([m.value for m in self.mode_map.keys()])
            raise ValueError(
                f"AES不支持{mode.value}模式，支持的模式有: {supported_str}"
            )

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        append_iv: bool = False,  # 默认附加IV
        **kwargs,
    ) -> bytes:
        """
        AES加密

        Args:
            plaintext: 明文
            key: 密钥
            iv: 初始向量(CBC、CFB、OFB、CTR模式需要)
            append_iv: 是否将IV附加到密文前面
            **kwargs: 其他参数, 如GCM模式的associated_data, CFB模式的segment_size

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
                if self.mode == Mode.GCM:
                    iv = os.urandom(12)  # GCM模式推荐12字节nonce
                else:
                    iv = os.urandom(16)  # 其他模式使用16字节IV
            elif isinstance(iv, str):
                iv = iv.encode("utf-8")

            # 确保IV长度正确
            if self.mode == Mode.GCM:
                iv = iv[:12].ljust(12, b"\0")  # GCM模式推荐12字节
            else:
                iv = iv[:16].ljust(16, b"\0")  # 其他模式16字节

        # 填充处理 (对所有模式，只要选择了填充方式)
        if self.padding != Padding.NONE:
            if self.padding == Padding.PKCS7:
                plaintext = pad(plaintext, self.block_size)
            elif self.padding == Padding.ZERO:
                # 零填充
                padding_length = self.block_size - (len(plaintext) % self.block_size)
                if padding_length != self.block_size:  # 只有在需要填充时才填充
                    plaintext = plaintext + b"\x00" * padding_length
        else:
            # 无填充模式下，数据长度必须是块大小的整数倍
            if len(plaintext) % self.block_size != 0:
                raise ValueError(
                    f"无填充模式下，数据长度必须是{self.block_size}的整数倍"
                )

        try:
            # 创建加密器
            mode_value = self.mode_map[self.mode]

            if self.mode == Mode.ECB:
                cipher = AES.new(key, mode_value)
            elif self.mode == Mode.CTR:
                # 对CTR模式进行特殊处理
                cipher = AES.new(key, mode_value, nonce=iv[:8])
            elif self.mode == Mode.GCM:
                cipher = AES.new(key, mode_value, nonce=iv)
            elif self.mode == Mode.CFB:
                segment_size = kwargs.get("segment_size", 128)  # 默认使用128位分段大小
                cipher = AES.new(key, mode_value, iv=iv, segment_size=segment_size)
            else:
                cipher = AES.new(key, mode_value, iv=iv)

            # 特殊模式处理
            if self.mode == Mode.GCM:
                associated_data = kwargs.get("associated_data")
                if associated_data is not None:
                    if isinstance(associated_data, str):
                        associated_data = associated_data.encode("utf-8")
                    cipher.update(associated_data)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                # 将nonce、tag和密文一起返回
                if append_iv:
                    return b"".join([iv, tag, ciphertext])
                else:
                    return b"".join([tag, ciphertext])

            # 普通加密
            ciphertext = cipher.encrypt(plaintext)

            # 对于需要IV的模式，根据append_iv参数决定是否将IV与密文一起返回
            if iv_required and append_iv:
                if self.mode == Mode.CTR:
                    # CTR模式返回完整的nonce和密文
                    return b"".join([cipher.nonce, ciphertext])
                else:
                    return b"".join([iv, ciphertext])

            return ciphertext

        except ValueError as e:
            raise ValueError(f"AES加密参数错误: {str(e)}")
        except TypeError as e:
            raise TypeError(f"AES加密类型错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"AES加密未知错误: {str(e)}")

    def decrypt(
        self,
        ciphertext: bytes,
        key: Union[str, bytes],
        iv: Optional[Union[str, bytes]] = None,
        iv_included: bool = False,  # 默认密文中包含IV
        **kwargs,
    ) -> bytes:
        """
        AES解密

        Args:
            ciphertext: 密文
            key: 密钥
            iv: 初始向量(如果加密时未包含在密文中)
            iv_included: 密文中是否包含IV
            **kwargs: 其他参数，如CFB模式的segment_size

        Returns:
            bytes: 解密后的明文
        """
        key = self.normalize_key(key, self.key_length)

        try:
            # 处理特殊模式
            if self.mode == Mode.GCM:
                if iv_included:
                    if len(ciphertext) < 28:  # 至少需要12字节nonce + 16字节tag
                        raise ValueError("GCM密文格式不正确")
                    # 从密文中提取nonce和tag
                    nonce, tag, ciphertext = (
                        ciphertext[:12],
                        ciphertext[12:28],
                        ciphertext[28:],
                    )
                else:
                    if len(ciphertext) < 16:  # 至少需要16字节tag
                        raise ValueError("GCM密文格式不正确")
                    if iv is None:
                        raise ValueError("GCM模式需要提供nonce")
                    if isinstance(iv, str):
                        nonce = iv.encode("utf-8")[:12].ljust(12, b"\0")
                    else:
                        nonce = iv[:12].ljust(12, b"\0")
                    # 从密文中提取tag
                    tag, ciphertext = ciphertext[:16], ciphertext[16:]

                cipher = AES.new(key, self.mode_map[self.mode], nonce=nonce)

                # 处理AAD
                associated_data = kwargs.get("associated_data")
                if associated_data is not None:
                    if isinstance(associated_data, str):
                        associated_data = associated_data.encode("utf-8")
                    cipher.update(associated_data)

                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                # 去除填充 (GCM模式也需要去填充)
                if self.padding != Padding.NONE:
                    if self.padding == Padding.PKCS7:
                        try:
                            plaintext = unpad(plaintext, self.block_size)
                        except ValueError:
                            # 如果解除填充失败，可能是填充无效，返回原始数据
                            pass
                    elif self.padding == Padding.ZERO:
                        plaintext = plaintext.rstrip(b"\x00")
                
                return plaintext

            # 处理其他模式
            iv_required = self.mode != Mode.ECB
            if iv_required:
                if self.mode == Mode.CTR:
                    # CTR模式处理
                    if iv_included:
                        # 从密文中提取nonce
                        nonce, ciphertext = ciphertext[:8], ciphertext[8:]
                    else:
                        if iv is None:
                            raise ValueError("CTR模式需要提供nonce")
                        if isinstance(iv, str):
                            nonce = iv.encode("utf-8")[:8]
                        else:
                            nonce = iv[:8]
                    cipher = AES.new(key, self.mode_map[self.mode], nonce=nonce)
                elif self.mode == Mode.CFB:
                    segment_size = kwargs.get(
                        "segment_size", 128
                    )  # 默认使用128位分段大小
                    if iv_included:
                        # 从密文中提取IV
                        iv, ciphertext = ciphertext[:16], ciphertext[16:]
                    else:
                        if iv is None:
                            raise ValueError("CFB模式需要提供IV")
                        if isinstance(iv, str):
                            iv = iv.encode("utf-8")[:16].ljust(16, b"\0")
                        else:
                            iv = iv[:16].ljust(16, b"\0")
                    cipher = AES.new(
                        key, self.mode_map[self.mode], iv=iv, segment_size=segment_size
                    )
                else:
                    # 其他需要IV的模式
                    if iv_included:
                        # 从密文中提取IV
                        iv, ciphertext = ciphertext[:16], ciphertext[16:]
                    else:
                        if iv is None:
                            raise ValueError(f"{self.mode.value}模式需要提供IV")
                        if isinstance(iv, str):
                            iv = iv.encode("utf-8")[:16].ljust(16, b"\0")
                        else:
                            iv = iv[:16].ljust(16, b"\0")
                    cipher = AES.new(key, self.mode_map[self.mode], iv=iv)
            else:
                # ECB模式
                cipher = AES.new(key, self.mode_map[self.mode])

            # 解密
            plaintext = cipher.decrypt(ciphertext)

            # 去除填充 (对所有模式，只要选择了填充方式)
            if self.padding != Padding.NONE:
                if self.padding == Padding.PKCS7:
                    try:
                        plaintext = unpad(plaintext, self.block_size)
                    except ValueError:
                        # 如果解除填充失败，可能是填充无效，返回原始数据
                        pass
                elif self.padding == Padding.ZERO:
                    plaintext = plaintext.rstrip(b"\x00")

            return plaintext

        except ValueError as e:
            raise ValueError(f"AES解密参数错误: {str(e)}")
        except TypeError as e:
            raise TypeError(f"AES解密类型错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"AES解密未知错误: {str(e)}")

    def normalize_key(self, key: Union[str, bytes], length: int) -> bytes:
        """标准化密钥长度"""
        if isinstance(key, str):
            key = key.encode("utf-8")

        # 如果密钥长度不足，使用填充；如果过长，则截断
        if len(key) < length:
            return key.ljust(length, b"\0")  # 使用0填充
        return key[:length]  # 截断到指定长度
