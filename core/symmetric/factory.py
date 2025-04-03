from typing import Union

from .base import Algorithm, Mode, Padding, SymmetricCipher
from .aes import AESCipher
from .sm4 import SM4Cipher
from .chacha20 import ChaCha20Cipher
from .salsa20 import Salsa20Cipher


class SymmetricFactory:
    """对称加密工厂类"""

    @staticmethod
    def create_cipher(algorithm: Union[str, Algorithm], **kwargs) -> SymmetricCipher:
        """
        创建对称加密实例

        Args:
            algorithm: 加密算法
            **kwargs: 其他参数
                key_size: 密钥长度(AES可选128、192、256位)
                mode: 加密模式
                padding: 填充方式

        Returns:
            SymmetricCipher: 加密实例
        """
        # 处理字符串输入
        if isinstance(algorithm, str):
            try:
                algorithm = Algorithm(algorithm.upper())
            except ValueError:
                supported = ", ".join([a.value for a in Algorithm])
                raise ValueError(
                    f"不支持的加密算法: {algorithm}. 支持的算法: {supported}"
                )

        # 处理模式参数
        mode = kwargs.get("mode", Mode.CBC)
        if isinstance(mode, str):
            try:
                mode = Mode(mode.upper())
            except ValueError:
                supported = ", ".join([m.value for m in Mode])
                raise ValueError(f"不支持的加密模式: {mode}. 支持的模式: {supported}")

        # 处理填充方式参数
        padding = kwargs.get("padding", Padding.PKCS7)
        if isinstance(padding, str):
            try:
                padding = Padding(padding.upper())
            except ValueError:
                supported = ", ".join([p.value for p in Padding])
                raise ValueError(
                    f"不支持的填充方式: {padding}. 支持的填充方式: {supported}"
                )

        # 创建对应的加密实例
        if algorithm == Algorithm.AES:
            key_size = kwargs.get("key_size", 256)
            return AESCipher(key_size=key_size, mode=mode, padding=padding)
        elif algorithm == Algorithm.SM4:
            return SM4Cipher(mode=mode, padding=padding)
        elif algorithm == Algorithm.CHACHA20:
            return ChaCha20Cipher()
        elif algorithm == Algorithm.SALSA20:
            return Salsa20Cipher()
        else:
            raise ValueError(f"不支持的加密算法: {algorithm.value}")
