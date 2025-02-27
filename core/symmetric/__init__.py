import base64
from typing import Union, Optional

from .base import Algorithm, Mode, Padding
from .factory import SymmetricFactory


def encrypt(
    algorithm: Union[str, Algorithm],
    plaintext: Union[str, bytes],
    key: Union[str, bytes],
    iv: Optional[Union[str, bytes]] = None,
    **kwargs
) -> bytes:
    """
    加密数据

    Args:
        algorithm: 加密算法
        plaintext: 明文
        key: 密钥
        iv: 初始向量(部分模式需要)
        **kwargs: 其他参数
            key_size: 密钥长度(AES可选128、192、256位)
            mode: 加密模式
            padding: 填充方式
            associated_data: GCM模式的关联数据
            nonce: CTR模式的nonce

    Returns:
        bytes: 加密后的密文
    """
    # 提取cipher创建参数
    cipher_kwargs = {
        k: v for k, v in kwargs.items() if k in ["key_size", "mode", "padding"]
    }

    # 创建加密器
    cipher = SymmetricFactory.create_cipher(algorithm, **cipher_kwargs)

    # 提取加密参数
    encrypt_kwargs = {k: v for k, v in kwargs.items() if k not in cipher_kwargs}

    # 执行加密
    return cipher.encrypt(plaintext, key, iv, **encrypt_kwargs)


def decrypt(
    algorithm: Union[str, Algorithm],
    ciphertext: bytes,
    key: Union[str, bytes],
    iv: Optional[Union[str, bytes]] = None,
    **kwargs
) -> bytes:
    """
    解密数据

    Args:
        algorithm: 加密算法
        ciphertext: 密文
        key: 密钥
        iv: 初始向量(部分模式需要)
        **kwargs: 其他参数
            key_size: 密钥长度(AES可选128、192、256位)
            mode: 加密模式
            padding: 填充方式
            associated_data: GCM模式的关联数据
            nonce: CTR模式的nonce

    Returns:
        bytes: 解密后的明文
    """
    # 提取cipher创建参数
    cipher_kwargs = {
        k: v for k, v in kwargs.items() if k in ["key_size", "mode", "padding"]
    }

    # 创建加密器
    cipher = SymmetricFactory.create_cipher(algorithm, **cipher_kwargs)

    # 提取解密参数
    decrypt_kwargs = {k: v for k, v in kwargs.items() if k not in cipher_kwargs}

    # 执行解密
    return cipher.decrypt(ciphertext, key, iv, **decrypt_kwargs)


def encrypt_to_base64(
    algorithm: Union[str, Algorithm],
    plaintext: Union[str, bytes],
    key: Union[str, bytes],
    iv: Optional[Union[str, bytes]] = None,
    **kwargs
) -> str:
    """
    加密并转为Base64字符串

    Args:
        algorithm: 加密算法
        plaintext: 明文
        key: 密钥
        iv: 初始向量(部分模式需要)
        **kwargs: 其他参数

    Returns:
        str: Base64编码的密文
    """
    ciphertext = encrypt(algorithm, plaintext, key, iv, **kwargs)
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_from_base64(
    algorithm: Union[str, Algorithm],
    ciphertext_b64: str,
    key: Union[str, bytes],
    iv: Optional[Union[str, bytes]] = None,
    **kwargs
) -> bytes:
    """
    从Base64字符串解密

    Args:
        algorithm: 加密算法
        ciphertext_b64: Base64编码的密文
        key: 密钥
        iv: 初始向量(部分模式需要)
        **kwargs: 其他参数

    Returns:
        bytes: 解密后的明文
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    return decrypt(algorithm, ciphertext, key, iv, **kwargs)


# 导出
__all__ = [
    "Algorithm",
    "Mode",
    "Padding",
    "encrypt",
    "decrypt",
    "encrypt_to_base64",
    "decrypt_from_base64",
]
