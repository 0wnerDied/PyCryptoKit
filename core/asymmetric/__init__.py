"""
非对称加密模块
提供RSA、ECC、ElGamal等非对称加密算法
"""

from .base import AsymmetricCipher, AsymmetricKey, KeyPair
from .factory import AsymmetricCipherFactory
from .rsa import RSA
from .ecc import ECC
from .elgamal import ElGamal

# 注册算法
AsymmetricCipherFactory.register_algorithm(RSA, set_default=True)  # 设置RSA为默认算法
AsymmetricCipherFactory.register_algorithm(ECC)
AsymmetricCipherFactory.register_algorithm(ElGamal)

__all__ = [
    "AsymmetricCipher",
    "AsymmetricKey",
    "KeyPair",
    "AsymmetricCipherFactory",
    "RSA",
    "ECC",
    "ElGamal",
]
