"""
非对称加密模块
提供RSA、ECC、ElGamal等非对称加密算法
"""

from .base import AsymmetricCipher, AsymmetricKey, KeyPair
from .factory import AsymmetricCipherFactory
from .rsa import RSA
from .ecc import ECC
from .edwards import Edwards
from .elgamal import ElGamal
from .sm2 import SM2

# 注册算法
AsymmetricCipherFactory.register_algorithm(RSA, set_default=True)  # 设置RSA为默认算法
AsymmetricCipherFactory.register_algorithm(ECC)
AsymmetricCipherFactory.register_algorithm(Edwards)
AsymmetricCipherFactory.register_algorithm(ElGamal)
AsymmetricCipherFactory.register_algorithm(SM2)

__all__ = [
    "AsymmetricCipher",
    "AsymmetricKey",
    "KeyPair",
    "AsymmetricCipherFactory",
    "RSA",
    "ECC",
    "Edwards",
    "ElGamal",
    "SM2",
]
