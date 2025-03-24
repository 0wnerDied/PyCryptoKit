"""
提供多种非对称加密算法的实现, 包括 RSA、ECC 和 ElGamal。
"""

# 导入基础类
from .base import AsymmetricKey, KeyPair

# 导入工厂类
from .factory import AsymmetricCipherFactory

# 导入具体算法实现
from .rsa import RSA
from .ecc import ECC
from .elgamal import ElGamal

# 注册算法到工厂
AsymmetricCipherFactory.register_algorithm(RSA, set_default=True)
AsymmetricCipherFactory.register_algorithm(ECC)
AsymmetricCipherFactory.register_algorithm(ElGamal)

# 导出公共API
__all__ = [
    # 基础类
    "AsymmetricKey",
    "KeyPair",
    # 工厂类
    "AsymmetricCipherFactory",
    # 具体算法实现
    "RSA",
    "ECC",
    "ElGamal",
]
