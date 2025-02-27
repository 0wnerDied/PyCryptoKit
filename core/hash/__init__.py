"""
哈希算法库

提供多种哈希算法的统一接口，包括:
- MD5 (不安全，仅用于兼容)
- SHA-1 (不安全，仅用于兼容)
- SHA-2 系列 (SHA-224, SHA-256, SHA-384, SHA-512)
- SHA-3 系列 (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256)
- BLAKE 系列 (BLAKE2b, BLAKE2s, BLAKE3)
- SM3 (国密算法)
"""

from typing import Dict, Type, Any, List, Tuple

# 导入所有哈希算法实现
from .base import HashBase
from .md5 import MD5Hash
from .sha import SHA1Hash, SHA224Hash, SHA256Hash, SHA384Hash, SHA512Hash
from .sha3 import (
    SHA3_224Hash,
    SHA3_256Hash,
    SHA3_384Hash,
    SHA3_512Hash,
    SHAKE128Hash,
    SHAKE256Hash,
)
from .blake import BLAKE2bHash, BLAKE2sHash, BLAKE3Hash
from .sm3 import SM3Hash

# 算法注册表
# 格式: {算法名称: (算法类, 是否安全, 描述, 默认参数)}
HASH_ALGORITHMS: Dict[str, Tuple[Type[HashBase], bool, str, Dict[str, Any]]] = {
    "MD5": (MD5Hash, False, "MD5 消息摘要算法 (不安全，仅用于兼容)", {}),
    "SHA1": (SHA1Hash, False, "SHA-1 安全哈希算法 (不安全，仅用于兼容)", {}),
    "SHA224": (SHA224Hash, True, "SHA-224 安全哈希算法", {}),
    "SHA256": (SHA256Hash, True, "SHA-256 安全哈希算法", {}),
    "SHA384": (SHA384Hash, True, "SHA-384 安全哈希算法", {}),
    "SHA512": (SHA512Hash, True, "SHA-512 安全哈希算法", {}),
    "SHA3_224": (SHA3_224Hash, True, "SHA3-224 安全哈希算法", {}),
    "SHA3_256": (SHA3_256Hash, True, "SHA3-256 安全哈希算法", {}),
    "SHA3_384": (SHA3_384Hash, True, "SHA3-384 安全哈希算法", {}),
    "SHA3_512": (SHA3_512Hash, True, "SHA3-512 安全哈希算法", {}),
    "SHAKE128": (SHAKE128Hash, True, "SHAKE128 安全哈希算法", {}),
    "SHAKE256": (SHAKE256Hash, True, "SHAKE256 安全哈希算法", {}),
    "BLAKE2b": (
        BLAKE2bHash,
        True,
        "BLAKE2b 哈希算法",
        {"digest_size": 64, "key": b"", "salt": b"", "person": b""},
    ),
    "BLAKE2s": (
        BLAKE2sHash,
        True,
        "BLAKE2s 哈希算法",
        {"digest_size": 32, "key": b"", "salt": b"", "person": b""},
    ),
    "BLAKE3": (
        BLAKE3Hash,
        True,
        "BLAKE3 哈希算法",
        {"key": b""},
    ),
    "SM3": (SM3Hash, True, "SM3 国密哈希算法", {}),
}

# 导出所有算法名称，按安全性分组
SECURE_ALGORITHMS: List[str] = [
    name for name, (_, is_secure, _, _) in HASH_ALGORITHMS.items() if is_secure
]

INSECURE_ALGORITHMS: List[str] = [
    name for name, (_, is_secure, _, _) in HASH_ALGORITHMS.items() if not is_secure
]

ALL_ALGORITHMS: List[str] = list(HASH_ALGORITHMS.keys())

# 导入工厂类
from .factory import HashFactory


# 便捷函数
def create_hash(algorithm: str, **kwargs) -> HashBase:
    """
    创建哈希算法实例的便捷函数

    Args:
        algorithm: 算法名称
        **kwargs: 传递给哈希算法构造函数的参数

    Returns:
        HashBase: 哈希算法实例

    Raises:
        ValueError: 如果算法不存在
        TypeError: 如果参数类型不正确
    """
    return HashFactory.create(algorithm, **kwargs)


def list_algorithms(secure_only: bool = False) -> List[str]:
    """
    列出支持的哈希算法的便捷函数

    Args:
        secure_only: 如果为True, 只返回安全的算法

    Returns:
        List[str]: 算法名称列表
    """
    return HashFactory.list_algorithms(secure_only)


def get_algorithm_info(algorithm: str) -> Dict[str, Any]:
    """
    获取算法信息的便捷函数

    Args:
        algorithm: 算法名称

    Returns:
        Dict: 包含算法信息的字典

    Raises:
        ValueError: 如果算法不存在
    """
    return HashFactory.get_algorithm_info(algorithm)


# 导出所有类和函数
__all__ = [
    "HashBase",
    "MD5Hash",
    "SHA1Hash",
    "SHA224Hash",
    "SHA256Hash",
    "SHA384Hash",
    "SHA512Hash",
    "SHA3_224Hash",
    "SHA3_256Hash",
    "SHA3_384Hash",
    "SHA3_512Hash",
    "SHAKE128Hash",
    "SHAKE256Hash",
    "BLAKE2bHash",
    "BLAKE2sHash",
    "BLAKE3Hash",
    "SM3Hash",
    "HashFactory",
    "create_hash",
    "list_algorithms",
    "get_algorithm_info",
    "SECURE_ALGORITHMS",
    "INSECURE_ALGORITHMS",
    "ALL_ALGORITHMS",
]
