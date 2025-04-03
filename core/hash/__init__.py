"""
哈希算法库

提供多种哈希算法的统一接口, 包括:
- MD5 (不安全, 仅用于兼容)
- SHA-1 (不安全, 仅用于兼容)
- SHA-2 系列 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
- SHA-3 系列 (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256)
- BLAKE 系列 (BLAKE2b, BLAKE2s, BLAKE3)
- SM3 (国密算法)
"""

from typing import Any, Dict, List, Tuple, Type

# 导入所有哈希算法实现
from .base import HashBase
from .blake import BLAKE2bHash, BLAKE2sHash, BLAKE3Hash
from .md5 import MD5Hash
from .sha import (
    SHA1Hash,
    SHA224Hash,
    SHA256Hash,
    SHA384Hash,
    SHA512Hash,
    SHA512_224Hash,
    SHA512_256Hash,
)
from .sha3 import (
    SHA3_224Hash,
    SHA3_256Hash,
    SHA3_384Hash,
    SHA3_512Hash,
    SHAKE128Hash,
    SHAKE256Hash,
)
from .sm3 import SM3Hash

# 算法注册表
# 格式: {算法名称: (算法类, 是否安全, 描述, 默认参数)}
HASH_ALGORITHMS: Dict[str, Tuple[Type[HashBase], bool, str, Dict[str, Any]]] = {
    "MD5": (
        MD5Hash,
        False,
        "MD5 消息摘要算法 (128位) - 已知存在碰撞攻击, 不应用于安全场景, 仅用于兼容",
        {},
    ),
    "SHA-1": (
        SHA1Hash,
        False,
        "SHA-1 哈希算法 (160位) - 已被证明不安全, 存在实际可行的碰撞攻击, 仅用于兼容",
        {},
    ),
    "SHA-224": (
        SHA224Hash,
        True,
        "SHA-224 哈希算法 (224位) - SHA-2家族成员, SHA-256的截断版本, 适用于空间受限但需要安全性的场景",
        {},
    ),
    "SHA-256": (
        SHA256Hash,
        True,
        "SHA-256 哈希算法 (256位) - SHA-2家族最广泛使用的算法, 提供良好的安全性和性能平衡",
        {},
    ),
    "SHA-384": (
        SHA384Hash,
        True,
        "SHA-384 哈希算法 (384位) - SHA-512的截断版本, 提供更高安全性, 适用于需要更强安全保证的场景",
        {},
    ),
    "SHA-512": (
        SHA512Hash,
        True,
        "SHA-512 哈希算法 (512位) - SHA-2家族中最安全的标准算法, 在64位系统上性能优异",
        {},
    ),
    "SHA-512/224": (
        SHA512_224Hash,
        True,
        "SHA-512/224 哈希算法 (224位) - 基于SHA-512的变种, 使用不同的初始值并截断到224位, 结合了SHA-512的优势和较小的输出大小",
        {},
    ),
    "SHA-512/256": (
        SHA512_256Hash,
        True,
        "SHA-512/256 哈希算法 (256位) - 基于SHA-512的变种, 使用不同的初始值并截断到256位, 在64位系统上比SHA-256更高效",
        {},
    ),
    "SHA3-224": (
        SHA3_224Hash,
        True,
        "SHA3-224 哈希算法 (224位) - 基于Keccak海绵函数构造的SHA-3标准算法, 抗量子计算攻击",
        {},
    ),
    "SHA3-256": (
        SHA3_256Hash,
        True,
        "SHA3-256 哈希算法 (256位) - SHA-3标准算法, 提供与SHA-256相当的安全性, 但结构完全不同, 作为备选标准",
        {},
    ),
    "SHA3-384": (
        SHA3_384Hash,
        True,
        "SHA3-384 哈希算法 (384位) - SHA-3标准算法, 提供高安全性, 适用于高安全需求场景",
        {},
    ),
    "SHA3-512": (
        SHA3_512Hash,
        True,
        "SHA3-512 哈希算法 (512位) - SHA-3标准中最安全的固定长度输出算法, 适用于最高安全需求",
        {},
    ),
    "SHAKE128": (
        SHAKE128Hash,
        True,
        "SHAKE128 可扩展输出函数 (XOF) - SHA-3标准的可变长度输出算法, 安全强度128位, 可生成任意长度的输出",
        {},
    ),
    "SHAKE256": (
        SHAKE256Hash,
        True,
        "SHAKE256 可扩展输出函数 (XOF) - SHA-3标准的可变长度输出算法, 安全强度256位, 可生成任意长度的输出, 提供更高安全性",
        {},
    ),
    "BLAKE2b": (
        BLAKE2bHash,
        True,
        "BLAKE2b 哈希算法 - 针对64位平台优化的高性能哈希算法, 支持1-64字节输出和可选密钥, 比MD5速度更快且安全",
        {"digest_size": 64},
    ),
    "BLAKE2s": (
        BLAKE2sHash,
        True,
        "BLAKE2s 哈希算法 - 针对32位平台优化的高性能哈希算法, 支持1-32字节输出和可选密钥, 适用于资源受限环境",
        {"digest_size": 32},
    ),
    "BLAKE3": (
        BLAKE3Hash,
        True,
        "BLAKE3 哈希算法 - 现代高性能并行哈希算法, 支持无限输出长度、密钥派生和内容寻址, 极高的吞吐量",
        {},
    ),
    "SM3": (
        SM3Hash,
        True,
        "SM3 国密哈希算法 (256位) - 中国国家密码管理局发布的密码杂凑算法标准, 用于数字签名和验证、消息认证",
        {},
    ),
}

# 导出所有算法名称, 按安全性分组
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
    "SHA512_224Hash",
    "SHA512_256Hash",
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
