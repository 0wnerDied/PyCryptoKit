"""
PyCryptoKit 数字签名模块

提供多种数字签名算法的实现，包括 RSA、ECDSA 等。
"""

from typing import Dict, Type, Any, List, Tuple

# 导入所有签名算法实现
from .base import SignatureBase
from .rsa_sig import RSASignature
from .ecdsa_sig import ECDSASignature

# 算法注册表
# 格式: {算法名称: (算法类, 描述, 默认参数)}
SIGNATURE_ALGORITHMS: Dict[str, Tuple[Type[SignatureBase], str, Dict[str, Any]]] = {
    "RSA": (
        RSASignature,
        "RSA 签名算法，基于大数因子分解问题",
        {"hash_algorithm": "SHA256"},
    ),
    "ECDSA": (
        ECDSASignature,
        "ECDSA 椭圆曲线数字签名算法",
        {"curve": "SECP256R1", "hash_algorithm": "SHA256"},
    ),
}

# 导出所有算法名称
ALL_ALGORITHMS: List[str] = list(SIGNATURE_ALGORITHMS.keys())

# 导入工厂类
from .factory import SignatureFactory


# 便捷函数
def create_signature(algorithm: str, **kwargs) -> SignatureBase:
    """
    创建签名算法实例的便捷函数

    Args:
        algorithm: 算法名称
        **kwargs: 传递给签名算法构造函数的参数

    Returns:
        SignatureBase: 签名算法实例

    Raises:
        ValueError: 如果算法不存在
        TypeError: 如果参数类型不正确
    """
    return SignatureFactory.create(algorithm, **kwargs)


def sign(
    data: bytes, key: bytes, algorithm: str, password: bytes = None, **kwargs
) -> bytes:
    """
    使用指定算法和私钥对数据进行签名

    Args:
        data: 要签名的数据
        key: 私钥数据
        algorithm: 签名算法名称
        password: 私钥密码（如果需要）
        **kwargs: 其他算法特定参数

    Returns:
        bytes: 签名数据
    """
    # 创建签名算法实例
    signature_algo = create_signature(algorithm=algorithm, **kwargs)

    # 执行签名
    return signature_algo.sign(data=data, private_key=key, password=password)


def list_algorithms() -> List[str]:
    """
    列出支持的签名算法

    Returns:
        List[str]: 算法名称列表
    """
    return SignatureFactory.list_algorithms()


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
    return SignatureFactory.get_algorithm_info(algorithm)


# 导出所有类和函数
__all__ = [
    "SignatureBase",
    "RSASignature",
    "ECDSASignature",
    "SignatureFactory",
    "create_signature",
    "list_algorithms",
    "get_algorithm_info",
    "ALL_ALGORITHMS",
]
