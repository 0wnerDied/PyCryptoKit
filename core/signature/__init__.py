"""
PyCryptoKit 数字签名模块

提供多种数字签名算法的实现, 包括 RSA、ECDSA 等。
"""

from typing import Any, Dict, List, Tuple, Type

# 导入所有签名算法实现
from .base import SignatureBase
from .ECDSA_sig import ECDSASignature
from .EdDSA_sig import EdDSASignature
from .RSA_sig import RSASignature, RSA_PKCS1v15Signature, RSA_PSSSignature

# 算法注册表
# 格式: {算法名称: (算法类, 描述, 默认参数)}
SIGNATURE_ALGORITHMS: Dict[str, Tuple[Type[SignatureBase], str, Dict[str, Any]]] = {
    "RSA": (
        RSA_PKCS1v15Signature,
        "传统 RSA 签名算法, 使用 PKCS#1 v1.5 填充",
        {"哈希算法": "SHA256"},
    ),
    "RSA-PSS": (
        RSA_PSSSignature,
        "RSA-PSS 签名算法, 使用 PSS 填充",
        {"哈希算法": "SHA256", "盐长度": 32},
    ),
    "ECDSA": (
        ECDSASignature,
        "ECDSA 椭圆曲线数字签名算法",
        {"曲线": "SECP256R1", "哈希算法": "SHA256"},
    ),
    "EdDSA": (
        EdDSASignature,
        "EdDSA 爱德华兹曲线数字签名算法",
        {"曲线": "ED25519"},
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
        password: 私钥密码 (如果需要)
        **kwargs: 其他算法特定参数

    Returns:
        bytes: 签名数据
    """
    # 创建签名算法实例
    signature_algo = create_signature(algorithm=algorithm, **kwargs)

    # 执行签名
    return signature_algo.sign(data=data, private_key=key, password=password, **kwargs)


def verify_signature(
    data: bytes, signature: bytes, key: bytes, algorithm: str, **kwargs
) -> bool:
    """
    使用指定算法和公钥验证数据签名

    Args:
        data: 原始数据
        signature: 签名数据
        key: 公钥数据
        algorithm: 签名算法名称
        **kwargs: 其他算法特定参数

    Returns:
        bool: 验证结果, True表示签名有效, False表示签名无效
    """
    # 创建签名算法实例
    signature_algo = create_signature(algorithm=algorithm, **kwargs)

    # 执行验证
    return signature_algo.verify(
        data=data, signature=signature, public_key=key, **kwargs
    )


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
    "RSA_PKCS1v15Signature",
    "RSA_PSSSignature",
    "ECDSASignature",
    "EdDSASignature",
    "SignatureFactory",
    "create_signature",
    "list_algorithms",
    "get_algorithm_info",
    "ALL_ALGORITHMS",
]
