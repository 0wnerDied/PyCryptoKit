"""
签名算法模块

提供多种数字签名算法实现, 包括RSA、ECDSA和EdDSA
"""

from typing import Any, Dict, List, Union

# 导入所有签名算法实现类
from .base import SignatureBase
from .rsa_sig import RSASignature, RSA_PKCS1v15Signature, RSA_PSSSignature
from .ecdsa_sig import ECDSASignature
from .eddsa_sig import EdDSASignature

# 算法映射表: 算法名称 -> (算法类, 描述, 默认参数)
SIGNATURE_ALGORITHMS = {
    "RSA_PKCS1v15": (
        RSA_PKCS1v15Signature,
        "RSA签名 (使用PKCS#1 v1.5填充)",
        {"常用哈希算法": "SHA256"},
    ),
    "RSA_PSS": (
        RSA_PSSSignature,
        "RSA-PSS签名",
        {"常用哈希算法": "SHA256", "盐值长度": 32},
    ),
    "ECDSA": (
        ECDSASignature,
        "ECDSA签名",
        {"常用曲线": "SECP256R1", "常用哈希算法": "SHA256"},
    ),
    "EdDSA": (
        EdDSASignature,
        "EdDSA签名 (Ed25519/Ed448)",
        {"常用曲线": "Ed25519"},
    ),
}

# 所有支持的算法列表
ALL_ALGORITHMS = list(SIGNATURE_ALGORITHMS.keys())


def create_signature(algorithm: str, **kwargs) -> SignatureBase:
    """
    创建指定的签名算法实例

    Args:
        algorithm: 算法名称, 如 "RSA", "ECDSA", "EdDSA"
        **kwargs: 传递给算法构造函数的参数

    Returns:
        SignatureBase: 签名算法实例

    Raises:
        ValueError: 如果算法不存在
    """
    from .factory import SignatureFactory

    return SignatureFactory.create(algorithm, **kwargs)


def sign_data(
    data: Union[bytes, str],
    key,
    algorithm: str,
    password: bytes = None,
    key_format: str = "Auto",
    **kwargs
) -> bytes:
    # 创建签名算法实例（不传递key_format）
    algo_params = {k: v for k, v in kwargs.items() if k != "key_format"}
    signature_algo = create_signature(algorithm=algorithm, **algo_params)

    # 执行签名（显式传递key_format）
    return signature_algo.sign(
        data=data, private_key=key, password=password, key_format=key_format, **kwargs
    )


def verify_signature(
    data: Union[bytes, str],
    signature: bytes,
    key,
    algorithm: str,
    key_format: str = "Auto",
    **kwargs
) -> bool:
    # 创建签名算法实例（不传递key_format）
    algo_params = {k: v for k, v in kwargs.items() if k != "key_format"}
    signature_algo = create_signature(algorithm=algorithm, **algo_params)

    # 执行验证（显式传递key_format）
    return signature_algo.verify(
        data=data, signature=signature, public_key=key, key_format=key_format, **kwargs
    )


def list_algorithms() -> List[str]:
    """
    列出支持的签名算法

    Returns:
        List[str]: 算法名称列表
    """
    from .factory import SignatureFactory

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
    from .factory import SignatureFactory

    return SignatureFactory.get_algorithm_info(algorithm)


# 导出所有类和函数
__all__ = [
    "SignatureBase",
    "RSASignature",
    "RSA_PKCS1v15Signature",
    "RSA_PSSSignature",
    "ECDSASignature",
    "EdDSASignature",
    "create_signature",
    "sign_data",
    "verify_signature",
    "list_algorithms",
    "get_algorithm_info",
    "ALL_ALGORITHMS",
]
