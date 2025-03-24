"""
签名算法模块

提供多种数字签名算法实现, 包括RSA、ECDSA和EdDSA
"""

from typing import Any, Dict, List, Union, Tuple

# 导入所有签名算法实现类
from .base import SignatureBase
from .RSA_sig import RSASignature, RSA_PKCS1v15Signature, RSA_PSSSignature
from .ECDSA_sig import ECDSASignature
from .EdDSA_sig import EdDSASignature

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
    data: Union[bytes, str], key, algorithm: str, password: bytes = None, **kwargs
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
    data: Union[bytes, str], signature: bytes, key, algorithm: str, **kwargs
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


def generate_key_pair(algorithm: str, **kwargs) -> Tuple:
    """
    使用指定算法生成密钥对

    Args:
        algorithm: 签名算法名称
        **kwargs: 算法特定参数, 如密钥长度、曲线类型等

    Returns:
        Tuple: (私钥, 公钥)
    """
    signature_algo = create_signature(algorithm=algorithm, **kwargs)
    return signature_algo.generate_key_pair(**kwargs)


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
    "generate_key_pair",
    "ALL_ALGORITHMS",
]
