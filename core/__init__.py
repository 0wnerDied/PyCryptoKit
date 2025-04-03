"""
PyCryptoKit 核心加密算法模块

包含对称加密、非对称加密、哈希算法和数字签名等核心加密功能。
"""

# 导出所有子包
from . import asymmetric, hash, signature, symmetric

# 导出非对称加密模块的内容
from .asymmetric import (
    AsymmetricCipher,
    AsymmetricKey,
    KeyPair,
    AsymmetricCipherFactory,
    RSA,
    ECC,
    ElGamal,
)

# 导出哈希模块的内容
from .hash import (
    HashBase,
    MD5Hash,
    SHA1Hash,
    SHA224Hash,
    SHA256Hash,
    SHA384Hash,
    SHA512Hash,
    SHA512_224Hash,
    SHA512_256Hash,
    SHA3_224Hash,
    SHA3_256Hash,
    SHA3_384Hash,
    SHA3_512Hash,
    SHAKE128Hash,
    SHAKE256Hash,
    BLAKE2bHash,
    BLAKE2sHash,
    SM3Hash,
    HashFactory,
    create_hash,
    list_algorithms as list_hash_algorithms,
    get_algorithm_info as get_hash_algorithm_info,
    SECURE_ALGORITHMS,
    INSECURE_ALGORITHMS,
    ALL_ALGORITHMS as ALL_HASH_ALGORITHMS,
)

# 导出签名模块的内容
from .signature import (
    SignatureBase,
    RSASignature,
    ECDSASignature,
    EdDSASignature,
    sign_data,
    verify_signature,
    RSA_PKCS1v15Signature,
    RSA_PSSSignature,
    create_signature,
    list_algorithms as list_signature_algorithms,
    get_algorithm_info as get_signature_algorithm_info,
    ALL_ALGORITHMS as ALL_SIGNATURE_ALGORITHMS,
)

# 导出对称加密模块的内容
from .symmetric import (
    Algorithm as SymmetricAlgorithm,
    Mode,
    Padding,
    encrypt,
    decrypt,
    encrypt_to_base64,
    decrypt_from_base64,
)

# 解决命名冲突
from .hash import list_algorithms as list_hash_algorithms
from .hash import get_algorithm_info as get_hash_algorithm_info
from .signature import list_algorithms as list_signature_algorithms
from .signature import get_algorithm_info as get_signature_algorithm_info

__all__ = [
    # 子模块
    "symmetric",
    "asymmetric",
    "hash",
    "signature",
    # 非对称加密
    "AsymmetricCipher",
    "AsymmetricKey",
    "KeyPair",
    "AsymmetricCipherFactory",
    "RSA",
    "ECC",
    "ElGamal",
    # 哈希算法
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
    "list_hash_algorithms",
    "get_hash_algorithm_info",
    "SECURE_ALGORITHMS",
    "INSECURE_ALGORITHMS",
    "ALL_HASH_ALGORITHMS",
    # 数字签名
    "SignatureBase",
    "RSASignature",
    "RSA_PKCS1v15Signature",
    "RSA_PSSSignature",
    "ECDSASignature",
    "EdDSASignature",
    "create_signature",
    "sign_data",
    "verify_signature",
    "list_signature_algorithms",
    "get_signature_algorithm_info",
    "ALL_SIGNATURE_ALGORITHMS",
    # 对称加密
    "SymmetricAlgorithm",
    "Mode",
    "Padding",
    "encrypt",
    "decrypt",
    "encrypt_to_base64",
    "decrypt_from_base64",
]
