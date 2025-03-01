"""
SHA3 系列哈希算法实现

提供 SHA3_224、SHA3_256、SHA3_384、SHA3_512、SHAKE128 和 SHAKE256 哈希算法实现。
所有实现基于 cryptography 库。

SHA3 (Secure Hash Algorithm 3) 是由 NIST 于 2015 年标准化的哈希函数家族，
基于 Keccak 算法。
"""

from cryptography.hazmat.primitives import hashes
from typing import Union

from .base import HashBase


class SHA3Hash(HashBase):
    """SHA3 哈希算法基类"""

    def __init__(self, algorithm):
        """
        初始化 SHA3 哈希对象

        Args:
            algorithm: cryptography 库中的哈希算法实例
        """
        self._algorithm = algorithm
        self._hash = hashes.Hash(self._algorithm)

    def update(self, data: Union[str, bytes, bytearray, memoryview]) -> None:
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Raises:
            TypeError: 如果数据类型不受支持
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._hash.update(data)

    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        hash_copy = self._hash.copy()
        return hash_copy.finalize()

    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        return self.digest().hex()

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = hashes.Hash(self._algorithm)


class SHA3_224Hash(SHA3Hash):
    """SHA3_224 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA3_224"

    @property
    def digest_size(self) -> int:
        return 28

    @property
    def block_size(self) -> int:
        return 144

    def __init__(self):
        """初始化 SHA3_224 哈希对象"""
        super().__init__(hashes.SHA3_224())

    def copy(self) -> "SHA3_224Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA3_224Hash: 当前哈希对象的副本
        """
        new_hash = SHA3_224Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA3_256Hash(SHA3Hash):
    """SHA3_256 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA3_256"

    @property
    def digest_size(self) -> int:
        return 32

    @property
    def block_size(self) -> int:
        return 136

    def __init__(self):
        """初始化 SHA3_256 哈希对象"""
        super().__init__(hashes.SHA3_256())

    def copy(self) -> "SHA3_256Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA3_256Hash: 当前哈希对象的副本
        """
        new_hash = SHA3_256Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA3_384Hash(SHA3Hash):
    """SHA3_384 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA3_384"

    @property
    def digest_size(self) -> int:
        return 48

    @property
    def block_size(self) -> int:
        return 104

    def __init__(self):
        """初始化 SHA3_384 哈希对象"""
        super().__init__(hashes.SHA3_384())

    def copy(self) -> "SHA3_384Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA3_384Hash: 当前哈希对象的副本
        """
        new_hash = SHA3_384Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA3_512Hash(SHA3Hash):
    """SHA3_512 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA3_512"

    @property
    def digest_size(self) -> int:
        return 64

    @property
    def block_size(self) -> int:
        return 72

    def __init__(self):
        """初始化 SHA3_512 哈希对象"""
        super().__init__(hashes.SHA3_512())

    def copy(self) -> "SHA3_512Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA3_512Hash: 当前哈希对象的副本
        """
        new_hash = SHA3_512Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHAKE128Hash(SHA3Hash):
    """SHAKE128 可扩展输出哈希函数实现"""

    @property
    def name(self) -> str:
        return "SHAKE128"

    @property
    def digest_size(self) -> int:
        # SHAKE128 没有固定的摘要大小，默认为 16 字节
        return 16

    @property
    def block_size(self) -> int:
        return 168

    def __init__(self, digest_size: int = 16):
        """
        初始化 SHAKE128 哈希对象

        Args:
            digest_size: 输出摘要的字节长度，默认为 16
        """
        self._digest_size = digest_size
        super().__init__(hashes.SHAKE128(digest_size))

    def copy(self) -> "SHAKE128Hash":
        """
        返回哈希对象的副本

        Returns:
            SHAKE128Hash: 当前哈希对象的副本
        """
        new_hash = SHAKE128Hash(self._digest_size)
        new_hash._hash = self._hash.copy()
        return new_hash


class SHAKE256Hash(SHA3Hash):
    """SHAKE256 可扩展输出哈希函数实现"""

    @property
    def name(self) -> str:
        return "SHAKE256"

    @property
    def digest_size(self) -> int:
        # SHAKE256 没有固定的摘要大小，默认为 32 字节
        return 32

    @property
    def block_size(self) -> int:
        return 136

    def __init__(self, digest_size: int = 32):
        """
        初始化 SHAKE256 哈希对象

        Args:
            digest_size: 输出摘要的字节长度，默认为 32
        """
        self._digest_size = digest_size
        super().__init__(hashes.SHAKE256(digest_size))

    def copy(self) -> "SHAKE256Hash":
        """
        返回哈希对象的副本

        Returns:
            SHAKE256Hash: 当前哈希对象的副本
        """
        new_hash = SHAKE256Hash(self._digest_size)
        new_hash._hash = self._hash.copy()
        return new_hash
