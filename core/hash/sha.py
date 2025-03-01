"""
SHA 系列哈希算法实现

提供 SHA1、SHA224、SHA256、SHA384、SHA512、SHA512_224 和 SHA512_256 哈希算法实现。
标准 SHA 算法基于 Python 标准库 hashlib, SHA512/224 和 SHA512/256 基于 cryptography 库实现。

注意: SHA1 已被证明不再安全, 不应用于安全场景。
推荐使用 SHA256 或更高级别的哈希算法。
"""

import hashlib
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .base import HashBase


class SHAHash(HashBase):
    """SHA 哈希算法基类"""

    # 子类需要覆盖这些属性
    _algorithm_name = None
    _digest_size = None
    _block_size = None

    @property
    def name(self) -> str:
        return self._algorithm_name

    @property
    def digest_size(self) -> int:
        return self._digest_size

    @property
    def block_size(self) -> int:
        return self._block_size

    def __init__(self):
        """初始化 SHA 哈希对象"""
        self.reset()

    def update(self, data: Union[str, bytes, bytearray, memoryview]) -> "SHAHash":
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Returns:
            self: 支持链式调用

        Raises:
            TypeError: 如果数据类型不受支持
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._hash.update(data)
        return self

    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        return self._hash.digest()

    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        return self._hash.hexdigest()

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = getattr(hashlib, self._algorithm_name.lower())()


class SHA1Hash(SHAHash):
    """SHA-1 哈希算法实现"""

    _algorithm_name = "SHA1"
    _digest_size = 20
    _block_size = 64

    def copy(self) -> "SHA1Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA1Hash: 当前哈希对象的副本
        """
        new_hash = SHA1Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA224Hash(SHAHash):
    """SHA224 哈希算法实现"""

    _algorithm_name = "SHA224"
    _digest_size = 28
    _block_size = 64

    def copy(self) -> "SHA224Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA224Hash: 当前哈希对象的副本
        """
        new_hash = SHA224Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA256Hash(SHAHash):
    """SHA256 哈希算法实现"""

    _algorithm_name = "SHA256"
    _digest_size = 32
    _block_size = 64

    def copy(self) -> "SHA256Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA256Hash: 当前哈希对象的副本
        """
        new_hash = SHA256Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA384Hash(SHAHash):
    """SHA384 哈希算法实现"""

    _algorithm_name = "SHA384"
    _digest_size = 48
    _block_size = 128

    def copy(self) -> "SHA384Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA384Hash: 当前哈希对象的副本
        """
        new_hash = SHA384Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA512Hash(SHAHash):
    """SHA512 哈希算法实现"""

    _algorithm_name = "SHA512"
    _digest_size = 64
    _block_size = 128

    def copy(self) -> "SHA512Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA512Hash: 当前哈希对象的副本
        """
        new_hash = SHA512Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class CryptographyHash(HashBase):
    """基于 cryptography 库的哈希算法基类"""

    _algorithm_class = None  # 子类需要覆盖，指定 cryptography 算法类
    _algorithm_name = None  # 算法名称
    _digest_size = None  # 摘要大小
    _block_size = None  # 块大小

    @property
    def name(self) -> str:
        return self._algorithm_name

    @property
    def digest_size(self) -> int:
        return self._digest_size

    @property
    def block_size(self) -> int:
        return self._block_size

    def __init__(self):
        """初始化哈希对象"""
        self.reset()

    def update(
        self, data: Union[str, bytes, bytearray, memoryview]
    ) -> "CryptographyHash":
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Returns:
            self: 支持链式调用
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._hash.update(data)
        return self

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
        self._hash = hashes.Hash(self._algorithm_class(), backend=default_backend())

    def copy(self):
        """
        返回哈希对象的副本

        Returns:
            CryptographyHash: 当前哈希对象的副本
        """
        new_hash = self.__class__()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA512_224Hash(CryptographyHash):
    """SHA512/224 哈希算法实现，基于 cryptography 库"""

    _algorithm_name = "SHA512_224"
    _algorithm_class = hashes.SHA512_224
    _digest_size = 28
    _block_size = 128


class SHA512_256Hash(CryptographyHash):
    """SHA512/256 哈希算法实现，基于 cryptography 库"""

    _algorithm_name = "SHA512_256"
    _algorithm_class = hashes.SHA512_256
    _digest_size = 32
    _block_size = 128
