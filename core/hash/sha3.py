"""
SHA3 系列哈希算法实现

提供 SHA3_224、SHA3_256、SHA3_384、SHA3_512、SHAKE128 和 SHAKE256 哈希算法实现。
所有实现基于 Python 标准库 hashlib, 提供最佳性能。

SHA3 (Secure Hash Algorithm 3) 是由 NIST 于 2015 年标准化的哈希函数家族, 
基于 Keccak 算法。
"""

import hashlib
from typing import Union

from .base import HashBase


class SHA3Hash(HashBase):
    """SHA3 哈希算法基类"""

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
        """初始化 SHA3 哈希对象"""
        self.reset()

    def update(self, data: Union[str, bytes, bytearray, memoryview]) -> "SHA3Hash":
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


class SHA3_224Hash(SHA3Hash):
    """SHA3_224 哈希算法实现"""

    _algorithm_name = "SHA3_224"
    _digest_size = 28
    _block_size = 144

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

    _algorithm_name = "SHA3_256"
    _digest_size = 32
    _block_size = 136

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

    _algorithm_name = "SHA3_384"
    _digest_size = 48
    _block_size = 104

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

    _algorithm_name = "SHA3_512"
    _digest_size = 64
    _block_size = 72

    def copy(self) -> "SHA3_512Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA3_512Hash: 当前哈希对象的副本
        """
        new_hash = SHA3_512Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHAKEHash(HashBase):
    """SHAKE 可扩展输出哈希函数基类"""

    # 子类需要覆盖这些属性
    _algorithm_name = None
    _block_size = None

    def __init__(self, digest_size: int):
        """
        初始化 SHAKE 哈希对象

        Args:
            digest_size: 输出摘要的字节长度
        """
        self._custom_digest_size = digest_size
        self.reset()

    @property
    def name(self) -> str:
        return f"{self._algorithm_name}_{self._custom_digest_size * 8}"

    @property
    def digest_size(self) -> int:
        return self._custom_digest_size

    @property
    def block_size(self) -> int:
        return self._block_size

    def update(self, data: Union[str, bytes, bytearray, memoryview]) -> "SHAKEHash":
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
        return self._hash.digest(self._custom_digest_size)

    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        return self._hash.hexdigest(self._custom_digest_size)

    def reset(self) -> None:
        """重置哈希对象的状态"""
        # 修复: 创建时不传递参数, 在 digest/hexdigest 时指定长度
        self._hash = getattr(hashlib, self._algorithm_name.lower())()


class SHAKE128Hash(SHAKEHash):
    """SHAKE128 可扩展输出哈希函数实现"""

    _algorithm_name = "shake_128"
    _block_size = 168

    def __init__(self, digest_size: int = 32):
        """
        初始化 SHAKE128 哈希对象

        Args:
            digest_size: 输出摘要的字节长度, 默认为 32
        """
        super().__init__(digest_size)

    def copy(self) -> "SHAKE128Hash":
        """
        返回哈希对象的副本

        Returns:
            SHAKE128Hash: 当前哈希对象的副本
        """
        new_hash = SHAKE128Hash(self._custom_digest_size)
        new_hash._hash = self._hash.copy()
        return new_hash


class SHAKE256Hash(SHAKEHash):
    """SHAKE256 可扩展输出哈希函数实现"""

    _algorithm_name = "shake_256"
    _block_size = 136

    def __init__(self, digest_size: int = 64):
        """
        初始化 SHAKE256 哈希对象

        Args:
            digest_size: 输出摘要的字节长度, 默认为 64
        """
        super().__init__(digest_size)

    def copy(self) -> "SHAKE256Hash":
        """
        返回哈希对象的副本

        Returns:
            SHAKE256Hash: 当前哈希对象的副本
        """
        new_hash = SHAKE256Hash(self._custom_digest_size)
        new_hash._hash = self._hash.copy()
        return new_hash
