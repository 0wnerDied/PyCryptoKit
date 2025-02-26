"""
SHA3 系列哈希算法实现
"""

import hashlib
from typing import Union, Optional

from .base import HashBase


class SHA3Hash(HashBase):
    """SHA3 哈希算法基类"""

    def __init__(self, algorithm: str):
        """
        初始化SHA3哈希对象

        Args:
            algorithm: SHA3算法名称
        """
        self._algorithm = algorithm
        self._hash = getattr(hashlib, algorithm)()

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """更新哈希对象的状态"""
        self._hash.update(data)

    def digest(self) -> bytes:
        """返回当前数据的二进制摘要"""
        return self._hash.digest()

    def hexdigest(self) -> str:
        """返回当前数据的十六进制摘要"""
        return self._hash.hexdigest()

    def copy(self) -> "SHA3Hash":
        """返回哈希对象的副本"""
        new_hash = self.__class__()
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = getattr(hashlib, self._algorithm)()


class SHA3_224Hash(SHA3Hash):
    """SHA3-224 哈希算法实现"""

    def __init__(self):
        """初始化SHA3-224哈希对象"""
        super().__init__("sha3_224")


class SHA3_256Hash(SHA3Hash):
    """SHA3-256 哈希算法实现"""

    def __init__(self):
        """初始化SHA3-256哈希对象"""
        super().__init__("sha3_256")


class SHA3_384Hash(SHA3Hash):
    """SHA3-384 哈希算法实现"""

    def __init__(self):
        """初始化SHA3-384哈希对象"""
        super().__init__("sha3_384")


class SHA3_512Hash(SHA3Hash):
    """SHA3-512 哈希算法实现"""

    def __init__(self):
        """初始化SHA3-512哈希对象"""
        super().__init__("sha3_512")


class SHAKEHash(HashBase):
    """SHAKE 可扩展输出函数基类"""

    def __init__(self, algorithm: str, length: int = None):
        """
        初始化SHAKE哈希对象

        Args:
            algorithm: SHAKE算法名称
            length: 输出长度 (字节数), 如果为None, 则使用默认长度
        """
        self._algorithm = algorithm
        self._length = length
        self._hash = getattr(hashlib, algorithm)()

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """更新哈希对象的状态"""
        self._hash.update(data)

    def digest(self, length: Optional[int] = None) -> bytes:
        """
        返回当前数据的二进制摘要

        Args:
            length: 输出长度 (字节数), 如果为None, 则使用初始化时指定的长度

        Returns:
            bytes: 哈希摘要
        """
        output_length = length or self._length
        if output_length is None:
            return self._hash.digest()
        return self._hash.digest(output_length)

    def hexdigest(self, length: Optional[int] = None) -> str:
        """
        返回当前数据的十六进制摘要

        Args:
            length: 输出长度 (字节数), 如果为None, 则使用初始化时指定的长度

        Returns:
            str: 十六进制格式的哈希摘要
        """
        output_length = length or self._length
        if output_length is None:
            return self._hash.hexdigest()
        return self._hash.hexdigest(output_length)

    def copy(self) -> "SHAKEHash":
        """返回哈希对象的副本"""
        new_hash = self.__class__(length=self._length)
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = getattr(hashlib, self._algorithm)()


class SHAKE128Hash(SHAKEHash):
    """SHAKE128 哈希算法实现"""

    def __init__(self, length: int = 32):
        """
        初始化SHAKE128哈希对象

        Args:
            length: 输出长度 (字节数), 默认为32字节
        """
        super().__init__("shake_128", length)


class SHAKE256Hash(SHAKEHash):
    """SHAKE256 哈希算法实现"""

    def __init__(self, length: int = 64):
        """
        初始化SHAKE256哈希对象

        Args:
            length: 输出长度 (字节数), 默认为64字节
        """
        super().__init__("shake_256", length)


# 辅助函数
def _create_sha3_function(cls):
    """创建SHA3哈希函数"""

    def hash_func(
        data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
    ) -> Union[bytes, HashBase]:
        hash_obj = cls()
        if data is not None:
            return hash_obj.hash_data(data, encoding)
        return hash_obj

    return hash_func


def _create_shake_function(cls):
    """创建SHAKE哈希函数"""

    def hash_func(
        data: Optional[Union[str, bytes, bytearray]] = None,
        length: int = None,
        encoding: str = "utf-8",
    ) -> Union[bytes, HashBase]:
        hash_obj = cls(length=length)
        if data is not None:
            return hash_obj.hash_data(data, encoding)
        return hash_obj

    return hash_func


# 导出函数
sha3_224 = _create_sha3_function(SHA3_224Hash)
sha3_256 = _create_sha3_function(SHA3_256Hash)
sha3_384 = _create_sha3_function(SHA3_384Hash)
sha3_512 = _create_sha3_function(SHA3_512Hash)
shake128 = _create_shake_function(SHAKE128Hash)
shake256 = _create_shake_function(SHAKE256Hash)
