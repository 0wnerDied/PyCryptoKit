"""
BLAKE 哈希算法实现模块

提供 BLAKE2b, BLAKE2s 和 BLAKE3 哈希算法的实现
"""

import blake3
import hashlib  # 使用内置 hashlib 模块, Python 3.6+ 支持 BLAKE2
from .base import HashBase


class BLAKE2bHash(HashBase):
    """BLAKE2b 哈希算法实现 - 高性能版本"""

    def __init__(self, digest_size=64):
        """
        初始化 BLAKE2b 哈希对象

        Args:
            digest_size: 摘要大小, 1-64字节, 默认64

        Raises:
            ValueError: 如果摘要大小无效
        """
        if not 1 <= digest_size <= 64:
            raise ValueError("BLAKE2b 摘要大小必须在1到64字节之间")

        self._digest_size = digest_size
        self.reset()

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._ctx = hashlib.blake2b(digest_size=self._digest_size)

    def update(self, data):
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Returns:
            self: 支持链式调用
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._ctx.update(data)
        return self

    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        return self._ctx.digest()

    def hexdigest(self) -> str:
        """
        返回当前数据的Hex 摘要

        Returns:
            str: Hex 格式的哈希摘要
        """
        return self._ctx.hexdigest()

    def copy(self) -> "BLAKE2bHash":
        """
        返回哈希对象的副本

        Returns:
            BLAKE2bHash: 当前哈希对象的副本
        """
        new_hash = BLAKE2bHash(digest_size=self._digest_size)
        new_hash._ctx = self._ctx.copy()
        return new_hash


class BLAKE2sHash(HashBase):
    """BLAKE2s 哈希算法实现 - 高性能版本"""

    def __init__(self, digest_size=32):
        """
        初始化 BLAKE2s 哈希对象

        Args:
            digest_size: 摘要大小, 1-32字节, 默认32

        Raises:
            ValueError: 如果摘要大小无效
        """
        if not 1 <= digest_size <= 32:
            raise ValueError("BLAKE2s 摘要大小必须在1到32字节之间")

        self._digest_size = digest_size
        self.reset()

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._ctx = hashlib.blake2s(digest_size=self._digest_size)

    def update(self, data):
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Returns:
            self: 支持链式调用
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._ctx.update(data)
        return self

    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        return self._ctx.digest()

    def hexdigest(self) -> str:
        """
        返回当前数据的Hex 摘要

        Returns:
            str: Hex 格式的哈希摘要
        """
        return self._ctx.hexdigest()

    def copy(self) -> "BLAKE2sHash":
        """
        返回哈希对象的副本

        Returns:
            BLAKE2sHash: 当前哈希对象的副本
        """
        new_hash = BLAKE2sHash(digest_size=self._digest_size)
        new_hash._ctx = self._ctx.copy()
        return new_hash


class BLAKE3Hash(HashBase):
    """BLAKE3 哈希算法实现"""

    def __init__(self):
        """
        初始化 BLAKE3 哈希对象

        """
        self._blake3_module = blake3
        self.reset()

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._ctx = self._blake3_module.blake3()

    def update(self, data):
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Returns:
            self: 支持链式调用
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._ctx.update(data)
        return self

    def digest(self, length=32) -> bytes:
        """
        返回当前数据的二进制摘要

        Args:
            length: 输出长度, 默认32字节

        Returns:
            bytes: 哈希摘要
        """
        return self._ctx.digest(length)

    def hexdigest(self, length=32) -> str:
        """
        返回当前数据的Hex 摘要

        Args:
            length: 输出长度, 默认32字节

        Returns:
            str: Hex 格式的哈希摘要
        """
        return self._ctx.hexdigest(length)

    def copy(self) -> "BLAKE3Hash":
        """
        返回哈希对象的副本

        Returns:
            BLAKE3Hash: 当前哈希对象的副本
        """
        new_hash = BLAKE3Hash()
        new_hash._ctx = self._ctx.copy()
        return new_hash
