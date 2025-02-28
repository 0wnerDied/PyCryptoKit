"""
MD5 哈希算法实现

MD5 (Message-Digest Algorithm 5) 是一种广泛使用的哈希函数，
生成一个 128 位的哈希值。

注意: MD5 已被证明存在安全漏洞，不应用于安全场景。
推荐使用 SHA-256 或更安全的哈希算法。
"""

from typing import Union
from cryptography.hazmat.primitives import hashes
from .base import HashBase


class MD5Hash(HashBase):
    """
    MD5 哈希算法实现类

    基于 cryptography 库的 MD5 实现
    """

    @property
    def name(self) -> str:
        return "MD5"

    @property
    def digest_size(self) -> int:
        return 16

    @property
    def block_size(self) -> int:
        return 64

    def __init__(self):
        """初始化 MD5 哈希对象"""
        self._algorithm = hashes.MD5()
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

    def copy(self) -> "MD5Hash":
        """
        返回哈希对象的副本

        Returns:
            MD5Hash: 当前哈希对象的副本
        """
        new_hash = MD5Hash()
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = hashes.Hash(self._algorithm)
