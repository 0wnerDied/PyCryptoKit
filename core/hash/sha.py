"""
SHA 系列哈希算法实现

提供 SHA1、SHA224、SHA256、SHA384、SHA512、SHA512_224 和 SHA512_256 哈希算法实现。
所有实现基于 cryptography 库。

注意: SHA1 已被证明不再安全, 不应用于安全场景。
推荐使用 SHA256 或更高级别的哈希算法。
"""

from cryptography.hazmat.primitives import hashes
from typing import Union

from .base import HashBase


class SHAHash(HashBase):
    """SHA 哈希算法基类"""

    def __init__(self, algorithm):
        """
        初始化 SHA 哈希对象

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


class SHA1Hash(SHAHash):
    """SHA-1 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA1"

    @property
    def digest_size(self) -> int:
        return 20

    @property
    def block_size(self) -> int:
        return 64

    def __init__(self):
        """初始化 SHA1 哈希对象"""
        super().__init__(hashes.SHA1())

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

    @property
    def name(self) -> str:
        return "SHA224"

    @property
    def digest_size(self) -> int:
        return 28

    @property
    def block_size(self) -> int:
        return 64

    def __init__(self):
        """初始化 SHA224 哈希对象"""
        super().__init__(hashes.SHA224())

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

    @property
    def name(self) -> str:
        return "SHA256"

    @property
    def digest_size(self) -> int:
        return 32

    @property
    def block_size(self) -> int:
        return 64

    def __init__(self):
        """初始化 SHA256 哈希对象"""
        super().__init__(hashes.SHA256())

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

    @property
    def name(self) -> str:
        return "SHA384"

    @property
    def digest_size(self) -> int:
        return 48

    @property
    def block_size(self) -> int:
        return 128

    def __init__(self):
        """初始化 SHA384 哈希对象"""
        super().__init__(hashes.SHA384())

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

    @property
    def name(self) -> str:
        return "SHA512"

    @property
    def digest_size(self) -> int:
        return 64

    @property
    def block_size(self) -> int:
        return 128

    def __init__(self):
        """初始化 SHA512 哈希对象"""
        super().__init__(hashes.SHA512())

    def copy(self) -> "SHA512Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA512Hash: 当前哈希对象的副本
        """
        new_hash = SHA512Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA512_224Hash(SHAHash):
    """SHA512_224 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA512_224"

    @property
    def digest_size(self) -> int:
        return 28

    @property
    def block_size(self) -> int:
        return 128

    def __init__(self):
        """初始化 SHA512_224 哈希对象"""
        super().__init__(hashes.SHA512_224())

    def copy(self) -> "SHA512_224Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA512_224Hash: 当前哈希对象的副本
        """
        new_hash = SHA512_224Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA512_256Hash(SHAHash):
    """SHA512_256 哈希算法实现"""

    @property
    def name(self) -> str:
        return "SHA512_256"

    @property
    def digest_size(self) -> int:
        return 32

    @property
    def block_size(self) -> int:
        return 128

    def __init__(self):
        """初始化 SHA512_256 哈希对象"""
        super().__init__(hashes.SHA512_256())

    def copy(self) -> "SHA512_256Hash":
        """
        返回哈希对象的副本

        Returns:
            SHA512_256Hash: 当前哈希对象的副本
        """
        new_hash = SHA512_256Hash()
        new_hash._hash = self._hash.copy()
        return new_hash
