"""
BLAKE 系列哈希算法实现

提供 BLAKE2b、BLAKE2s 和 BLAKE3 哈希算法的实现。
BLAKE2b 和 BLAKE2s 基于 cryptography 库，
BLAKE3 使用 blake3 库实现。
"""

import blake3
from typing import Union, Optional
from cryptography.hazmat.primitives import hashes
from .base import HashBase


class BLAKEHash(HashBase):
    """BLAKE 哈希算法基类"""

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


class BLAKE2bHash(BLAKEHash):
    """BLAKE2b 哈希算法实现，基于 cryptography 库"""

    @property
    def name(self) -> str:
        return "BLAKE2b"

    @property
    def digest_size(self) -> int:
        return self._digest_size

    @property
    def block_size(self) -> int:
        return 128

    def __init__(
        self,
        digest_size: int = 64,
        key: bytes = b"",
        salt: bytes = b"",
        person: bytes = b"",
    ):
        """
        初始化BLAKE2b哈希对象

        Args:
            digest_size: 摘要大小 (字节数), 1到64之间
            key: 可选的密钥
            salt: 可选的盐值 (最多16字节)
            person: 可选的个性化字符串 (最多16字节)

        Raises:
            ValueError: 如果参数值超出有效范围
            TypeError: 如果参数类型不正确
        """
        # 参数验证
        if not isinstance(digest_size, int):
            raise TypeError("digest_size必须是整数")
        if not 1 <= digest_size <= 64:
            raise ValueError("digest_size必须在1到64字节之间")

        if not isinstance(key, bytes):
            raise TypeError("key必须是字节类型")

        if not isinstance(salt, bytes):
            raise TypeError("salt必须是字节类型")
        if len(salt) > 16:
            raise ValueError("salt最多16字节")

        if not isinstance(person, bytes):
            raise TypeError("person必须是字节类型")
        if len(person) > 16:
            raise ValueError("person最多16字节")

        self._digest_size = digest_size
        self._key = key
        self._salt = salt
        self._person = person

        # 使用 cryptography 库的 BLAKE2b 实现
        self._algorithm = hashes.BLAKE2b(
            digest_size=digest_size,
            key=key if key else None,
            salt=salt if salt else None,
            person=person if person else None,
        )
        self._hash = hashes.Hash(self._algorithm)

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

    def copy(self) -> "BLAKE2bHash":
        """
        返回哈希对象的副本

        Returns:
            BLAKE2bHash: 当前哈希对象的副本
        """
        new_hash = BLAKE2bHash(
            digest_size=self._digest_size,
            key=self._key,
            salt=self._salt,
            person=self._person,
        )
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = hashes.Hash(self._algorithm)


class BLAKE2sHash(BLAKEHash):
    """BLAKE2s 哈希算法实现，基于 cryptography 库"""

    @property
    def name(self) -> str:
        return "BLAKE2s"

    @property
    def digest_size(self) -> int:
        return self._digest_size

    @property
    def block_size(self) -> int:
        return 64

    def __init__(
        self,
        digest_size: int = 32,
        key: bytes = b"",
        salt: bytes = b"",
        person: bytes = b"",
    ):
        """
        初始化BLAKE2s哈希对象

        Args:
            digest_size: 摘要大小 (字节数), 1到32之间
            key: 可选的密钥
            salt: 可选的盐值 (最多8字节)
            person: 可选的个性化字符串 (最多8字节)

        Raises:
            ValueError: 如果参数值超出有效范围
            TypeError: 如果参数类型不正确
        """
        # 参数验证
        if not isinstance(digest_size, int):
            raise TypeError("digest_size必须是整数")
        if not 1 <= digest_size <= 32:
            raise ValueError("digest_size必须在1到32字节之间")

        if not isinstance(key, bytes):
            raise TypeError("key必须是字节类型")

        if not isinstance(salt, bytes):
            raise TypeError("salt必须是字节类型")
        if len(salt) > 8:
            raise ValueError("salt最多8字节")

        if not isinstance(person, bytes):
            raise TypeError("person必须是字节类型")
        if len(person) > 8:
            raise ValueError("person最多8字节")

        self._digest_size = digest_size
        self._key = key
        self._salt = salt
        self._person = person

        # 使用 cryptography 库的 BLAKE2s 实现
        self._algorithm = hashes.BLAKE2s(
            digest_size=digest_size,
            key=key if key else None,
            salt=salt if salt else None,
            person=person if person else None,
        )
        self._hash = hashes.Hash(self._algorithm)

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

    def copy(self) -> "BLAKE2sHash":
        """
        返回哈希对象的副本

        Returns:
            BLAKE2sHash: 当前哈希对象的副本
        """
        new_hash = BLAKE2sHash(
            digest_size=self._digest_size,
            key=self._key,
            salt=self._salt,
            person=self._person,
        )
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = hashes.Hash(self._algorithm)


class BLAKE3Hash(BLAKEHash):
    """BLAKE3 哈希算法实现，使用 blake3 库"""

    @property
    def name(self) -> str:
        return "BLAKE3"

    @property
    def digest_size(self) -> int:
        return 32  # BLAKE3 默认摘要大小是 32 字节

    @property
    def block_size(self) -> int:
        return 64  # BLAKE3 的块大小是 64 字节

    def __init__(self, key: bytes = b""):
        """
        初始化BLAKE3哈希对象

        Args:
            key: 可选的密钥。如果提供, 将使用keyed哈希模式

        Raises:
            RuntimeError: 如果系统不支持BLAKE3算法
        """
        if not isinstance(key, bytes):
            raise TypeError("key必须是字节类型")

        self._key = key

        try:
            if key:
                self._hash = blake3.blake3(key=key)
            else:
                self._hash = blake3.blake3()
        except Exception as e:
            raise RuntimeError(f"BLAKE3初始化失败: {str(e)}")

    def copy(self) -> "BLAKE3Hash":
        """
        返回哈希对象的副本

        Returns:
            BLAKE3Hash: 当前哈希对象的副本
        """
        new_hash = BLAKE3Hash(key=self._key)
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        if self._key:
            self._hash = blake3.blake3(key=self._key)
        else:
            self._hash = blake3.blake3()

    def digest(self, length: Optional[int] = None) -> bytes:
        """
        返回当前数据的二进制摘要

        Args:
            length: 可选的输出长度 (字节)。BLAKE3支持任意输出长度。

        Returns:
            bytes: 哈希摘要
        """
        if length is not None:
            return self._hash.digest(length)
        return self._hash.digest()

    def hexdigest(self, length: Optional[int] = None) -> str:
        """
        返回当前数据的十六进制摘要

        Args:
            length: 可选的输出长度 (字节)。BLAKE3支持任意输出长度。

        Returns:
            str: 十六进制格式的哈希摘要
        """
        if length is not None:
            return self._hash.hexdigest(length)
        return self._hash.hexdigest()
