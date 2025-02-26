"""
BLAKE 系列哈希算法实现
"""

import hashlib
from abc import abstractmethod
from typing import Union, Optional

from .base import HashBase


class BLAKEHash(HashBase):
    """BLAKE 哈希算法基类"""

    def __init__(self):
        """初始化BLAKE哈希对象"""
        self._hash = None  # 将在子类中初始化

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
        return self._hash.digest()

    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        return self._hash.hexdigest()

    @abstractmethod
    def copy(self) -> "BLAKEHash":
        """
        返回哈希对象的副本

        Returns:
            BLAKEHash: 当前哈希对象的副本
        """
        raise NotImplementedError("子类必须实现此方法")

    @abstractmethod
    def reset(self) -> None:
        """重置哈希对象的状态"""
        raise NotImplementedError("子类必须实现此方法")


class BLAKE2bHash(BLAKEHash):
    """BLAKE2b 哈希算法实现"""

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
            RuntimeError: 如果系统不支持BLAKE2b算法
        """
        super().__init__()

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

        try:
            self._hash = hashlib.blake2b(
                digest_size=digest_size, key=key, salt=salt, person=person
            )
        except AttributeError:
            raise RuntimeError("当前系统不支持BLAKE2b算法")

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
        self._hash = hashlib.blake2b(
            digest_size=self._digest_size,
            key=self._key,
            salt=self._salt,
            person=self._person,
        )


class BLAKE2sHash(BLAKEHash):
    """BLAKE2s 哈希算法实现"""

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
            RuntimeError: 如果系统不支持BLAKE2s算法
        """
        super().__init__()

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

        try:
            self._hash = hashlib.blake2s(
                digest_size=digest_size, key=key, salt=salt, person=person
            )
        except AttributeError:
            raise RuntimeError("当前系统不支持BLAKE2s算法")

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
        self._hash = hashlib.blake2s(
            digest_size=self._digest_size,
            key=self._key,
            salt=self._salt,
            person=self._person,
        )


# 导出函数
def blake2b(
    data: Optional[Union[str, bytes, bytearray]] = None,
    digest_size: int = 64,
    key: bytes = b"",
    salt: bytes = b"",
    person: bytes = b"",
    encoding: str = "utf-8",
) -> Union[bytes, BLAKE2bHash]:
    """
    计算数据的BLAKE2b哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回哈希对象
        digest_size: 摘要大小 (字节数), 1到64之间
        key: 可选的密钥
        salt: 可选的盐值 (最多16字节)
        person: 可选的个性化字符串 (最多16字节)
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, BLAKE2bHash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象

    Raises:
        ValueError: 如果参数值无效
        TypeError: 如果参数类型不正确
        RuntimeError: 如果系统不支持BLAKE2b算法
    """
    hash_obj = BLAKE2bHash(digest_size, key, salt, person)
    if data is not None:
        return hash_obj.hash_data(data, encoding)
    return hash_obj


def blake2s(
    data: Optional[Union[str, bytes, bytearray]] = None,
    digest_size: int = 32,
    key: bytes = b"",
    salt: bytes = b"",
    person: bytes = b"",
    encoding: str = "utf-8",
) -> Union[bytes, BLAKE2sHash]:
    """
    计算数据的BLAKE2s哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回哈希对象
        digest_size: 摘要大小 (字节数), 1到32之间
        key: 可选的密钥
        salt: 可选的盐值 (最多8字节)
        person: 可选的个性化字符串 (最多8字节)
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, BLAKE2sHash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象

    Raises:
        ValueError: 如果参数值无效
        TypeError: 如果参数类型不正确
        RuntimeError: 如果系统不支持BLAKE2s算法
    """
    hash_obj = BLAKE2sHash(digest_size, key, salt, person)
    if data is not None:
        return hash_obj.hash_data(data, encoding)
    return hash_obj
