"""
SHA 系列哈希算法实现
"""

import hashlib
from typing import Union, Optional, Type, TypeVar

from .base import HashBase

T = TypeVar("T", bound="SHAHash")


class SHAHash(HashBase):
    """SHA 哈希算法基类"""

    def __init__(self, algorithm: str):
        """
        初始化SHA哈希对象

        Args:
            algorithm: SHA算法名称
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

    def copy(self: T) -> T:
        """返回哈希对象的副本"""
        # 这个方法不应该被直接调用，应该在子类中实现
        raise NotImplementedError("子类应该实现此方法")

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._hash = getattr(hashlib, self._algorithm)()


class SHA1Hash(SHAHash):
    """SHA-1 哈希算法实现"""

    def __init__(self):
        """初始化SHA-1哈希对象"""
        super().__init__("sha1")

    def copy(self) -> "SHA1Hash":
        """返回哈希对象的副本"""
        new_hash = SHA1Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA224Hash(SHAHash):
    """SHA-224 哈希算法实现"""

    def __init__(self):
        """初始化SHA-224哈希对象"""
        super().__init__("sha224")

    def copy(self) -> "SHA224Hash":
        """返回哈希对象的副本"""
        new_hash = SHA224Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA256Hash(SHAHash):
    """SHA-256 哈希算法实现"""

    def __init__(self):
        """初始化SHA-256哈希对象"""
        super().__init__("sha256")

    def copy(self) -> "SHA256Hash":
        """返回哈希对象的副本"""
        new_hash = SHA256Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA384Hash(SHAHash):
    """SHA-384 哈希算法实现"""

    def __init__(self):
        """初始化SHA-384哈希对象"""
        super().__init__("sha384")

    def copy(self) -> "SHA384Hash":
        """返回哈希对象的副本"""
        new_hash = SHA384Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


class SHA512Hash(SHAHash):
    """SHA-512 哈希算法实现"""

    def __init__(self):
        """初始化SHA-512哈希对象"""
        super().__init__("sha512")

    def copy(self) -> "SHA512Hash":
        """返回哈希对象的副本"""
        new_hash = SHA512Hash()
        new_hash._hash = self._hash.copy()
        return new_hash


# 辅助函数
def _create_sha_function(cls: Type[HashBase]):
    """创建SHA哈希函数"""

    def hash_func(
        data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
    ) -> Union[bytes, HashBase]:
        hash_obj = cls()
        if data is not None:
            return hash_obj.hash_data(data, encoding)
        return hash_obj

    return hash_func


# 导出函数
sha1 = _create_sha_function(SHA1Hash)
sha224 = _create_sha_function(SHA224Hash)
sha256 = _create_sha_function(SHA256Hash)
sha384 = _create_sha_function(SHA384Hash)
sha512 = _create_sha_function(SHA512Hash)
