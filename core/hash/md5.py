"""
MD5 哈希算法实现
"""

import hashlib
from typing import Union, Optional

from .base import HashBase


class MD5Hash(HashBase):
    """MD5 哈希算法实现"""

    def __init__(self):
        """初始化MD5哈希对象"""
        self._md5 = hashlib.md5()

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """更新哈希对象的状态"""
        self._md5.update(data)

    def digest(self) -> bytes:
        """返回当前数据的二进制摘要"""
        return self._md5.digest()

    def hexdigest(self) -> str:
        """返回当前数据的十六进制摘要"""
        return self._md5.hexdigest()

    def copy(self) -> "MD5Hash":
        """返回哈希对象的副本"""
        new_hash = MD5Hash()
        new_hash._md5 = self._md5.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._md5 = hashlib.md5()


def MD5(
    data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
) -> Union[bytes, MD5Hash]:
    """
    计算数据的MD5哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回未更新的哈希对象
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, MD5Hash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象
    """
    hash_obj = MD5Hash()
    if data is not None:
        return hash_obj.hash_data(data, encoding)
    return hash_obj
