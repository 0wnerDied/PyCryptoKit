"""
国密 SM3 哈希算法实现
"""

from typing import Union, Optional
import binascii

from .base import HashBase

try:
    from gmssl import sm3

    GMSSL_AVAILABLE = True
except ImportError:
    GMSSL_AVAILABLE = False

    class GMSSLNotInstalledError(ImportError):
        """当GMSSL库未安装时抛出的异常"""

        def __init__(self):
            super().__init__("GMSSL库未安装, 请使用 'pip install gmssl' 安装")


class SM3Hash(HashBase):
    """SM3 哈希算法实现"""

    def __init__(self):
        """初始化SM3哈希对象"""
        if not GMSSL_AVAILABLE:
            raise GMSSLNotInstalledError()

        self._buffer = bytearray()
        self._sm3_ctx = sm3.SM3()

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的字节数据
        """
        if not GMSSL_AVAILABLE:
            raise GMSSLNotInstalledError()

        # 将数据添加到缓冲区
        self._buffer.extend(data)

    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        if not GMSSL_AVAILABLE:
            raise GMSSLNotInstalledError()

        # 计算哈希
        sm3_ctx = sm3.SM3()
        sm3_ctx.update(bytes(self._buffer))
        digest_hex = sm3_ctx.hexdigest()
        return binascii.unhexlify(digest_hex)

    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        if not GMSSL_AVAILABLE:
            raise GMSSLNotInstalledError()

        # 计算哈希
        sm3_ctx = sm3.SM3()
        sm3_ctx.update(bytes(self._buffer))
        return sm3_ctx.hexdigest()

    def copy(self) -> "SM3Hash":
        """
        返回哈希对象的副本

        Returns:
            SM3Hash: 当前哈希对象的副本
        """
        if not GMSSL_AVAILABLE:
            raise GMSSLNotInstalledError()

        new_hash = SM3Hash()
        new_hash._buffer = bytearray(self._buffer)
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        if not GMSSL_AVAILABLE:
            raise GMSSLNotInstalledError()

        self._buffer = bytearray()
        self._sm3_ctx = sm3.SM3()


def sm3_hash(
    data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
) -> Union[bytes, SM3Hash]:
    """
    计算数据的SM3哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回哈希对象
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, SM3Hash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象
    """
    if not GMSSL_AVAILABLE:
        raise GMSSLNotInstalledError()

    hash_obj = SM3Hash()
    if data is not None:
        return hash_obj.hash_data(data, encoding)
    return hash_obj


# 兼容性函数，与其他哈希算法保持一致的接口
def SM3(
    data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
) -> Union[bytes, SM3Hash]:
    """
    计算数据的SM3哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回哈希对象
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, SM3Hash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象
    """
    return sm3_hash(data, encoding)
