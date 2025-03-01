"""
SM3 哈希算法实现

SM3 是中国国家密码管理局发布的密码杂凑算法标准，
输出长度为 256 位的哈希值。

本实现基于 cryptography 库提供的 SM3 算法。
"""

from cryptography.hazmat.primitives import hashes

from .base import HashBase


class SM3Hash(HashBase):
    """
    SM3 哈希算法实现类

    基于 cryptography 库的 SM3 实现
    """

    @property
    def name(self) -> str:
        return "SM3"

    @property
    def digest_size(self) -> int:
        return 32

    @property
    def block_size(self) -> int:
        return 64

    def __init__(self):
        """初始化 SM3 哈希对象"""
        self._algorithm = hashes.SM3()
        self._hash = hashes.Hash(self._algorithm)

    def update(self, data: bytes) -> None:
        """更新哈希对象的状态"""
        self._hash.update(data)

    def digest(self) -> bytes:
        """计算当前数据的哈希值"""
        # 创建副本以便不影响原始对象
        hash_copy = self._hash.copy()
        return hash_copy.finalize()

    def hexdigest(self) -> str:
        """计算当前数据的十六进制哈希值"""
        return self.digest().hex()

    def copy(self):
        """创建当前哈希对象的副本"""
        new_hash = SM3Hash()
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象状态"""
        self._hash = hashes.Hash(self._algorithm)
