"""
SM3 哈希算法实现

SM3 是中国国家密码管理局发布的密码杂凑算法标准，
输出长度为256位(32字节)的哈希值。

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
        return 32  # 256位 = 32字节

    @property
    def block_size(self) -> int:
        return 64  # SM3 的块大小为 512 位 = 64 字节

    def __init__(self):
        """初始化 SM3 哈希对象"""
        self._hash = hashes.Hash(hashes.SM3())

    def update(self, data: bytes) -> None:
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的字节数据
        """
        self._hash.update(data)

    def digest(self) -> bytes:
        """
        计算当前数据的哈希值

        Returns:
            bytes: 32字节的哈希值
        """
        # 创建副本以便不影响原始对象
        hash_copy = self._hash.copy()
        return hash_copy.finalize()

    def hexdigest(self) -> str:
        """
        计算当前数据的十六进制哈希值

        Returns:
            str: 64字符的十六进制哈希值
        """
        return self.digest().hex()

    def copy(self):
        """
        创建当前哈希对象的副本

        Returns:
            SM3Hash: 具有相同状态的新哈希对象
        """
        new_hash = SM3Hash()
        new_hash._hash = self._hash.copy()
        return new_hash

    def reset(self) -> None:
        """重置哈希对象状态"""
        self._hash = hashes.Hash(hashes.SM3())


# 测试代码
if __name__ == "__main__":
    # 测试向量
    test_data = b"abc"
    expected_hash = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

    # 创建哈希对象
    sm3 = SM3Hash()
    sm3.update(test_data)
    result = sm3.hexdigest()

    # 验证结果
    print(f"SM3('{test_data.decode()}') = {result}")
    print(f"验证结果: {'成功' if result == expected_hash else '失败'}")
