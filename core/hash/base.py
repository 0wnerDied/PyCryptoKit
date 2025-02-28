"""
基础哈希接口定义
"""

import hmac
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union, BinaryIO


class HashBase(ABC):
    """哈希算法基类"""

    @abstractmethod
    def update(self, data: Union[str, bytes, bytearray, memoryview]) -> None:
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的数据

        Raises:
            TypeError: 如果数据类型不受支持
        """
        pass

    @abstractmethod
    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        pass

    @abstractmethod
    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        pass

    @abstractmethod
    def copy(self) -> "HashBase":
        """
        返回哈希对象的副本

        Returns:
            HashBase: 当前哈希对象的副本
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """重置哈希对象的状态"""
        pass
