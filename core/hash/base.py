"""
基础哈希接口定义
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union


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

    def hash_data(
        self, data: Union[str, bytes, bytearray], encoding: str = "utf-8"
    ) -> bytes:
        """
        计算数据的哈希值

        Args:
            data: 要计算哈希的数据
            encoding: 如果data是字符串, 指定编码方式

        Returns:
            bytes: 哈希摘要

        Raises:
            TypeError: 如果数据类型不受支持
            UnicodeError: 如果字符串编码失败
        """
        self.reset()

        # 检查数据类型
        if not isinstance(data, (str, bytes, bytearray)):
            raise TypeError(f"不支持的数据类型: {type(data).__name__}")

        # 如果是字符串, 转换为字节
        if isinstance(data, str):
            try:
                data = data.encode(encoding)
            except UnicodeError as e:
                raise UnicodeError(f"字符串编码失败: {e}")

        self.update(data)
        return self.digest()

    def hash_file(self, file_path: Union[str, Path], chunk_size: int = 8192) -> bytes:
        """
        计算文件的哈希值

        Args:
            file_path: 文件路径
            chunk_size: 每次读取的块大小

        Returns:
            bytes: 哈希摘要

        Raises:
            FileNotFoundError: 如果文件不存在
            IOError: 如果读取文件时出错
            ValueError: 如果chunk_size小于等于0
        """
        # 检查chunk_size参数
        if chunk_size <= 0:
            raise ValueError("chunk_size必须大于0")

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        if not file_path.is_file():
            raise ValueError(f"路径不是文件: {file_path}")

        self.reset()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    self.update(chunk)
            return self.digest()
        except IOError as e:
            raise IOError(f"读取文件时出错: {e}")
