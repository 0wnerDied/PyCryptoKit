"""
哈希算法工厂模块

提供创建各种哈希算法实例的工厂类和方法
"""

from typing import Any, Dict, List

from .base import HashBase
from . import HASH_ALGORITHMS, ALL_ALGORITHMS, SECURE_ALGORITHMS


class HashFactory:
    """哈希算法工厂类"""

    @staticmethod
    def get_algorithm_info(algorithm: str) -> Dict[str, Any]:
        """
        获取算法信息

        Args:
            algorithm: 算法名称

        Returns:
            Dict: 包含算法信息的字典，格式为:
                {
                    "name": 算法名称,
                    "class": 类名,
                    "secure": 是否安全,
                    "description": 算法描述,
                    "default_params": 默认参数
                }

        Raises:
            ValueError: 如果算法不存在
        """
        if algorithm not in HASH_ALGORITHMS:
            raise ValueError(
                f"不支持的哈希算法: {algorithm}. 支持的算法: {', '.join(ALL_ALGORITHMS)}"
            )

        cls, is_secure, description, default_params = HASH_ALGORITHMS[algorithm]

        return {
            "name": algorithm,
            "class": cls.__name__,
            "secure": is_secure,
            "description": description,
            "default_params": default_params.copy(),
        }

    @staticmethod
    def list_algorithms(secure_only: bool = False) -> List[str]:
        """
        列出支持的哈希算法

        Args:
            secure_only: 如果为True, 只返回安全的算法

        Returns:
            List[str]: 算法名称列表
        """
        return SECURE_ALGORITHMS.copy() if secure_only else ALL_ALGORITHMS.copy()

    @staticmethod
    def create(algorithm: str, **kwargs) -> HashBase:
        """
        创建哈希算法实例

        Args:
            algorithm: 算法名称
            **kwargs: 传递给哈希算法构造函数的参数

        Returns:
            HashBase: 哈希算法实例

        Raises:
            ValueError: 如果算法不存在或参数无效
            TypeError: 如果参数类型不正确
            RuntimeError: 如果创建实例失败
        """
        if algorithm not in HASH_ALGORITHMS:
            raise ValueError(
                f"不支持的哈希算法: {algorithm}. 支持的算法: {', '.join(ALL_ALGORITHMS)}"
            )

        # 获取算法类和默认参数
        cls, _, _, default_params = HASH_ALGORITHMS[algorithm]

        # 合并默认参数和用户提供的参数
        params = default_params.copy()
        for key, value in kwargs.items():
            if key in params or not params:
                # 如果参数在默认参数列表中，或者默认参数为空（表示算法不需要特定参数）
                params[key] = value
            else:
                # 如果参数不在默认参数列表中，且不是空字典，则可能是无效参数
                raise ValueError(
                    f"算法 {algorithm} 不支持参数: {key}. 支持的参数: {', '.join(default_params.keys())}"
                )

        # 创建实例
        try:
            return cls(**params)
        except TypeError as e:
            raise TypeError(f"创建 {algorithm} 哈希实例失败: 参数类型错误 - {e}")
        except ValueError as e:
            raise ValueError(f"创建 {algorithm} 哈希实例失败: 参数值无效 - {e}")
        except Exception as e:
            raise RuntimeError(f"创建 {algorithm} 哈希实例失败: {e}")
