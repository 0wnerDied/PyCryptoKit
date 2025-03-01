"""
签名算法工厂模块

提供创建各种签名算法实例的工厂类和方法
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Any, Dict, List, Type

from .base import SignatureBase
from . import SIGNATURE_ALGORITHMS, ALL_ALGORITHMS


class SignatureFactory:
    """签名算法工厂类，用于创建不同的签名算法实例"""

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
                    "description": 算法描述,
                    "default_params": 默认参数
                }

        Raises:
            ValueError: 如果算法不存在
        """
        if algorithm not in SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"不支持的签名算法: {algorithm}. 支持的算法: {', '.join(ALL_ALGORITHMS)}"
            )

        cls, description, default_params = SIGNATURE_ALGORITHMS[algorithm]

        return {
            "name": algorithm,
            "class": cls.__name__,
            "description": description,
            "default_params": default_params.copy(),
        }

    @staticmethod
    def list_algorithms() -> List[str]:
        """
        列出支持的签名算法

        Returns:
            List[str]: 算法名称列表
        """
        return ALL_ALGORITHMS.copy()

    @staticmethod
    def create(algorithm: str, **kwargs) -> SignatureBase:
        """
        创建指定的签名算法实例

        Args:
            algorithm: 算法名称，如 "RSA", "ECDSA"
            **kwargs: 传递给算法构造函数的参数

        Returns:
            SignatureBase: 签名算法实例

        Raises:
            ValueError: 如果算法不存在或参数无效
            TypeError: 如果参数类型不正确
            RuntimeError: 如果创建实例失败
        """
        if algorithm not in SIGNATURE_ALGORITHMS:
            raise ValueError(
                f"不支持的签名算法: {algorithm}. 支持的算法: {', '.join(ALL_ALGORITHMS)}"
            )

        # 获取算法类和默认参数
        cls, _, default_params = SIGNATURE_ALGORITHMS[algorithm]

        # 处理特殊参数（如哈希算法、曲线等）
        processed_kwargs = {}

        # 处理哈希算法
        if "哈希算法" in kwargs:
            hash_alg = kwargs.pop("哈希算法")
            if isinstance(hash_alg, str):
                hash_alg = hash_alg.upper()
                if hasattr(hashes, hash_alg):
                    processed_kwargs["哈希算法"] = getattr(hashes, hash_alg)()
                else:
                    raise ValueError(f"不支持的哈希算法: {hash_alg}")
            else:
                # 假设已经是哈希算法实例
                processed_kwargs["哈希算法"] = hash_alg

        # 处理椭圆曲线（仅适用于 ECDSA）
        if algorithm == "ECDSA" and "曲线" in kwargs:
            curve = kwargs.pop("曲线")
            if isinstance(curve, str):
                curve = curve.upper()
                if hasattr(ec, curve):
                    processed_kwargs["曲线"] = getattr(ec, curve)()
                else:
                    raise ValueError(f"不支持的椭圆曲线: {curve}")
            else:
                # 假设已经是曲线实例
                processed_kwargs["曲线"] = curve

        # 合并其他参数
        processed_kwargs.update(kwargs)

        # 创建实例
        try:
            return cls(**processed_kwargs)
        except TypeError as e:
            raise TypeError(f"创建 {algorithm} 签名实例失败: 参数类型错误 - {e}")
        except ValueError as e:
            raise ValueError(f"创建 {algorithm} 签名实例失败: 参数值无效 - {e}")
        except Exception as e:
            raise RuntimeError(f"创建 {algorithm} 签名实例失败: {e}")

    @classmethod
    def register_algorithm(
        cls,
        name: str,
        algorithm_class: Type[SignatureBase],
        description: str,
        default_params: Dict[str, Any] = None,
    ) -> None:
        """
        注册新的签名算法

        Args:
            name: 算法名称
            algorithm_class: 算法类，必须继承自 SignatureBase
            description: 算法描述
            default_params: 默认参数

        Raises:
            TypeError: 如果算法类不是 SignatureBase 的子类
        """
        if not issubclass(algorithm_class, SignatureBase):
            raise TypeError("算法类必须继承自 SignatureBase")

        if default_params is None:
            default_params = {}

        SIGNATURE_ALGORITHMS[name] = (algorithm_class, description, default_params)
        # 更新算法列表
        global ALL_ALGORITHMS
        ALL_ALGORITHMS = list(SIGNATURE_ALGORITHMS.keys())
