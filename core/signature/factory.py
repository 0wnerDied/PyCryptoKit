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
    """签名算法工厂类, 用于创建不同的签名算法实例"""

    @staticmethod
    def get_algorithm_info(algorithm: str) -> Dict[str, Any]:
        """
        获取算法信息

        Args:
            algorithm: 算法名称

        Returns:
            Dict: 包含算法信息的字典, 格式为:
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
            algorithm: 算法名称, 如 "RSA", "ECDSA", "EdDSA"
            **kwargs: 传递给算法构造函数的参数
                      RSA 可接受: hash_algorithm, key_size
                      ECDSA 可接受: hash_algorithm, curve
                      EdDSA 可接受: curve, context

                      参数也可以使用中文键名:
                      "哈希算法" -> hash_algorithm
                      "密钥长度" -> key_size
                      "曲线" -> curve
                      "上下文" -> context

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

        # 处理特殊参数 (如哈希算法、曲线等)
        processed_kwargs = {}

        # 参数名称映射 (中文 -> 英文)
        param_mapping = {
            "哈希算法": "hash_algorithm",
            "密钥长度": "key_size",
            "曲线": "curve",
            "上下文": "context",
            "盐长度": "salt_length",
        }

        # 转换中文参数名称为英文
        for cn_name, en_name in param_mapping.items():
            if cn_name in kwargs:
                kwargs[en_name] = kwargs.pop(cn_name)

        # 处理哈希算法
        if "hash_algorithm" in kwargs:
            hash_alg = kwargs.pop("hash_algorithm")
            if isinstance(hash_alg, str):
                hash_alg = hash_alg.upper()
                # 检查是否是直接的哈希算法类名
                if hasattr(hashes, hash_alg):
                    processed_kwargs["hash_algorithm"] = getattr(hashes, hash_alg)()
                else:
                    raise ValueError(f"不支持的哈希算法: {hash_alg}")
            else:
                # 假设已经是哈希算法实例
                processed_kwargs["hash_algorithm"] = hash_alg

        # 处理椭圆曲线
        if "curve" in kwargs:
            curve = kwargs.pop("curve")
            if isinstance(curve, str):
                curve_name = curve.upper()
                if algorithm == "ECDSA":
                    # ECDSA 使用 cryptography 库的曲线
                    if hasattr(ec, curve_name) or curve_name in cls.SUPPORTED_CURVES:
                        if curve_name in cls.SUPPORTED_CURVES:
                            processed_kwargs["curve"] = cls.SUPPORTED_CURVES[curve_name]
                        else:
                            processed_kwargs["curve"] = getattr(ec, curve_name)()
                    else:
                        raise ValueError(f"不支持的椭圆曲线: {curve}")
                elif algorithm == "EdDSA":
                    # EdDSA 使用 Cryptodome 库的曲线
                    if curve in ["Ed25519", "Ed448"]:
                        processed_kwargs["curve"] = curve
                    else:
                        raise ValueError(
                            f"EdDSA 仅支持 Ed25519 或 Ed448 曲线, 不支持: {curve}"
                        )
            else:
                # 假设已经是曲线实例
                processed_kwargs["curve"] = curve

        # 处理密钥长度
        if "key_size" in kwargs:
            key_size = kwargs.pop("key_size")
            if algorithm == "RSA":
                if isinstance(key_size, int) and key_size in cls.SUPPORTED_KEY_SIZES:
                    processed_kwargs["key_size"] = key_size
                else:
                    raise ValueError(
                        f"不支持的RSA密钥长度: {key_size}。支持的长度: {list(cls.SUPPORTED_KEY_SIZES)}"
                    )
            elif algorithm in ["ECDSA", "EdDSA"]:
                # 对于ECDSA和EdDSA, 密钥长度由曲线决定, 忽略此参数
                pass

        # 处理EdDSA上下文
        if algorithm == "EdDSA" and "context" in kwargs:
            context = kwargs.pop("context")
            if isinstance(context, str):
                context = context.encode("utf-8")
            if len(context) > 255:
                raise ValueError("EdDSA 上下文数据不能超过 255 字节")
            processed_kwargs["context"] = context

        # 处理RSA-PSS盐长度
        if algorithm == "RSA_PSS" and "salt_length" in kwargs:
            salt_length = kwargs.pop("salt_length")
            if isinstance(salt_length, int) and salt_length > 0:
                processed_kwargs["salt_length"] = salt_length
            else:
                raise ValueError("RSA-PSS 盐长度必须是正整数")

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
            algorithm_class: 算法类, 必须继承自 SignatureBase
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
