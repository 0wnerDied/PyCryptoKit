from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Dict, Optional, Union, Any
import xml.etree.ElementTree as ET
import base64

from .base import SignatureBase


class ECDSASignature(SignatureBase):
    """ECDSA 签名实现类"""

    # 支持的椭圆曲线
    SUPPORTED_CURVES = {
        "SECP192R1": ec.SECP192R1(),
        "SECP224R1": ec.SECP224R1(),
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
        "SECP521R1": ec.SECP521R1(),
        "SECP256K1": ec.SECP256K1(),
        "SECT163K1": ec.SECT163K1(),
        "SECT233K1": ec.SECT233K1(),
        "SECT283K1": ec.SECT283K1(),
        "SECT409K1": ec.SECT409K1(),
        "SECT571K1": ec.SECT571K1(),
        "SECT163R2": ec.SECT163R2(),
        "SECT233R1": ec.SECT233R1(),
        "SECT283R1": ec.SECT283R1(),
        "SECT409R1": ec.SECT409R1(),
        "SECT571R1": ec.SECT571R1(),
        "BRAINPOOLP256R1": ec.BrainpoolP256R1(),
        "BRAINPOOLP384R1": ec.BrainpoolP384R1(),
        "BRAINPOOLP512R1": ec.BrainpoolP512R1(),
    }
    DEFAULT_CURVE = "SECP256R1"

    # OpenSSH格式支持的ECC曲线列表
    OPENSSH_SUPPORTED_CURVES = ["SECP256R1", "SECP384R1", "SECP521R1"]

    # 支持的哈希算法
    SUPPORTED_HASH_ALGORITHMS = {
        "MD5": hashes.MD5(),
        "SHA1": hashes.SHA1(),
        "SHA3_224": hashes.SHA3_224(),
        "SHA3_256": hashes.SHA3_256(),
        "SHA3_384": hashes.SHA3_384(),
        "SHA3_512": hashes.SHA3_512(),
        "SHA224": hashes.SHA224(),
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
        "SHA512_224": hashes.SHA512_224(),
        "SHA512_256": hashes.SHA512_256(),
        "SM3": hashes.SM3(),
    }
    DEFAULT_HASH = "SHA256"

    def __init__(self, curve=None, hash_algorithm=None):
        """初始化 ECDSA 签名类

        Args:
            curve: 椭圆曲线, 默认为 SECP256R1
            hash_algorithm: 哈希算法, 默认为 SHA256
        """
        # 设置曲线
        if curve is None:
            self.curve = self.SUPPORTED_CURVES[self.DEFAULT_CURVE]
        elif isinstance(curve, str):
            curve_name = curve.upper()
            if curve_name in self.SUPPORTED_CURVES:
                self.curve = self.SUPPORTED_CURVES[curve_name]
            else:
                raise ValueError(f"不支持的椭圆曲线: {curve}")
        else:
            # 假设已经是曲线实例
            self.curve = curve

        # 设置哈希算法
        if hash_algorithm is None:
            self.hash_algorithm = self.SUPPORTED_HASH_ALGORITHMS[self.DEFAULT_HASH]
        elif isinstance(hash_algorithm, str):
            hash_name = hash_algorithm.upper()
            if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                self.hash_algorithm = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
            else:
                raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
        else:
            # 假设已经是哈希算法实例
            self.hash_algorithm = hash_algorithm

    def set_hash_algorithm(self, hash_algorithm: Any) -> None:
        """设置哈希算法

        Args:
            hash_algorithm: 哈希算法对象或算法名称
        """
        if isinstance(hash_algorithm, str):
            hash_name = hash_algorithm.upper()
            if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                self.hash_algorithm = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
            else:
                raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
        else:
            # 假设已经是哈希算法实例
            self.hash_algorithm = hash_algorithm

    def set_curve(self, curve: Any) -> None:
        """设置椭圆曲线

        Args:
            curve: 椭圆曲线对象或曲线名称
        """
        if isinstance(curve, str):
            curve_name = curve.upper()
            if curve_name in self.SUPPORTED_CURVES:
                self.curve = self.SUPPORTED_CURVES[curve_name]
            else:
                raise ValueError(f"不支持的椭圆曲线: {curve}")
        else:
            # 假设已经是曲线实例
            self.curve = curve

    def get_supported_key_sizes(self) -> Dict[str, int]:
        """获取支持的密钥长度

        注意: ECDSA密钥长度由曲线决定, 不能直接指定

        Returns:
            Dict[str, int]: 密钥长度名称和对应的位数
        """
        return {
            "注意": "ECDSA密钥长度由曲线决定, 请使用set_curve方法设置曲线",
            "支持的曲线": list(self.SUPPORTED_CURVES.keys()),
            "OpenSSH支持的曲线": self.OPENSSH_SUPPORTED_CURVES,
        }

    def get_supported_hash_algorithms(self) -> Dict[str, Any]:
        """获取支持的哈希算法

        Returns:
            Dict[str, Any]: 哈希算法名称和对应的算法对象
        """
        return self.SUPPORTED_HASH_ALGORITHMS.copy()

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        hash_algorithm: Any = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bytes:
        """使用 ECDSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: ECDSA 私钥对象或私钥数据
            password: 私钥密码 (如果私钥已加密)
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 使用提供的哈希算法或默认值
        hash_alg = self.hash_algorithm
        if hash_algorithm is not None:
            if isinstance(hash_algorithm, str):
                hash_name = hash_algorithm.upper()
                if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                    hash_alg = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
                else:
                    raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
            else:
                hash_alg = hash_algorithm

        # 如果 private_key 不是密钥对象, 则加载它
        if not hasattr(private_key, "sign"):
            private_key = self._load_private_key(private_key, password, key_format)

        signature = private_key.sign(data, ec.ECDSA(hash_alg))
        return signature

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        hash_algorithm: Any = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bool:
        """使用 ECDSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: ECDSA 公钥对象或公钥数据
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 使用提供的哈希算法或默认值
        hash_alg = self.hash_algorithm
        if hash_algorithm is not None:
            if isinstance(hash_algorithm, str):
                hash_name = hash_algorithm.upper()
                if hash_name in self.SUPPORTED_HASH_ALGORITHMS:
                    hash_alg = self.SUPPORTED_HASH_ALGORITHMS[hash_name]
                else:
                    raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
            else:
                hash_alg = hash_algorithm

        # 如果 public_key 不是密钥对象, 则加载它
        if not hasattr(public_key, "verify"):
            public_key = self._load_public_key(public_key, key_format)

        try:
            public_key.verify(signature, data, ec.ECDSA(hash_alg))
            return True
        except InvalidSignature:
            return False

    def load_private_key(
        self, path: str, password: Optional[bytes] = None, format: str = "Auto"
    ):
        """从文件加载 ECDSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码, 如果有加密
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            ECDSA 私钥对象
        """
        with open(path, "rb") as f:
            key_data = f.read()

        return self._load_private_key(key_data, password, format)

    def load_public_key(self, path: str, format: str = "Auto"):
        """从文件加载 ECDSA 公钥

        Args:
            path: 公钥文件路径
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            ECDSA 公钥对象
        """
        with open(path, "rb") as f:
            key_data = f.read()

        return self._load_public_key(key_data, format)

    def _load_private_key(
        self, key_data, password: Optional[bytes] = None, format: str = "Auto"
    ):
        """内部方法：加载 ECDSA 私钥

        Args:
            key_data: 私钥数据
            password: 私钥密码, 如果有加密
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            ECDSA 私钥对象
        """
        # 如果已经是私钥对象，直接返回
        if hasattr(key_data, "sign"):
            return key_data

        # 如果是字符串，检查是否是XML格式
        if isinstance(key_data, str):
            if format == "Auto" and key_data.strip().startswith("<"):
                return self._load_private_key_from_xml(key_data)
            elif format == "XML":
                return self._load_private_key_from_xml(key_data)
            else:
                key_data = key_data.encode()

        # 自动检测格式
        if format == "Auto":
            try:
                return serialization.load_pem_private_key(key_data, password=password)
            except ValueError:
                try:
                    return serialization.load_der_private_key(
                        key_data, password=password
                    )
                except ValueError:
                    try:
                        return serialization.load_ssh_private_key(
                            key_data, password=password
                        )
                    except ValueError:
                        try:
                            return self._load_private_key_from_xml(
                                key_data.decode("utf-8", errors="ignore")
                            )
                        except:
                            raise ValueError("无法自动识别私钥格式")
        elif format == "PEM":
            return serialization.load_pem_private_key(key_data, password=password)
        elif format == "DER":
            return serialization.load_der_private_key(key_data, password=password)
        elif format == "OpenSSH":
            # 加载密钥
            key = serialization.load_ssh_private_key(key_data, password=password)

            # 检查是否是ECDSA密钥并验证曲线类型
            if isinstance(key.curve, ec.EllipticCurve):
                curve_name = None
                # 从密钥中获取曲线名称
                for name, curve_obj in self.SUPPORTED_CURVES.items():
                    if isinstance(key.curve, type(curve_obj)):
                        curve_name = name
                        break

                # 验证曲线是否在OpenSSH支持列表中
                if curve_name and curve_name not in self.OPENSSH_SUPPORTED_CURVES:
                    raise ValueError(
                        f"OpenSSH格式不支持{curve_name}曲线的ECDSA密钥, 仅支持: {', '.join(self.OPENSSH_SUPPORTED_CURVES)}"
                    )

            return key
        elif format == "XML":
            if isinstance(key_data, bytes):
                key_data = key_data.decode("utf-8", errors="ignore")
            return self._load_private_key_from_xml(key_data)
        else:
            raise ValueError(f"不支持的密钥格式: {format}")

    def _load_public_key(self, key_data, format: str = "Auto"):
        """内部方法：加载 ECDSA 公钥

        Args:
            key_data: 公钥数据
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            ECDSA 公钥对象
        """
        # 如果已经是公钥对象，直接返回
        if hasattr(key_data, "verify"):
            return key_data

        # 如果是字符串，检查是否是XML格式
        if isinstance(key_data, str):
            if format == "Auto" and key_data.strip().startswith("<"):
                return self._load_public_key_from_xml(key_data)
            elif format == "XML":
                return self._load_public_key_from_xml(key_data)
            else:
                key_data = key_data.encode()

        # 自动检测格式
        if format == "Auto":
            try:
                return serialization.load_pem_public_key(key_data)
            except ValueError:
                try:
                    return serialization.load_der_public_key(key_data)
                except ValueError:
                    try:
                        return serialization.load_ssh_public_key(key_data)
                    except ValueError:
                        try:
                            return self._load_public_key_from_xml(
                                key_data.decode("utf-8", errors="ignore")
                            )
                        except:
                            raise ValueError("无法自动识别公钥格式")
        elif format == "PEM":
            return serialization.load_pem_public_key(key_data)
        elif format == "DER":
            return serialization.load_der_public_key(key_data)
        elif format == "OpenSSH":
            # 加载密钥
            key = serialization.load_ssh_public_key(key_data)

            # 检查是否是ECDSA密钥并验证曲线类型
            if isinstance(key.curve, ec.EllipticCurve):
                curve_name = None
                # 从密钥中获取曲线名称
                for name, curve_obj in self.SUPPORTED_CURVES.items():
                    if isinstance(key.curve, type(curve_obj)):
                        curve_name = name
                        break

                # 验证曲线是否在OpenSSH支持列表中
                if curve_name and curve_name not in self.OPENSSH_SUPPORTED_CURVES:
                    raise ValueError(
                        f"OpenSSH格式不支持{curve_name}曲线的ECDSA密钥, 仅支持: {', '.join(self.OPENSSH_SUPPORTED_CURVES)}"
                    )

            return key
        elif format == "XML":
            if isinstance(key_data, bytes):
                key_data = key_data.decode("utf-8", errors="ignore")
            return self._load_public_key_from_xml(key_data)
        else:
            raise ValueError(f"不支持的密钥格式: {format}")

    def _load_private_key_from_xml(self, xml_data):
        """从XML加载ECDSA私钥

        Args:
            xml_data: XML格式的私钥数据

        Returns:
            ECDSA私钥对象
        """
        try:
            # 解析XML
            root = ET.fromstring(xml_data)

            # 获取曲线名称
            curve_name = root.find("Curve").text.upper()
            if curve_name not in self.SUPPORTED_CURVES:
                raise ValueError(f"不支持的椭圆曲线: {curve_name}")

            # 获取私钥值
            d_b64 = root.find("D").text
            d = int.from_bytes(base64.b64decode(d_b64), byteorder="big")

            # 获取公钥点坐标
            x_b64 = root.find("X").text
            y_b64 = root.find("Y").text
            x = int.from_bytes(base64.b64decode(x_b64), byteorder="big")
            y = int.from_bytes(base64.b64decode(y_b64), byteorder="big")

            # 创建公钥和私钥数字
            curve = self.SUPPORTED_CURVES[curve_name]
            public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
            private_numbers = ec.EllipticCurvePrivateNumbers(
                private_value=d, public_numbers=public_numbers
            )

            # 生成私钥对象
            return private_numbers.private_key()
        except Exception as e:
            raise ValueError(f"无法从XML加载ECDSA私钥: {str(e)}")

    def _load_public_key_from_xml(self, xml_data):
        """从XML加载ECDSA公钥

        Args:
            xml_data: XML格式的公钥数据

        Returns:
            ECDSA公钥对象
        """
        try:
            # 解析XML
            root = ET.fromstring(xml_data)

            # 获取曲线名称
            curve_name = root.find("Curve").text.upper()
            if curve_name not in self.SUPPORTED_CURVES:
                raise ValueError(f"不支持的椭圆曲线: {curve_name}")

            # 获取公钥点坐标
            x_b64 = root.find("X").text
            y_b64 = root.find("Y").text
            x = int.from_bytes(base64.b64decode(x_b64), byteorder="big")
            y = int.from_bytes(base64.b64decode(y_b64), byteorder="big")

            # 创建公钥数字
            curve = self.SUPPORTED_CURVES[curve_name]
            public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)

            # 生成公钥对象
            return public_numbers.public_key()
        except Exception as e:
            raise ValueError(f"无法从XML加载ECDSA公钥: {str(e)}")

    def _ensure_bytes(self, data: Union[bytes, str]) -> bytes:
        """确保数据为字节类型

        Args:
            data: 输入数据, 可以是字符串或字节

        Returns:
            bytes: 字节类型的数据
        """
        if isinstance(data, str):
            return data.encode("utf-8")
        return data
