from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from typing import Dict, Literal, Optional, Union, Any
import xml.etree.ElementTree as ET
import base64

from .base import SignatureBase


class RSASignature(SignatureBase):
    """RSA 签名实现类, 支持 PKCS#1 v1.5 和 PSS 两种填充方式"""

    # 支持的密钥长度
    SUPPORTED_KEY_SIZES = {1024, 2048, 3072, 4096}
    DEFAULT_KEY_SIZE = 2048

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

    def __init__(self, hash_algorithm=None):
        """初始化 RSA 签名类

        Args:
            hash_algorithm: 哈希算法, 默认为 SHA256
        """
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

    def get_supported_key_sizes(self) -> Dict[str, int]:
        """获取支持的密钥长度

        Returns:
            Dict[str, int]: 密钥长度名称和对应的位数
        """
        return {
            "最小": min(self.SUPPORTED_KEY_SIZES),
            "默认": self.DEFAULT_KEY_SIZE,
            "最大": max(self.SUPPORTED_KEY_SIZES),
            "支持的值": list(self.SUPPORTED_KEY_SIZES),
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
        padding_mode: Literal["pkcs1v15", "pss"] = "pkcs1v15",
        pss_salt_length: int = 32,
        hash_algorithm: Any = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bytes:
        """使用 RSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: RSA 私钥对象或私钥数据
            password: 私钥密码 (如果私钥已加密)
            padding_mode: 填充模式, 可选 "pkcs1v15" (传统RSA) 或 "pss" (RSA-PSS)
            pss_salt_length: PSS 模式的盐长度, 仅在 padding_mode="pss" 时使用
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

        # 如果 private_key 是字节数据或字符串, 则加载它
        if not hasattr(private_key, "sign"):
            private_key = self._load_private_key(private_key, password, key_format)

        # 根据填充模式选择不同的填充算法
        if padding_mode == "pss":
            padding_algorithm = padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=pss_salt_length,
            )
        else:  # 默认使用 pkcs1v15
            padding_algorithm = padding.PKCS1v15()

        # 执行签名
        signature = private_key.sign(
            data,
            padding_algorithm,
            hash_alg,
        )
        return signature

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        padding_mode: Literal["pkcs1v15", "pss"] = "pkcs1v15",
        pss_salt_length: int = 32,
        hash_algorithm: Any = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bool:
        """使用 RSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥对象或公钥数据
            padding_mode: 填充模式, 可选 "pkcs1v15" (传统RSA) 或 "pss" (RSA-PSS)
            pss_salt_length: PSS 模式的盐长度, 仅在 padding_mode="pss" 时使用
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

        # 如果 public_key 是字节数据或字符串, 则加载它
        if not hasattr(public_key, "verify"):
            public_key = self._load_public_key(public_key, key_format)

        # 根据填充模式选择不同的填充算法
        if padding_mode == "pss":
            padding_algorithm = padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=pss_salt_length,
            )
        else:  # 默认使用 pkcs1v15
            padding_algorithm = padding.PKCS1v15()

        try:
            public_key.verify(
                signature,
                data,
                padding_algorithm,
                hash_alg,
            )
            return True
        except InvalidSignature:
            return False

    def load_private_key(
        self, path: str, password: Optional[bytes] = None, format: str = "Auto"
    ):
        """从文件加载 RSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码, 如果有加密
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            RSA 私钥对象
        """
        with open(path, "rb") as f:
            key_data = f.read()

        return self._load_private_key(key_data, password, format)

    def load_public_key(self, path: str, format: str = "Auto"):
        """从文件加载 RSA 公钥

        Args:
            path: 公钥文件路径
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            RSA 公钥对象
        """
        with open(path, "rb") as f:
            key_data = f.read()

        return self._load_public_key(key_data, format)

    def _load_private_key(
        self, key_data, password: Optional[bytes] = None, format: str = "Auto"
    ):
        """内部方法：加载 RSA 私钥

        Args:
            key_data: 私钥数据
            password: 私钥密码, 如果有加密
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            RSA 私钥对象
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
            return serialization.load_ssh_private_key(key_data, password=password)
        elif format == "XML":
            if isinstance(key_data, bytes):
                key_data = key_data.decode("utf-8", errors="ignore")
            return self._load_private_key_from_xml(key_data)
        else:
            raise ValueError(f"不支持的密钥格式: {format}")

    def _load_public_key(self, key_data, format: str = "Auto"):
        """内部方法：加载 RSA 公钥

        Args:
            key_data: 公钥数据
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            RSA 公钥对象
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
            return serialization.load_ssh_public_key(key_data)
        elif format == "XML":
            if isinstance(key_data, bytes):
                key_data = key_data.decode("utf-8", errors="ignore")
            return self._load_public_key_from_xml(key_data)
        else:
            raise ValueError(f"不支持的密钥格式: {format}")

    def _load_private_key_from_xml(self, xml_data):
        """从XML加载RSA私钥

        Args:
            xml_data: XML格式的私钥数据

        Returns:
            RSA私钥对象
        """
        try:
            # 解析XML
            root = ET.fromstring(xml_data)

            # 提取各个参数
            modulus_b64 = root.find("Modulus").text
            exponent_b64 = root.find("Exponent").text
            d_b64 = root.find("D").text
            p_b64 = root.find("P").text
            q_b64 = root.find("Q").text
            dp_b64 = root.find("DP").text
            dq_b64 = root.find("DQ").text
            inverse_q_b64 = root.find("InverseQ").text

            # 解码Base64并转换为整数
            n = int.from_bytes(base64.b64decode(modulus_b64), byteorder="big")
            e = int.from_bytes(base64.b64decode(exponent_b64), byteorder="big")
            d = int.from_bytes(base64.b64decode(d_b64), byteorder="big")
            p = int.from_bytes(base64.b64decode(p_b64), byteorder="big")
            q = int.from_bytes(base64.b64decode(q_b64), byteorder="big")
            dp = int.from_bytes(base64.b64decode(dp_b64), byteorder="big")
            dq = int.from_bytes(base64.b64decode(dq_b64), byteorder="big")
            iqmp = int.from_bytes(base64.b64decode(inverse_q_b64), byteorder="big")

            # 创建公钥和私钥数字
            public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
            private_numbers = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=dp,
                dmq1=dq,
                iqmp=iqmp,
                public_numbers=public_numbers,
            )

            # 生成私钥对象
            return private_numbers.private_key()
        except Exception as e:
            raise ValueError(f"无法从XML加载RSA私钥: {str(e)}")

    def _load_public_key_from_xml(self, xml_data):
        """从XML加载RSA公钥

        Args:
            xml_data: XML格式的公钥数据

        Returns:
            RSA公钥对象
        """
        try:
            # 解析XML
            root = ET.fromstring(xml_data)

            # 提取模数和指数
            modulus_b64 = root.find("Modulus").text
            exponent_b64 = root.find("Exponent").text

            # 解码Base64并转换为整数
            n = int.from_bytes(base64.b64decode(modulus_b64), byteorder="big")
            e = int.from_bytes(base64.b64decode(exponent_b64), byteorder="big")

            # 创建公钥数字
            public_numbers = rsa.RSAPublicNumbers(e=e, n=n)

            # 生成公钥对象
            return public_numbers.public_key()
        except Exception as e:
            raise ValueError(f"无法从XML加载RSA公钥: {str(e)}")

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


class RSA_PKCS1v15Signature(RSASignature):
    """传统 RSA 签名实现类 (使用 PKCS#1 v1.5 填充)"""

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        hash_algorithm: Any = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bytes:
        """使用传统 RSA 签名 (PKCS#1 v1.5 填充)

        Args:
            data: 要签名的数据
            private_key: RSA 私钥或私钥数据
            password: 私钥密码 (如果私钥已加密)
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            bytes: 签名结果
        """
        return super().sign(
            data=data,
            private_key=private_key,
            password=password,
            padding_mode="pkcs1v15",
            hash_algorithm=hash_algorithm,
            key_format=key_format,
            **kwargs,
        )

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        hash_algorithm: Any = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bool:
        """使用传统 RSA 验证签名 (PKCS#1 v1.5 填充)

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥或公钥数据
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            bool: 验证是否通过
        """
        return super().verify(
            data=data,
            signature=signature,
            public_key=public_key,
            padding_mode="pkcs1v15",
            hash_algorithm=hash_algorithm,
            key_format=key_format,
            **kwargs,
        )


class RSA_PSSSignature(RSASignature):
    """RSA-PSS 签名实现类"""

    def __init__(self, hash_algorithm=None, salt_length: int = 32):
        """初始化 RSA-PSS 签名类

        Args:
            hash_algorithm: 哈希算法, 默认为 SHA256
            salt_length: PSS 盐长度, 默认为 32 字节
        """
        super().__init__(hash_algorithm=hash_algorithm)
        self.salt_length = salt_length

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        hash_algorithm: Any = None,
        salt_length: int = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bytes:
        """使用 RSA-PSS 签名

        Args:
            data: 要签名的数据
            private_key: RSA 私钥或私钥数据
            password: 私钥密码 (如果私钥已加密)
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值
            salt_length: 可选的盐长度, 覆盖实例默认值
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            bytes: 签名结果
        """
        return super().sign(
            data=data,
            private_key=private_key,
            password=password,
            padding_mode="pss",
            pss_salt_length=(
                salt_length if salt_length is not None else self.salt_length
            ),
            hash_algorithm=hash_algorithm,
            key_format=key_format,
            **kwargs,
        )

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        hash_algorithm: Any = None,
        salt_length: int = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bool:
        """使用 RSA-PSS 验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: RSA 公钥或公钥数据
            hash_algorithm: 可选的哈希算法, 覆盖实例默认值
            salt_length: 可选的盐长度, 覆盖实例默认值
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            bool: 验证是否通过
        """
        return super().verify(
            data=data,
            signature=signature,
            public_key=public_key,
            padding_mode="pss",
            pss_salt_length=(
                salt_length if salt_length is not None else self.salt_length
            ),
            hash_algorithm=hash_algorithm,
            key_format=key_format,
            **kwargs,
        )
