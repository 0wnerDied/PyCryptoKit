from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from typing import Dict, Optional, Union, Any
import base64
import xml.etree.ElementTree as ET

from .base import SignatureBase


class EdDSASignature(SignatureBase):
    """EdDSA 签名实现类 (支持 Ed25519 和 Ed448 算法)"""

    # 支持的曲线
    SUPPORTED_CURVES = {"Ed25519", "Ed448"}
    DEFAULT_CURVE = "Ed25519"

    # OpenSSH格式支持的Edwards曲线
    OPENSSH_SUPPORTED_CURVES = ["Ed25519"]

    def __init__(self, curve: str = "Ed25519"):
        """初始化 EdDSA 签名类

        Args:
            curve: 曲线类型, 可选 "Ed25519" (默认) 或 "Ed448"
        """
        if curve not in self.SUPPORTED_CURVES:
            raise ValueError(f"曲线类型必须是 {' 或 '.join(self.SUPPORTED_CURVES)}")
        self.curve = curve
        self.context = b""  # RFC8032 上下文, 默认为空

    def set_context(self, context: bytes) -> None:
        """设置签名上下文

        Args:
            context: 最多 255 字节的上下文数据, 用于区分不同协议或应用
        """
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")
        self.context = context

    def set_hash_algorithm(self, hash_algorithm: Any) -> None:
        """设置哈希算法

        EdDSA 使用固定的哈希算法 (Ed25519 使用 SHA-512, Ed448 使用 SHAKE256)

        Args:
            hash_algorithm: 哈希算法对象或算法名称

        Raises:
            NotImplementedError: EdDSA 使用固定的哈希算法, 不能更改
        """
        raise NotImplementedError("EdDSA 使用固定的哈希算法, 不能更改")

    def set_curve(self, curve: str) -> None:
        """设置曲线类型

        Args:
            curve: 曲线类型, "Ed25519" 或 "Ed448"

        Raises:
            ValueError: 如果曲线类型不受支持
        """
        if curve not in self.SUPPORTED_CURVES:
            raise ValueError(f"曲线类型必须是 {' 或 '.join(self.SUPPORTED_CURVES)}")
        self.curve = curve

    def get_supported_key_sizes(self) -> Dict[str, Any]:
        """获取支持的密钥长度

        注意: EdDSA密钥长度由曲线决定, 不能直接指定

        Returns:
            Dict[str, Any]: 密钥长度名称和对应的位数
        """
        return {
            "注意": "EdDSA密钥长度由曲线决定, 不能直接指定",
            "Ed25519": 256,  # 实际密钥长度为32字节(256位)
            "Ed448": 448,  # 实际密钥长度为57字节(456位)
            "支持的曲线": list(self.SUPPORTED_CURVES),
            "OpenSSH支持的曲线": self.OPENSSH_SUPPORTED_CURVES,
        }

    def get_supported_hash_algorithms(self) -> Dict[str, Any]:
        """获取支持的哈希算法

        Returns:
            Dict[str, Any]: 哈希算法名称和对应的算法对象
        """
        return {
            "注意": "EdDSA 使用固定的哈希算法",
            "Ed25519": "SHA-512",
            "Ed448": "SHAKE256",
        }

    def sign(
        self,
        data: Union[bytes, str],
        private_key,
        password: Optional[bytes] = None,
        key_format: str = "Auto",
        **kwargs,
    ) -> bytes:
        """使用 EdDSA 私钥对数据进行签名

        Args:
            data: 要签名的数据
            private_key: EdDSA 私钥对象或私钥数据
            password: 私钥密码 (如果私钥已加密)
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"
            **kwargs: 其他参数, 可以包含'context'来指定上下文

        Returns:
            bytes: 签名结果
        """
        data = self._ensure_bytes(data)

        # 检查是否提供了context参数
        context = kwargs.get("context", self.context)
        if isinstance(context, str):
            context = context.encode("utf-8")
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")

        # 如果 private_key 不是密钥对象, 则加载它
        if not hasattr(
            private_key, "pointQ"
        ):  # PyCryptodome的EdDSA密钥对象有pointQ属性
            private_key = self._load_private_key(private_key, password, key_format)

        # 创建签名对象并签名
        signer = eddsa.new(private_key, mode="rfc8032", context=context)
        signature = signer.sign(data)
        return signature

    def verify(
        self,
        data: Union[bytes, str],
        signature: bytes,
        public_key,
        key_format: str = "Auto",
        **kwargs,
    ) -> bool:
        """使用 EdDSA 公钥验证签名

        Args:
            data: 原始数据
            signature: 签名
            public_key: EdDSA 公钥对象或公钥数据
            key_format: 密钥格式, 可选 "Auto", "PEM", "DER", "OpenSSH", "XML"
            **kwargs: 其他参数, 可以包含'context'来指定上下文

        Returns:
            bool: 验证是否通过
        """
        data = self._ensure_bytes(data)

        # 检查是否提供了context参数
        context = kwargs.get("context", self.context)
        if isinstance(context, str):
            context = context.encode("utf-8")
        if len(context) > 255:
            raise ValueError("上下文数据不能超过 255 字节")

        # 如果 public_key 不是密钥对象, 则加载它
        if not hasattr(public_key, "pointQ"):  # PyCryptodome的EdDSA密钥对象有pointQ属性
            public_key = self._load_public_key(public_key, key_format)

        # 创建验证对象并验证
        verifier = eddsa.new(public_key, mode="rfc8032", context=context)
        try:
            verifier.verify(data, signature)
            return True
        except ValueError:
            return False

    def load_private_key(
        self, path: str, password: Optional[bytes] = None, format: str = "Auto"
    ):
        """从文件加载 EdDSA 私钥

        Args:
            path: 私钥文件路径
            password: 私钥密码, 如果有加密
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            EdDSA 私钥对象
        """
        with open(path, "rb") as f:
            key_data = f.read()

        return self._load_private_key(key_data, password, format)

    def load_public_key(self, path: str, format: str = "Auto"):
        """从文件加载 EdDSA 公钥

        Args:
            path: 公钥文件路径
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            EdDSA 公钥对象
        """
        with open(path, "rb") as f:
            key_data = f.read()

        return self._load_public_key(key_data, format)

    def _load_private_key(
        self, key_data, password: Optional[bytes] = None, format: str = "Auto"
    ):
        """内部方法：加载 EdDSA 私钥

        Args:
            key_data: 私钥数据
            password: 私钥密码, 如果有加密
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            EdDSA 私钥对象
        """
        # 如果已经是私钥对象，直接返回
        if hasattr(key_data, "pointQ"):
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
            # 先尝试作为PEM/DER/SSH格式加载
            try:
                key = ECC.import_key(key_data, passphrase=password)
                # 验证曲线类型
                if key.curve not in self.SUPPORTED_CURVES:
                    raise ValueError(
                        f"导入的密钥曲线类型 {key.curve} 与支持的类型不匹配"
                    )
                return key
            except (ValueError, TypeError):
                # 如果失败，尝试作为XML格式加载
                try:
                    if isinstance(key_data, bytes):
                        xml_data = key_data.decode("utf-8", errors="ignore")
                    else:
                        xml_data = key_data
                    return self._load_private_key_from_xml(xml_data)
                except Exception:
                    raise ValueError("无法自动识别私钥格式")
        elif format in ("PEM", "DER"):
            key = ECC.import_key(key_data, passphrase=password)
            # 验证曲线类型
            if key.curve not in self.SUPPORTED_CURVES:
                raise ValueError(f"导入的密钥曲线类型 {key.curve} 与支持的类型不匹配")
            return key
        elif format == "OpenSSH":
            # 尝试加载OpenSSH格式的密钥
            try:
                key = ECC.import_key(key_data, passphrase=password)
                # 验证曲线类型
                if key.curve not in self.SUPPORTED_CURVES:
                    raise ValueError(
                        f"导入的密钥曲线类型 {key.curve} 与支持的类型不匹配"
                    )

                # 验证曲线是否在OpenSSH支持列表中
                if key.curve not in self.OPENSSH_SUPPORTED_CURVES:
                    raise ValueError(
                        f"OpenSSH格式不支持{key.curve}曲线的EdDSA密钥, 仅支持: {', '.join(self.OPENSSH_SUPPORTED_CURVES)}"
                    )

                return key
            except Exception as e:
                raise ValueError(f"无法加载OpenSSH格式的EdDSA私钥: {str(e)}")
        elif format == "XML":
            if isinstance(key_data, bytes):
                key_data = key_data.decode("utf-8", errors="ignore")
            return self._load_private_key_from_xml(key_data)
        else:
            raise ValueError(f"不支持的密钥格式: {format}")

    def _load_public_key(self, key_data, format: str = "Auto"):
        """内部方法：加载 EdDSA 公钥

        Args:
            key_data: 公钥数据
            format: 密钥格式, 支持 "Auto", "PEM", "DER", "OpenSSH", "XML"

        Returns:
            EdDSA 公钥对象
        """
        # 如果已经是公钥对象，直接返回
        if hasattr(key_data, "pointQ"):
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
            # 先尝试作为PEM/DER/SSH格式加载
            try:
                key = ECC.import_key(key_data)
                # 验证曲线类型
                if key.curve not in self.SUPPORTED_CURVES:
                    raise ValueError(
                        f"导入的密钥曲线类型 {key.curve} 与支持的类型不匹配"
                    )
                return key
            except (ValueError, TypeError):
                # 如果失败，尝试作为XML格式加载
                try:
                    if isinstance(key_data, bytes):
                        xml_data = key_data.decode("utf-8", errors="ignore")
                    else:
                        xml_data = key_data
                    return self._load_public_key_from_xml(xml_data)
                except Exception:
                    raise ValueError("无法自动识别公钥格式")
        elif format in ("PEM", "DER"):
            key = ECC.import_key(key_data)
            # 验证曲线类型
            if key.curve not in self.SUPPORTED_CURVES:
                raise ValueError(f"导入的密钥曲线类型 {key.curve} 与支持的类型不匹配")
            return key
        elif format == "OpenSSH":
            # 尝试加载OpenSSH格式的密钥
            try:
                key = ECC.import_key(key_data)
                # 验证曲线类型
                if key.curve not in self.SUPPORTED_CURVES:
                    raise ValueError(
                        f"导入的密钥曲线类型 {key.curve} 与支持的类型不匹配"
                    )

                # 验证曲线是否在OpenSSH支持列表中
                if key.curve not in self.OPENSSH_SUPPORTED_CURVES:
                    raise ValueError(
                        f"OpenSSH格式不支持{key.curve}曲线的EdDSA密钥, 仅支持: {', '.join(self.OPENSSH_SUPPORTED_CURVES)}"
                    )

                return key
            except Exception as e:
                raise ValueError(f"无法加载OpenSSH格式的EdDSA公钥: {str(e)}")
        elif format == "XML":
            if isinstance(key_data, bytes):
                key_data = key_data.decode("utf-8", errors="ignore")
            return self._load_public_key_from_xml(key_data)
        else:
            raise ValueError(f"不支持的密钥格式: {format}")

    def _load_private_key_from_xml(self, xml_data: str):
        """从XML加载EdDSA私钥

        Args:
            xml_data: XML格式的私钥数据

        Returns:
            EdDSA 私钥对象
        """
        try:
            # 解析XML
            root = ET.fromstring(xml_data)

            # 获取曲线类型
            curve_elem = root.find("Curve")
            if curve_elem is None:
                raise ValueError("XML中未找到Curve元素")

            curve = curve_elem.text
            if curve not in self.SUPPORTED_CURVES:
                raise ValueError(f"不支持的曲线类型: {curve}")

            # 首先尝试使用 edwards.py 中使用的标签 "PrivateKey"
            private_elem = root.find("PrivateKey")
            if private_elem is not None and private_elem.text:
                seed_b64 = private_elem.text
            else:
                # 如果找不到 "PrivateKey" 标签，则尝试使用 "Seed" 标签
                seed_elem = root.find("Seed")
                if seed_elem is None:
                    raise ValueError("XML中未找到PrivateKey或Seed元素")

                seed_b64 = seed_elem.text
                if not seed_b64:
                    raise ValueError("私钥元素内容为空")

            seed = base64.b64decode(seed_b64)

            # 验证密钥长度
            expected_length = 32 if curve == "Ed25519" else 57
            if len(seed) != expected_length:
                raise ValueError(
                    f"{curve}私钥种子长度应为{expected_length}字节，但得到{len(seed)}字节"
                )

            # 使用PyCryptodome导入私钥
            try:
                private_key = eddsa.import_private_key(seed)
                if private_key.curve != curve:
                    raise ValueError(
                        f"导入的密钥曲线类型 {private_key.curve} 与XML中指定的 {curve} 不匹配"
                    )
                return private_key
            except Exception as e:
                raise ValueError(f"无法导入EdDSA私钥: {str(e)}")

        except Exception as e:
            raise ValueError(f"无法从XML加载EdDSA私钥: {str(e)}")

    def _load_public_key_from_xml(self, xml_data: str):
        """从XML加载EdDSA公钥

        Args:
            xml_data: XML格式的公钥数据

        Returns:
            EdDSA 公钥对象
        """
        try:
            # 解析XML
            root = ET.fromstring(xml_data)

            # 获取曲线类型
            curve_elem = root.find("Curve")
            if curve_elem is None:
                raise ValueError("XML中未找到Curve元素")

            curve = curve_elem.text
            if curve not in self.SUPPORTED_CURVES:
                raise ValueError(f"不支持的曲线类型: {curve}")

            # 首先尝试使用 edwards.py 中使用的标签 "PublicKey"
            public_elem = root.find("PublicKey")
            if public_elem is not None and public_elem.text:
                point_b64 = public_elem.text
            else:
                # 如果找不到 "PublicKey" 标签，则尝试使用 "Point" 标签
                point_elem = root.find("Point")
                if point_elem is None:
                    raise ValueError("XML中未找到PublicKey或Point元素")

                point_b64 = point_elem.text
                if not point_b64:
                    raise ValueError("公钥元素内容为空")

            point = base64.b64decode(point_b64)

            # 验证密钥长度
            expected_length = 32 if curve == "Ed25519" else 57
            if len(point) != expected_length:
                raise ValueError(
                    f"{curve}公钥点长度应为{expected_length}字节，但得到{len(point)}字节"
                )

            # 使用PyCryptodome导入公钥
            try:
                public_key = eddsa.import_public_key(point)
                if public_key.curve != curve:
                    raise ValueError(
                        f"导入的密钥曲线类型 {public_key.curve} 与XML中指定的 {curve} 不匹配"
                    )
                return public_key
            except Exception as e:
                raise ValueError(f"无法导入EdDSA公钥: {str(e)}")

        except Exception as e:
            raise ValueError(f"无法从XML加载EdDSA公钥: {str(e)}")

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
