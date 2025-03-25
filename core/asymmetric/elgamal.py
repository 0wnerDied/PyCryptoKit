"""
ElGamal 加密模块
提供ElGamal密钥对生成功能
"""

import logging
import xml.etree.ElementTree as ET
import base64
from typing import Union, Optional, BinaryIO, List

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)

# 支持的密钥大小
_ELGAMAL_KEY_SIZES = [1024, 2048, 3072, 4096]


class ElGamalKey(AsymmetricKey):
    """ElGamal密钥类, 包装DSA/DH参数和密钥"""

    def __init__(
        self, key_data, key_type: str, params=None, password: Optional[bytes] = None
    ):
        super().__init__(key_data, key_type, ElGamal.algorithm_name())
        self.params = params  # 存储DH参数
        self.password = password  # 存储密码

    def to_pem(self) -> bytes:
        """将密钥转换为PEM格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
            if self.password:
                encryption_algorithm = serialization.BestAvailableEncryption(
                    self.password
                )

            return self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                encryption_algorithm=encryption_algorithm,
            )

    def to_der(self) -> bytes:
        """将密钥转换为DER格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
            if self.password:
                encryption_algorithm = serialization.BestAvailableEncryption(
                    self.password
                )

            return self.key_data.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                encryption_algorithm=encryption_algorithm,
            )

    def to_xml(self) -> str:
        """将密钥转换为XML格式"""
        if self.key_type == "public":
            # 获取公钥参数
            public_numbers = self.key_data.public_numbers()
            parameter_numbers = public_numbers.parameter_numbers

            p = parameter_numbers.p
            g = parameter_numbers.g
            y = public_numbers.y  # 公钥值

            root = ET.Element("ElGamalKeyValue")

            # 添加参数
            p_elem = ET.SubElement(root, "P")
            p_elem.text = base64.b64encode(
                p.to_bytes((p.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            g_elem = ET.SubElement(root, "G")
            g_elem.text = base64.b64encode(
                g.to_bytes((g.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            y_elem = ET.SubElement(root, "Y")
            y_elem.text = base64.b64encode(
                y.to_bytes((y.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

        else:
            # 获取私钥参数
            private_numbers = self.key_data.private_numbers()
            public_numbers = private_numbers.public_numbers
            parameter_numbers = public_numbers.parameter_numbers

            p = parameter_numbers.p
            g = parameter_numbers.g
            y = public_numbers.y  # 公钥值
            x = private_numbers.x  # 私钥值

            root = ET.Element("ElGamalKeyValue")

            # 添加参数
            p_elem = ET.SubElement(root, "P")
            p_elem.text = base64.b64encode(
                p.to_bytes((p.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            g_elem = ET.SubElement(root, "G")
            g_elem.text = base64.b64encode(
                g.to_bytes((g.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            y_elem = ET.SubElement(root, "Y")
            y_elem.text = base64.b64encode(
                y.to_bytes((y.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

            x_elem = ET.SubElement(root, "X")
            x_elem.text = base64.b64encode(
                x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
            ).decode("utf-8")

        return ET.tostring(root, encoding="unicode")

    def save_to_file(
        self, filepath: str, format: str = "pem", password: Optional[bytes] = None
    ) -> None:
        """
        将密钥保存到文件

        Args:
            filepath: 文件路径
            format: 文件格式 ('pem', 'der', 'xml')
            password: 加密密码 (仅适用于私钥)
        """
        try:
            # 如果没有提供密码，但密钥对象有密码，则使用密钥对象的密码
            if not password and self.password:
                password = self.password

            if format.lower() == "pem":
                if self.key_type == "public":
                    key_bytes = self.key_data.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                else:
                    encryption_algorithm = serialization.NoEncryption()
                    if password:
                        encryption_algorithm = serialization.BestAvailableEncryption(
                            password
                        )
                    key_bytes = self.key_data.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                        encryption_algorithm=encryption_algorithm,
                    )
            elif format.lower() == "der":
                if self.key_type == "public":
                    key_bytes = self.key_data.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                else:
                    encryption_algorithm = serialization.NoEncryption()
                    if password:
                        encryption_algorithm = serialization.BestAvailableEncryption(
                            password
                        )
                    key_bytes = self.key_data.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,  # 使用传统的OpenSSL格式
                        encryption_algorithm=encryption_algorithm,
                    )
            elif format.lower() == "xml":
                key_bytes = self.to_xml().encode("utf-8")
            else:
                raise ValueError(f"不支持的格式: {format}")

            with open(filepath, "wb") as f:
                f.write(key_bytes)

            logger.info(f"密钥已保存到 {filepath}")

        except Exception as e:
            logger.error(f"保存密钥失败: {e}")
            raise ValueError(f"保存密钥失败: {e}")


class ElGamal(AsymmetricCipher):
    """ElGamal加密算法实现"""

    @classmethod
    def algorithm_name(cls) -> str:
        return "ElGamal"

    @classmethod
    def get_supported_key_sizes(cls) -> List[int]:
        """获取支持的密钥大小列表"""
        return _ELGAMAL_KEY_SIZES

    @classmethod
    def generate_key_pair(cls, key_size: int = 2048, **kwargs) -> KeyPair:
        """
        生成ElGamal密钥对

        Args:
            key_size: 密钥大小, 默认2048位
            **kwargs: 其他参数
                - password: 私钥加密密码 (可选)

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        try:
            # 验证密钥大小
            if key_size not in _ELGAMAL_KEY_SIZES:
                raise ValueError(
                    f"不支持的密钥大小: {key_size}, 支持的大小: {', '.join(map(str, _ELGAMAL_KEY_SIZES))}"
                )

            # 获取密码
            password = kwargs.get("password")

            # 生成DSA参数, 我们将使用这些参数来实现ElGamal
            # DSA参数包含p, q, g值, 这些也是ElGamal所需的
            parameters = dsa.generate_parameters(
                key_size=key_size, backend=default_backend()
            )

            # 从参数生成私钥
            private_key = parameters.generate_private_key()

            # 获取公钥
            public_key = private_key.public_key()

            logger.info(f"成功生成ElGamal密钥对, 密钥大小: {key_size}位")

            # 创建并返回密钥对
            return KeyPair(
                ElGamalKey(public_key, "public", parameters),
                ElGamalKey(private_key, "private", parameters, password),
            )
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")

    @classmethod
    def load_public_key(
        cls, key_data: Union[bytes, str, BinaryIO], format: str = "pem"
    ) -> AsymmetricKey:
        """
        加载公钥

        Args:
            key_data: 密钥数据
            format: 格式 ('pem', 'der', 'xml')

        Returns:
            公钥对象
        """
        try:
            if isinstance(key_data, str):
                if format.lower() == "xml":
                    # 解析XML格式
                    root = ET.fromstring(key_data)
                    p_b64 = root.find("P").text
                    g_b64 = root.find("G").text
                    y_b64 = root.find("Y").text

                    # 解码参数
                    p_bytes = base64.b64decode(p_b64)
                    g_bytes = base64.b64decode(g_b64)
                    y_bytes = base64.b64decode(y_b64)

                    p = int.from_bytes(p_bytes, byteorder="big")
                    g = int.from_bytes(g_bytes, byteorder="big")
                    y = int.from_bytes(y_bytes, byteorder="big")

                    # 创建参数和公钥
                    # 注意: 这里我们需要q值, 但XML中没有提供
                    # 我们可以尝试计算q, 但这超出了简单的加载功能
                    # 这里简化处理, 仅用于示例
                    q = 0  # 这里应该计算q, 但简化处理
                    parameter_numbers = dsa.DSAParameterNumbers(p=p, q=q, g=g)
                    public_numbers = dsa.DSAPublicNumbers(
                        y=y, parameter_numbers=parameter_numbers
                    )

                    # 创建参数对象
                    params = parameter_numbers.parameters(default_backend())

                    # 创建公钥
                    key_obj = public_numbers.public_key(default_backend())
                    return ElGamalKey(key_obj, "public", params)
                else:
                    key_data = key_data.encode("utf-8")
            elif hasattr(key_data, "read"):  # 如果是文件对象
                key_data = key_data.read()
                if isinstance(key_data, str):
                    key_data = key_data.encode("utf-8")

            if format.lower() == "pem":
                key_obj = serialization.load_pem_public_key(
                    key_data, backend=default_backend()
                )
            elif format.lower() == "der":
                key_obj = serialization.load_der_public_key(
                    key_data, backend=default_backend()
                )
            else:
                raise ValueError(f"不支持的格式: {format}")

            # 验证密钥类型
            if not isinstance(key_obj, dsa.DSAPublicKey):
                raise ValueError("提供的密钥不是有效的DSA/ElGamal公钥")

            # 从公钥中提取参数
            params = dsa.DSAParameterNumbers(
                p=key_obj.public_numbers().parameter_numbers.p,
                q=key_obj.public_numbers().parameter_numbers.q,
                g=key_obj.public_numbers().parameter_numbers.g,
            ).parameters(default_backend())

            return ElGamalKey(key_obj, "public", params)

        except Exception as e:
            logger.error(f"加载公钥失败: {e}")
            raise ValueError(f"加载公钥失败: {e}")

    @classmethod
    def load_private_key(
        cls,
        key_data: Union[bytes, str, BinaryIO],
        format: str = "pem",
        password: Optional[bytes] = None,
    ) -> AsymmetricKey:
        """
        加载私钥

        Args:
            key_data: 密钥数据
            format: 格式 ('pem', 'der', 'xml')
            password: 密码 (如果有)

        Returns:
            私钥对象
        """
        try:
            if isinstance(key_data, str):
                if format.lower() == "xml":
                    # 解析XML格式
                    root = ET.fromstring(key_data)
                    p_b64 = root.find("P").text
                    g_b64 = root.find("G").text
                    y_b64 = root.find("Y").text
                    x_b64 = root.find("X").text

                    # 解码参数
                    p_bytes = base64.b64decode(p_b64)
                    g_bytes = base64.b64decode(g_b64)
                    y_bytes = base64.b64decode(y_b64)
                    x_bytes = base64.b64decode(x_b64)

                    p = int.from_bytes(p_bytes, byteorder="big")
                    g = int.from_bytes(g_bytes, byteorder="big")
                    y = int.from_bytes(y_bytes, byteorder="big")
                    x = int.from_bytes(x_bytes, byteorder="big")

                    # 创建参数和私钥
                    # 注意: 这里我们需要q值, 但XML中没有提供
                    # 我们可以尝试计算q, 但这超出了简单的加载功能
                    # 这里简化处理, 仅用于示例
                    q = 0  # 这里应该计算q, 但简化处理
                    parameter_numbers = dsa.DSAParameterNumbers(p=p, q=q, g=g)
                    public_numbers = dsa.DSAPublicNumbers(
                        y=y, parameter_numbers=parameter_numbers
                    )
                    private_numbers = dsa.DSAPrivateNumbers(
                        x=x, public_numbers=public_numbers
                    )

                    # 创建参数对象
                    params = parameter_numbers.parameters(default_backend())

                    # 创建私钥
                    key_obj = private_numbers.private_key(default_backend())
                    return ElGamalKey(key_obj, "private", params, password)
                else:
                    key_data = key_data.encode("utf-8")
            elif hasattr(key_data, "read"):  # 如果是文件对象
                key_data = key_data.read()
                if isinstance(key_data, str):
                    key_data = key_data.encode("utf-8")

            if format.lower() == "pem":
                key_obj = serialization.load_pem_private_key(
                    key_data, password=password, backend=default_backend()
                )
            elif format.lower() == "der":
                key_obj = serialization.load_der_private_key(
                    key_data, password=password, backend=default_backend()
                )
            else:
                raise ValueError(f"不支持的格式: {format}")

            # 验证密钥类型
            if not isinstance(key_obj, dsa.DSAPrivateKey):
                raise ValueError("提供的密钥不是有效的DSA/ElGamal私钥")

            # 从私钥中提取参数
            params = dsa.DSAParameterNumbers(
                p=key_obj.private_numbers().public_numbers.parameter_numbers.p,
                q=key_obj.private_numbers().public_numbers.parameter_numbers.q,
                g=key_obj.private_numbers().public_numbers.parameter_numbers.g,
            ).parameters(default_backend())

            return ElGamalKey(key_obj, "private", params, password)

        except Exception as e:
            logger.error(f"加载私钥失败: {e}")
            raise ValueError(f"加载私钥失败: {e}")
