"""
ECC (椭圆曲线加密) 模块
提供基于椭圆曲线的加密、解密功能
"""

import os
import base64
import logging
from typing import Union, Optional, Dict, BinaryIO

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)


class ECCKey(AsymmetricKey):
    """椭圆曲线密钥类, 包装Cryptography库的ECC密钥"""

    def __init__(self, key_data, key_type: str):
        super().__init__(key_data, key_type, ECC.algorithm_name())

        # 存储曲线信息
        if key_type == "public":
            self.curve = key_data.curve
        else:
            self.curve = key_data.curve

    def to_bytes(self) -> bytes:
        """将密钥转换为字节格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            return self.key_data.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def to_pem(self) -> bytes:
        """将密钥转换为PEM格式"""
        if self.key_type == "public":
            return self.key_data.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            return self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def save_to_file(self, filename: str, password: Optional[bytes] = None) -> None:
        """将密钥保存到文件"""
        if self.key_type == "public":
            with open(filename, "wb") as f:
                f.write(self.to_pem())
        else:
            # 确定加密算法
            encryption_algorithm = serialization.NoEncryption()
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)

            pem = self.key_data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

            with open(filename, "wb") as f:
                f.write(pem)


class ECC(AsymmetricCipher):
    """椭圆曲线加密算法实现, 包装Cryptography库"""

    # 支持的曲线类型
    _CURVES = {
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
        "SECP521R1": ec.SECP521R1(),
    }

    @classmethod
    def algorithm_name(cls) -> str:
        return "ECC"

    @classmethod
    def supported_curves(cls) -> list:
        """返回支持的椭圆曲线列表"""
        return list(cls._CURVES.keys())

    @classmethod
    def generate_key_pair(cls, curve: str = "SECP256R1", **kwargs) -> KeyPair:
        """
        生成ECC密钥对

        Args:
            curve: 椭圆曲线类型, 默认为SECP256R1

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        try:
            # 验证曲线类型
            if curve not in cls._CURVES:
                raise ValueError(
                    f"不支持的曲线类型: {curve}, 支持的类型: {', '.join(cls._CURVES.keys())}"
                )

            curve_obj = cls._CURVES[curve]

            # 生成私钥
            private_key = ec.generate_private_key(
                curve=curve_obj, backend=default_backend()
            )

            # 获取公钥
            public_key = private_key.public_key()

            logger.info(f"成功生成ECC密钥对, 使用曲线: {curve}")

            # 创建并返回密钥对
            return KeyPair(ECCKey(public_key, "public"), ECCKey(private_key, "private"))
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")

    @classmethod
    def encrypt(cls, data: bytes, public_key: AsymmetricKey) -> bytes:
        """
        使用ECIES (椭圆曲线集成加密方案) 加密数据

        Args:
            data: 要加密的数据
            public_key: ECC公钥

        Returns:
            序列化的加密数据
        """
        if not cls.validate_key(public_key) or public_key.key_type != "public":
            raise ValueError("无效的ECC公钥")

        try:
            # 获取曲线
            curve = public_key.key_data.curve

            # 生成临时ECC密钥对
            ephemeral_private_key = ec.generate_private_key(
                curve=curve, backend=default_backend()
            )
            ephemeral_public_key = ephemeral_private_key.public_key()

            # 使用ECDH密钥交换派生共享密钥
            shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key.key_data)

            # 生成随机盐值
            salt = os.urandom(16)

            # 使用HKDF从共享密钥派生AES密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,
                info=b"ECIES-AES-256",
                backend=default_backend(),
            ).derive(shared_key)

            # 生成随机IV
            iv = os.urandom(16)

            # 使用AES-GCM模式加密数据
            encryptor = Cipher(
                algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend()
            ).encryptor()

            # 加密数据
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # 获取认证标签
            tag = encryptor.tag

            # 序列化临时公钥
            ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )

            # 构建加密结果字典
            encrypted_data = {
                "ephemeral_public_key": ephemeral_public_key_bytes,
                "salt": salt,
                "iv": iv,
                "ciphertext": ciphertext,
                "tag": tag,
            }

            # 序列化加密结果
            # 格式: [4字节长度][临时公钥][16字节盐值][16字节IV][16字节标签][密文]
            result = len(ephemeral_public_key_bytes).to_bytes(4, byteorder="big")
            result += ephemeral_public_key_bytes
            result += salt
            result += iv
            result += tag
            result += ciphertext

            logger.debug(f"成功加密数据, 长度: {len(data)} 字节")
            return result

        except Exception as e:
            logger.error(f"加密失败: {e}")
            raise ValueError(f"加密失败: {e}")

    @classmethod
    def decrypt(cls, encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
        """
        使用ECIES解密数据

        Args:
            encrypted_data: 加密的数据
            private_key: ECC私钥

        Returns:
            解密后的数据
        """
        if not cls.validate_key(private_key) or private_key.key_type != "private":
            raise ValueError("无效的ECC私钥")

        try:
            # 解析加密数据
            # 格式: [4字节长度][临时公钥][16字节盐值][16字节IV][16字节标签][密文]
            i = 0

            # 读取临时公钥长度
            ephemeral_key_len = int.from_bytes(
                encrypted_data[i : i + 4], byteorder="big"
            )
            i += 4

            # 读取临时公钥
            ephemeral_public_key_bytes = encrypted_data[i : i + ephemeral_key_len]
            i += ephemeral_key_len

            # 读取盐值、IV和标签
            salt = encrypted_data[i : i + 16]
            i += 16

            iv = encrypted_data[i : i + 16]
            i += 16

            tag = encrypted_data[i : i + 16]
            i += 16

            # 剩余部分是密文
            ciphertext = encrypted_data[i:]

            # 从字节数据加载临时公钥
            try:
                ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve=private_key.key_data.curve, data=ephemeral_public_key_bytes
                )
            except Exception as e:
                logger.error(f"无效的临时公钥或曲线不匹配: {e}")
                raise ValueError(f"无效的临时公钥或曲线不匹配: {e}")

            # 使用ECDH密钥交换派生共享密钥
            shared_key = private_key.key_data.exchange(ec.ECDH(), ephemeral_public_key)

            # 使用HKDF从共享密钥派生AES密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,
                info=b"ECIES-AES-256",
                backend=default_backend(),
            ).derive(shared_key)

            # 使用AES-GCM模式解密数据
            try:
                decryptor = Cipher(
                    algorithms.AES(derived_key),
                    modes.GCM(iv, tag),
                    backend=default_backend(),
                ).decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            except InvalidTag:
                logger.error("解密失败: 数据完整性验证失败")
                raise ValueError("解密失败: 数据可能被篡改或密钥不正确")

            logger.debug(f"成功解密数据, 长度: {len(plaintext)} 字节")
            return plaintext

        except Exception as e:
            logger.error(f"解密失败: {e}")
            raise ValueError(f"解密失败: {e}")

    @classmethod
    def load_public_key(
        cls, key_data: Union[bytes, str, BinaryIO], format: str = "pem"
    ) -> AsymmetricKey:
        """
        加载公钥

        Args:
            key_data: 密钥数据
            format: 格式('pem', 'der')

        Returns:
            公钥对象
        """
        try:
            if isinstance(key_data, str):
                key_data = key_data.encode("utf-8")
            elif hasattr(key_data, "read"):  # 如果是文件对象
                key_data = key_data.read()

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
            if not isinstance(key_obj, ec.EllipticCurvePublicKey):
                raise ValueError("提供的密钥不是有效的椭圆曲线公钥")

            return ECCKey(key_obj, "public")

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
            format: 格式('pem', 'der')
            password: 密码(如果有)

        Returns:
            私钥对象
        """
        try:
            if isinstance(key_data, str):
                key_data = key_data.encode("utf-8")
            elif hasattr(key_data, "read"):  # 如果是文件对象
                key_data = key_data.read()

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
            if not isinstance(key_obj, ec.EllipticCurvePrivateKey):
                raise ValueError("提供的密钥不是有效的椭圆曲线私钥")

            return ECCKey(key_obj, "private")

        except Exception as e:
            logger.error(f"加载私钥失败: {e}")
            raise ValueError(f"加载私钥失败: {e}")

    @classmethod
    def validate_key(cls, key: AsymmetricKey) -> bool:
        """
        验证密钥是否为有效的ECC密钥

        Args:
            key: 要验证的密钥

        Returns:
            如果是有效的ECC密钥则返回True
        """
        if not isinstance(key, ECCKey):
            return False

        if key.key_type == "public":
            return isinstance(key.key_data, ec.EllipticCurvePublicKey)
        else:
            return isinstance(key.key_data, ec.EllipticCurvePrivateKey)

    @classmethod
    def encrypt_to_base64(
        cls, data: bytes, public_key: AsymmetricKey
    ) -> Dict[str, str]:
        """
        加密数据并返回Base64编码的结果

        Args:
            data: 要加密的数据
            public_key: 公钥对象

        Returns:
            包含Base64编码加密结果的字典
        """
        if not cls.validate_key(public_key) or public_key.key_type != "public":
            raise ValueError("无效的ECC公钥")

        try:
            # 生成临时的ECC密钥对用于此次加密
            ephemeral_key = ec.generate_private_key(
                curve=public_key.key_data.curve, backend=default_backend()
            )
            ephemeral_public_key = ephemeral_key.public_key()

            # 使用接收方的公钥和临时私钥生成共享密钥
            shared_key = ephemeral_key.exchange(ec.ECDH(), public_key.key_data)

            # 生成随机盐值
            salt = os.urandom(16)

            # 从共享密钥派生对称加密密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"ECIES-AES-256",
                backend=default_backend(),
            ).derive(shared_key)

            # 生成随机IV
            iv = os.urandom(16)

            # 使用AES-GCM加密数据
            encryptor = Cipher(
                algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend()
            ).encryptor()

            # 可以添加额外的认证数据(AAD), 这里使用空字节
            encryptor.authenticate_additional_data(b"")

            # 加密数据
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # 将临时公钥序列化
            serialized_ephemeral_public_key = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )

            # 返回Base64编码的结果
            return {
                "iv": base64.b64encode(iv).decode("utf-8"),
                "ephemeral_public_key": base64.b64encode(
                    serialized_ephemeral_public_key
                ).decode("utf-8"),
                "salt": base64.b64encode(salt).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
            }
        except Exception as e:
            logger.error(f"Base64加密失败: {e}")
            raise ValueError(f"Base64加密失败: {str(e)}")

    @classmethod
    def decrypt_from_base64(
        cls, encrypted_data: Dict[str, str], private_key: AsymmetricKey
    ) -> bytes:
        """
        从Base64编码的加密数据中解密

        Args:
            encrypted_data: 包含Base64编码加密数据的字典
            private_key: 私钥对象

        Returns:
            解密后的字节数据
        """
        if not cls.validate_key(private_key) or private_key.key_type != "private":
            raise ValueError("无效的ECC私钥")

        try:
            # 解码Base64数据
            iv = base64.b64decode(encrypted_data["iv"])
            ephemeral_public_key_bytes = base64.b64decode(
                encrypted_data["ephemeral_public_key"]
            )
            salt = base64.b64decode(
                encrypted_data.get("salt", "")
            )  # 兼容可能没有盐值的情况
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            tag = base64.b64decode(encrypted_data["tag"])

            # 从字节数据加载临时公钥
            try:
                ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve=private_key.key_data.curve, data=ephemeral_public_key_bytes
                )
            except Exception:
                # 尝试加载PEM格式的公钥 (向后兼容)
                ephemeral_public_key = serialization.load_pem_public_key(
                    ephemeral_public_key_bytes, backend=default_backend()
                )

            # 使用私钥和临时公钥生成共享密钥
            shared_key = private_key.key_data.exchange(ec.ECDH(), ephemeral_public_key)

            # 从共享密钥派生对称加密密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt if salt else None,
                info=b"ECIES-AES-256",
                backend=default_backend(),
            ).derive(shared_key)

            # 使用AES-GCM解密数据
            decryptor = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(iv, tag),
                backend=default_backend(),
            ).decryptor()

            # 可以添加额外的认证数据(AAD), 这里使用空字节
            decryptor.authenticate_additional_data(b"")

            # 解密数据
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            logger.debug(f"成功从Base64解密数据, 长度: {len(plaintext)} 字节")
            return plaintext
        except InvalidTag:
            logger.error("Base64解密失败: 数据完整性验证失败")
            raise ValueError("Base64解密失败: 数据可能被篡改或密钥不正确")
        except Exception as e:
            logger.error(f"Base64解密失败: {e}")
            raise ValueError(f"Base64解密失败: {str(e)}")
