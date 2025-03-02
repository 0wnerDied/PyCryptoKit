"""
ElGamal 加密模块
提供基于离散对数问题的非对称加密功能
"""

import os
import base64
import logging
from typing import Union, Optional, Dict, BinaryIO

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)


class ElGamalKey(AsymmetricKey):
    """ElGamal密钥类，包装DSA/DH参数和密钥"""

    def __init__(self, key_data, key_type: str, params=None):
        super().__init__(key_data, key_type, ElGamal.algorithm_name())
        self.params = params  # 存储DH参数

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


class ElGamal(AsymmetricCipher):
    """ElGamal加密算法实现"""

    @classmethod
    def algorithm_name(cls) -> str:
        return "ElGamal"

    @classmethod
    def generate_key_pair(cls, key_size: int = 2048, **kwargs) -> KeyPair:
        """
        生成ElGamal密钥对

        Args:
            key_size: 密钥大小，默认2048位

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        try:
            # 生成DSA参数，我们将使用这些参数来实现ElGamal
            # DSA参数包含p, q, g值，这些也是ElGamal所需的
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
                ElGamalKey(private_key, "private", parameters),
            )
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")

    @classmethod
    def encrypt(cls, data: bytes, public_key: AsymmetricKey) -> bytes:
        """
        使用ElGamal算法加密数据

        Args:
            data: 要加密的数据
            public_key: ElGamal公钥

        Returns:
            序列化的加密数据
        """
        if not cls.validate_key(public_key) or public_key.key_type != "public":
            raise ValueError("无效的ElGamal公钥")

        try:
            # 获取DSA参数
            dsa_public_key = public_key.key_data
            parameters = public_key.params

            # 为此次加密生成临时私钥
            ephemeral_private_key = parameters.generate_private_key()
            ephemeral_public_key = ephemeral_private_key.public_key()

            # 计算共享密钥 - 在ElGamal中，这相当于g^(xy) mod p
            # 由于cryptography库没有直接提供ElGamal，我们使用DH密钥交换来模拟
            # 将DSA公钥数字参数提取出来
            dsa_numbers = dsa_public_key.public_numbers()
            p = dsa_numbers.parameter_numbers.p
            g = dsa_numbers.parameter_numbers.g
            y = dsa_numbers.y  # 接收方的公钥

            # 提取临时私钥的数字
            x = ephemeral_private_key.private_numbers().x  # 临时私钥

            # 计算共享密钥 s = y^x mod p
            shared_secret = pow(y, x, p)
            shared_key = shared_secret.to_bytes(
                (shared_secret.bit_length() + 7) // 8, byteorder="big"
            )

            # 使用KDF从共享密钥派生对称加密密钥
            salt = os.urandom(16)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,
                info=b"ElGamal-AES-256",
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

            # 提取临时公钥的数字参数
            k_public = ephemeral_public_key.public_numbers().y

            # 序列化临时公钥 - 我们只需要y值
            k_public_bytes = k_public.to_bytes(
                (k_public.bit_length() + 7) // 8, byteorder="big"
            )

            # 构建加密结果
            # 格式: [4字节k长度][临时公钥k][16字节盐值][16字节IV][16字节标签][密文]
            result = len(k_public_bytes).to_bytes(4, byteorder="big")
            result += k_public_bytes
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
        使用ElGamal解密数据

        Args:
            encrypted_data: 加密的数据
            private_key: ElGamal私钥

        Returns:
            解密后的数据
        """
        if not cls.validate_key(private_key) or private_key.key_type != "private":
            raise ValueError("无效的ElGamal私钥")

        try:
            # 解析加密数据
            # 格式: [4字节k长度][临时公钥k][16字节盐值][16字节IV][16字节标签][密文]
            i = 0

            # 读取临时公钥长度
            k_len = int.from_bytes(encrypted_data[i : i + 4], byteorder="big")
            i += 4

            # 读取临时公钥
            k_public_bytes = encrypted_data[i : i + k_len]
            i += k_len

            # 读取盐值、IV和标签
            salt = encrypted_data[i : i + 16]
            i += 16

            iv = encrypted_data[i : i + 16]
            i += 16

            tag = encrypted_data[i : i + 16]
            i += 16

            # 剩余部分是密文
            ciphertext = encrypted_data[i:]

            # 获取DSA参数
            dsa_private_key = private_key.key_data
            dsa_numbers = dsa_private_key.private_numbers()
            p = dsa_numbers.public_numbers.parameter_numbers.p
            x = dsa_numbers.x  # 接收方的私钥

            # 将临时公钥字节转换为整数
            k_public = int.from_bytes(k_public_bytes, byteorder="big")

            # 计算共享密钥 s = k^x mod p
            shared_secret = pow(k_public, x, p)
            shared_key = shared_secret.to_bytes(
                (shared_secret.bit_length() + 7) // 8, byteorder="big"
            )

            # 使用KDF从共享密钥派生对称加密密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,
                info=b"ElGamal-AES-256",
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
            except Exception:
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
            if not isinstance(key_obj, dsa.DSAPublicKey):
                raise ValueError("提供的密钥不是有效的DSA公钥")

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
            if not isinstance(key_obj, dsa.DSAPrivateKey):
                raise ValueError("提供的密钥不是有效的DSA私钥")

            # 从私钥中提取参数
            params = dsa.DSAParameterNumbers(
                p=key_obj.private_numbers().public_numbers.parameter_numbers.p,
                q=key_obj.private_numbers().public_numbers.parameter_numbers.q,
                g=key_obj.private_numbers().public_numbers.parameter_numbers.g,
            ).parameters(default_backend())

            return ElGamalKey(key_obj, "private", params)

        except Exception as e:
            logger.error(f"加载私钥失败: {e}")
            raise ValueError(f"加载私钥失败: {e}")

    @classmethod
    def validate_key(cls, key: AsymmetricKey) -> bool:
        """
        验证密钥是否为有效的ElGamal密钥

        Args:
            key: 要验证的密钥

        Returns:
            如果是有效的ElGamal密钥则返回True
        """
        if not isinstance(key, ElGamalKey):
            return False

        if key.key_type == "public":
            return isinstance(key.key_data, dsa.DSAPublicKey)
        else:
            return isinstance(key.key_data, dsa.DSAPrivateKey)

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
            raise ValueError("无效的ElGamal公钥")

        try:
            # 获取DSA参数
            dsa_public_key = public_key.key_data
            parameters = public_key.params

            # 为此次加密生成临时私钥
            ephemeral_private_key = parameters.generate_private_key()
            ephemeral_public_key = ephemeral_private_key.public_key()

            # 计算共享密钥
            dsa_numbers = dsa_public_key.public_numbers()
            p = dsa_numbers.parameter_numbers.p
            g = dsa_numbers.parameter_numbers.g
            y = dsa_numbers.y  # 接收方的公钥

            # 提取临时私钥的数字
            x = ephemeral_private_key.private_numbers().x  # 临时私钥

            # 计算共享密钥 s = y^x mod p
            shared_secret = pow(y, x, p)
            shared_key = shared_secret.to_bytes(
                (shared_secret.bit_length() + 7) // 8, byteorder="big"
            )

            # 使用KDF从共享密钥派生对称加密密钥
            salt = os.urandom(16)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,
                info=b"ElGamal-AES-256",
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

            # 提取临时公钥的数字参数
            k_public = ephemeral_public_key.public_numbers().y

            # 序列化临时公钥 - 我们只需要y值
            k_public_bytes = k_public.to_bytes(
                (k_public.bit_length() + 7) // 8, byteorder="big"
            )

            # 返回Base64编码的结果
            return {
                "k": base64.b64encode(k_public_bytes).decode("utf-8"),
                "iv": base64.b64encode(iv).decode("utf-8"),
                "salt": base64.b64encode(salt).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "tag": base64.b64encode(tag).decode("utf-8"),
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
            raise ValueError("无效的ElGamal私钥")

        try:
            # 解码Base64数据
            k_public_bytes = base64.b64decode(encrypted_data["k"])
            iv = base64.b64decode(encrypted_data["iv"])
            salt = base64.b64decode(encrypted_data["salt"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            tag = base64.b64decode(encrypted_data["tag"])

            # 获取DSA参数
            dsa_private_key = private_key.key_data
            dsa_numbers = dsa_private_key.private_numbers()
            p = dsa_numbers.public_numbers.parameter_numbers.p
            x = dsa_numbers.x  # 接收方的私钥

            # 将临时公钥字节转换为整数
            k_public = int.from_bytes(k_public_bytes, byteorder="big")

            # 计算共享密钥 s = k^x mod p
            shared_secret = pow(k_public, x, p)
            shared_key = shared_secret.to_bytes(
                (shared_secret.bit_length() + 7) // 8, byteorder="big"
            )

            # 使用KDF从共享密钥派生对称加密密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,
                info=b"ElGamal-AES-256",
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
            except Exception:
                logger.error("Base64解密失败: 数据完整性验证失败")
                raise ValueError("Base64解密失败: 数据可能被篡改或密钥不正确")

            logger.debug(f"成功从Base64解密数据, 长度: {len(plaintext)} 字节")
            return plaintext
        except Exception as e:
            logger.error(f"Base64解密失败: {e}")
            raise ValueError(f"Base64解密失败: {str(e)}")
