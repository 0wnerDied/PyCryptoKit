"""
ECC (椭圆曲线加密) 模块
提供基于椭圆曲线的加密、解密功能
"""

import os
import base64
import logging
import tempfile
from typing import Tuple, Union, Optional, Dict

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# 配置日志
logger = logging.getLogger(__name__)


class ECCCipher:
    """椭圆曲线加密类"""

    def __init__(self, curve=ec.SECP256R1()):
        """
        初始化ECC加密器

        Args:
            curve: 椭圆曲线, 默认为 SECP256R1
        """
        self._private_key = None
        self._public_key = None
        self._curve = curve
        logger.debug(f"初始化ECC加密器, 使用曲线: {curve.name}")

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        生成ECC密钥对

        Returns:
            (private_key_pem, public_key_pem): PEM 格式的私钥和公钥
        """
        try:
            # 生成私钥
            self._private_key = ec.generate_private_key(
                curve=self._curve, backend=default_backend()
            )

            # 从私钥获取公钥
            self._public_key = self._private_key.public_key()

            # 获取PEM格式的密钥
            private_pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            logger.info(f"成功生成ECC密钥对, 使用曲线: {self._curve.name}")
            return private_pem, public_pem
        except Exception as e:
            logger.error(f"生成密钥对失败: {e}")
            raise ValueError(f"生成密钥对失败: {e}")

    def load_private_key(
        self, key_data: Union[str, bytes], password: Optional[bytes] = None
    ) -> None:
        """
        加载PEM格式的私钥

        Args:
            key_data: PEM 格式的私钥数据
            password: 如果私钥有密码保护, 提供密码
        """
        try:
            if isinstance(key_data, str):
                key_data = key_data.encode("utf-8")

            self._private_key = serialization.load_pem_private_key(
                key_data, password=password, backend=default_backend()
            )

            # 验证密钥类型
            if not isinstance(self._private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("提供的密钥不是有效的椭圆曲线私钥")

            # 从私钥获取公钥
            self._public_key = self._private_key.public_key()

            # 更新当前曲线
            self._curve = self._private_key.curve

            logger.info(f"成功加载私钥, 曲线: {self._curve.name}")
        except Exception as e:
            logger.error(f"加载私钥失败: {e}")
            raise ValueError(f"加载私钥失败: {e}")

    def load_public_key(self, key_data: Union[str, bytes]) -> None:
        """
        加载 PEM 格式的公钥

        Args:
            key_data: PEM 格式的公钥数据
        """
        try:
            if isinstance(key_data, str):
                key_data = key_data.encode("utf-8")

            self._public_key = serialization.load_pem_public_key(
                key_data, backend=default_backend()
            )

            # 验证密钥类型
            if not isinstance(self._public_key, ec.EllipticCurvePublicKey):
                raise ValueError("提供的密钥不是有效的椭圆曲线公钥")

            # 更新当前曲线
            self._curve = self._public_key.curve

            logger.info(f"成功加载公钥, 曲线: {self._curve.name}")
        except Exception as e:
            logger.error(f"加载公钥失败: {e}")
            raise ValueError(f"加载公钥失败: {e}")

    def save_private_key(self, filename: str, password: Optional[bytes] = None) -> None:
        """
        将私钥安全地保存到文件

        Args:
            filename: 要保存的文件名
            password: 可选的密码保护
        """
        if self._private_key is None:
            raise ValueError("没有可用的私钥")

        try:
            # 确定加密算法
            encryption_algorithm = serialization.NoEncryption()
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)

            # 序列化私钥
            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

            # 使用临时文件和原子操作安全写入
            fd, temp_path = tempfile.mkstemp(
                dir=os.path.dirname(os.path.abspath(filename))
            )
            try:
                with os.fdopen(fd, "wb") as temp_file:
                    temp_file.write(pem)
                # 在Unix系统上, 这是原子操作
                os.replace(temp_path, filename)
                logger.info(f"成功保存私钥到文件: {filename}")
            except Exception as e:
                os.unlink(temp_path)  # 删除临时文件
                raise e
        except Exception as e:
            logger.error(f"保存私钥失败: {e}")
            raise ValueError(f"保存私钥失败: {e}")

    def save_public_key(self, filename: str) -> None:
        """
        将公钥安全地保存到文件

        Args:
            filename: 要保存的文件名
        """
        if self._public_key is None:
            raise ValueError("没有可用的公钥")

        try:
            # 序列化公钥
            pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # 使用临时文件和原子操作安全写入
            fd, temp_path = tempfile.mkstemp(
                dir=os.path.dirname(os.path.abspath(filename))
            )
            try:
                with os.fdopen(fd, "wb") as temp_file:
                    temp_file.write(pem)
                # 在Unix系统上, 这是原子操作
                os.replace(temp_path, filename)
                logger.info(f"成功保存公钥到文件: {filename}")
            except Exception as e:
                os.unlink(temp_path)  # 删除临时文件
                raise e
        except Exception as e:
            logger.error(f"保存公钥失败: {e}")
            raise ValueError(f"保存公钥失败: {e}")

    def set_curve(self, curve_name: str) -> None:
        """设置椭圆曲线类型"""
        curves = {
            "SECP256R1": ec.SECP256R1(),
            "SECP384R1": ec.SECP384R1(),
            "SECP521R1": ec.SECP521R1(),
        }
        if curve_name not in curves:
            raise ValueError(f"不支持的曲线: {curve_name}")
        self._curve = curves[curve_name]

    def encrypt(self, data: Union[str, bytes]) -> Dict[str, bytes]:
        """
        使用 ECIES (椭圆曲线集成加密方案) 加密数据

        Args:
            data: 要加密的数据

        Returns:
            包含加密结果的字典: {
                'ephemeral_public_key': 临时公钥字节,
                'salt': 盐值,
                'iv': 初始化向量,
                'ciphertext': 带认证标签的密文
            }
        """
        if self._public_key is None:
            raise ValueError("没有可用的公钥")

        try:
            # 将字符串转换为字节
            if isinstance(data, str):
                data = data.encode("utf-8")

            # 生成临时ECC密钥对
            ephemeral_private_key = ec.generate_private_key(
                curve=self._curve, backend=default_backend()
            )
            ephemeral_public_key = ephemeral_private_key.public_key()

            # 使用ECDH密钥交换派生共享密钥
            shared_key = ephemeral_private_key.exchange(ec.ECDH(), self._public_key)

            # 生成随机盐值
            salt = os.urandom(16)

            # 使用HKDF从共享密钥派生AES密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,  # 使用随机盐值
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

            # 获取认证标签并附加到密文
            tag = encryptor.tag
            ciphertext_with_tag = ciphertext + tag

            # 序列化临时公钥
            ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )

            logger.debug(f"成功加密数据, 长度: {len(data)} 字节")

            return {
                "ephemeral_public_key": ephemeral_public_key_bytes,
                "salt": salt,
                "iv": iv,
                "ciphertext": ciphertext_with_tag,
            }
        except Exception as e:
            logger.error(f"加密失败: {e}")
            raise ValueError(f"加密失败: {e}")

    def decrypt(self, encrypted_data: Dict[str, bytes]) -> bytes:
        """
        使用ECIES解密数据

        Args:
            encrypted_data: 包含加密数据的字典, 应包含：
                - ephemeral_public_key: 临时公钥字节
                - salt: 盐值
                - iv: 初始化向量
                - ciphertext: 带认证标签的密文

        Returns:
            解密后的数据
        """
        if self._private_key is None:
            raise ValueError("没有可用的私钥")

        try:
            # 提取加密参数
            ephemeral_public_key_bytes = encrypted_data["ephemeral_public_key"]
            salt = encrypted_data.get("salt", None)  # 兼容旧版本
            iv = encrypted_data["iv"]
            ciphertext_with_tag = encrypted_data["ciphertext"]

            # 从字节数据加载临时公钥
            try:
                ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve=self._curve, data=ephemeral_public_key_bytes
                )
            except Exception as e:
                logger.error(f"无效的临时公钥或曲线不匹配: {e}")
                raise ValueError(f"无效的临时公钥或曲线不匹配: {e}")

            # 使用ECDH密钥交换派生共享密钥
            shared_key = self._private_key.exchange(ec.ECDH(), ephemeral_public_key)

            # 使用HKDF从共享密钥派生AES密钥
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256位AES密钥
                salt=salt,  # 使用提供的盐值, 如果是旧版本可能为None
                info=b"ECIES-AES-256",
                backend=default_backend(),
            ).derive(shared_key)

            # 分离密文和认证标签
            tag_length = 16  # GCM标签长度为16字节
            ciphertext = ciphertext_with_tag[:-tag_length]
            tag = ciphertext_with_tag[-tag_length:]

            # 使用AES-GCM模式解密数据
            try:
                decryptor = Cipher(
                    algorithms.AES(derived_key),
                    modes.GCM(iv, tag),
                    backend=default_backend(),
                ).decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            except InvalidTag as e:
                logger.error("解密失败: 数据完整性验证失败")
                raise ValueError("解密失败: 数据可能被篡改或密钥不正确")

            logger.debug(f"成功解密数据, 长度: {len(plaintext)} 字节")
            return plaintext
        except KeyError as e:
            logger.error(f"解密失败: 缺少必要的加密参数 {e}")
            raise ValueError(f"解密失败: 缺少必要的加密参数 {e}")
        except Exception as e:
            logger.error(f"解密失败: {e}")
            raise ValueError(f"解密失败: {e}")

    def encrypt_to_base64(self, data: Union[str, bytes]) -> Dict[str, str]:
        """
        加密数据并返回Base64编码的结果

        Args:
            data: 要加密的数据

        Returns:
            包含Base64编码加密结果的字典
        """
        if self._public_key is None:
            raise ValueError("没有可用的公钥")

        try:
            # 确保数据是字节类型
            if isinstance(data, str):
                data = data.encode("utf-8")

            # 生成临时的ECC密钥对用于此次加密
            ephemeral_key = ec.generate_private_key(
                curve=self._curve, backend=default_backend()
            )
            ephemeral_public_key = ephemeral_key.public_key()

            # 使用接收方的公钥和临时私钥生成共享密钥
            shared_key = ephemeral_key.exchange(ec.ECDH(), self._public_key)

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

    def decrypt_from_base64(self, encrypted_data: Dict[str, str]) -> bytes:
        """
        从Base64编码的加密数据中解密

        Args:
            encrypted_data: 包含Base64编码加密数据的字典

        Returns:
            解密后的字节数据
        """
        if self._private_key is None:
            raise ValueError("没有可用的私钥")

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
                    curve=self._curve, data=ephemeral_public_key_bytes
                )
            except Exception:
                # 尝试加载PEM格式的公钥 (向后兼容)
                ephemeral_public_key = serialization.load_pem_public_key(
                    ephemeral_public_key_bytes, backend=default_backend()
                )

            # 使用私钥和临时公钥生成共享密钥
            shared_key = self._private_key.exchange(ec.ECDH(), ephemeral_public_key)

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
