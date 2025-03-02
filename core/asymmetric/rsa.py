from typing import Union, Optional, BinaryIO
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from .base import AsymmetricCipher, AsymmetricKey, KeyPair


class RSAKey(AsymmetricKey):
    """RSA密钥类，包装Cryptography库的RSA密钥"""

    def __init__(self, key_data, key_type: str):
        super().__init__(key_data, key_type, RSA.algorithm_name())

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

    @classmethod
    def from_bytes(cls, data: bytes, key_type: str, algorithm: str) -> "RSAKey":
        """从字节创建RSA密钥"""
        if algorithm != RSA.algorithm_name():
            raise ValueError(
                f"Invalid algorithm: {algorithm}, expected: {RSA.algorithm_name()}"
            )

        if key_type == "public":
            key_data = serialization.load_der_public_key(
                data, backend=default_backend()
            )
        else:
            key_data = serialization.load_der_private_key(
                data, password=None, backend=default_backend()
            )

        return cls(key_data, key_type)

    @classmethod
    def from_pem(
        cls,
        pem_data: bytes,
        key_type: str,
        algorithm: str,
        password: Optional[bytes] = None,
    ) -> "RSAKey":
        """从PEM格式创建RSA密钥"""
        if algorithm != RSA.algorithm_name():
            raise ValueError(
                f"Invalid algorithm: {algorithm}, expected: {RSA.algorithm_name()}"
            )

        if key_type == "public":
            key_data = serialization.load_pem_public_key(
                pem_data, backend=default_backend()
            )
        else:
            key_data = serialization.load_pem_private_key(
                pem_data, password=password, backend=default_backend()
            )

        return cls(key_data, key_type)


class RSA(AsymmetricCipher):
    """RSA加密算法实现，包装Cryptography库"""

    @classmethod
    def algorithm_name(cls) -> str:
        return "RSA"

    @classmethod
    def generate_key_pair(cls, key_size: int = 2048, **kwargs) -> KeyPair:
        """
        生成RSA密钥对

        Args:
            key_size: 密钥位数，至少2048位

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        if key_size < 2048:
            raise ValueError("为确保安全, RSA密钥至少为 2048 位")

        # 使用Cryptography库生成RSA密钥
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        public_key = private_key.public_key()

        return KeyPair(RSAKey(public_key, "public"), RSAKey(private_key, "private"))

    @classmethod
    def encrypt(cls, data: bytes, public_key: AsymmetricKey) -> bytes:
        """
        RSA加密

        Args:
            data: 待加密数据
            public_key: RSA公钥

        Returns:
            加密后的数据
        """
        if not cls.validate_key(public_key) or public_key.key_type != "public":
            raise ValueError("Invalid RSA public key")

        # 使用OAEP填充进行加密
        ciphertext = public_key.key_data.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return ciphertext

    @classmethod
    def decrypt(cls, encrypted_data: bytes, private_key: AsymmetricKey) -> bytes:
        """
        RSA解密

        Args:
            encrypted_data: 密文
            private_key: RSA私钥

        Returns:
            解密后的数据
        """
        if not cls.validate_key(private_key) or private_key.key_type != "private":
            raise ValueError("Invalid RSA private key")

        # 解密
        plaintext = private_key.key_data.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return plaintext

    @classmethod
    def encrypt_large_data(
        cls, data: bytes, public_key: AsymmetricKey, chunk_size: Optional[int] = None
    ) -> bytes:
        """
        加密大型数据 (分块加密)

        Args:
            data: 要加密的数据
            public_key: RSA公钥
            chunk_size: 分块大小，如果为None则根据密钥大小自动计算

        Returns:
            加密后的数据
        """
        if not cls.validate_key(public_key) or public_key.key_type != "public":
            raise ValueError("Invalid RSA public key")

        # 计算最大可加密大小 (密钥大小/8 - OAEP填充开销)
        # OAEP开销 = 2 * hash_size + 2
        # 对于SHA256, hash_size = 32字节，所以开销是66字节
        max_chunk_size = public_key.key_data.key_size // 8 - 66

        # 如果提供了chunk_size, 确保不超过最大值
        if chunk_size is None:
            chunk_size = max_chunk_size
        elif chunk_size > max_chunk_size:
            chunk_size = max_chunk_size

        # 分块加密
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
        encrypted_chunks = []

        for chunk in chunks:
            encrypted_chunk = cls.encrypt(chunk, public_key)
            encrypted_chunks.append(encrypted_chunk)

        # 合并加密块
        result = b""
        for chunk in encrypted_chunks:
            # 存储每个加密块的长度和内容
            result += len(chunk).to_bytes(4, byteorder="big")
            result += chunk

        return result

    @classmethod
    def decrypt_large_data(cls, data: bytes, private_key: AsymmetricKey) -> bytes:
        """
        解密大型数据 (分块解密)

        Args:
            data: 要解密的数据
            private_key: RSA私钥

        Returns:
            解密后的数据
        """
        if not cls.validate_key(private_key) or private_key.key_type != "private":
            raise ValueError("Invalid RSA private key")

        result = b""
        i = 0

        while i < len(data):
            # 读取块长度
            chunk_len = int.from_bytes(data[i : i + 4], byteorder="big")
            i += 4

            # 提取并解密块
            chunk = data[i : i + chunk_len]
            decrypted_chunk = cls.decrypt(chunk, private_key)
            result += decrypted_chunk

            i += chunk_len

        return result

    @classmethod
    def load_public_key(
        cls, key_data: Union[bytes, str, BinaryIO], format: str = "pem"
    ) -> AsymmetricKey:
        """
        加载公钥

        Args:
            key_data: 密钥数据
            format: 格式('pem', 'der', 'bytes')

        Returns:
            公钥对象
        """
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
            raise ValueError(f"Unsupported format: {format}")

        return RSAKey(key_obj, "public")

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
            format: 格式('pem', 'der', 'bytes')
            password: 密码(如果有)

        Returns:
            私钥对象
        """
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
            raise ValueError(f"Unsupported format: {format}")

        return RSAKey(key_obj, "private")
