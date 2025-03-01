"""
RSA加密模块
提供RSA密钥生成、加密、解密、导入导出等功能
"""

import base64
from typing import Tuple, Union, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class RSACipher:
    """RSA加密解密类"""

    def __init__(self):
        """初始化RSA加密器"""
        self._private_key = None
        self._public_key = None

    def generate_key_pair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        生成RSA密钥对

        Args:
            key_size: 密钥长度, 默认2048位

        Returns:
            (private_key_pem, public_key_pem): PEM格式的私钥和公钥
        """
        if key_size < 2048:
            raise ValueError("为确保安全, RSA密钥至少为 2048 位")

        # 生成私钥
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
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

        return private_pem, public_pem

    def load_private_key(
        self, key_data: Union[str, bytes], password: Optional[bytes] = None
    ) -> None:
        """
        加载PEM格式的私钥

        Args:
            key_data: PEM格式的私钥数据
            password: 如果私钥有密码保护, 提供密码
        """
        if isinstance(key_data, str):
            key_data = key_data.encode("utf-8")

        self._private_key = serialization.load_pem_private_key(
            key_data, password=password, backend=default_backend()
        )

        # 从私钥获取公钥
        self._public_key = self._private_key.public_key()

    def load_public_key(self, key_data: Union[str, bytes]) -> None:
        """
        加载PEM格式的公钥

        Args:
            key_data: PEM格式的公钥数据
        """
        if isinstance(key_data, str):
            key_data = key_data.encode("utf-8")

        self._public_key = serialization.load_pem_public_key(
            key_data, backend=default_backend()
        )

    def save_private_key(self, filename: str, password: Optional[bytes] = None) -> None:
        """
        将私钥保存到文件

        Args:
            filename: 要保存的文件名
            password: 可选的密码保护
        """
        if self._private_key is None:
            raise ValueError("没有可用的私钥")

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

        # 写入文件
        with open(filename, "wb") as f:
            f.write(pem)

    def save_public_key(self, filename: str) -> None:
        """
        将公钥保存到文件

        Args:
            filename: 要保存的文件名
        """
        if self._public_key is None:
            raise ValueError("没有可用的公钥")

        # 序列化公钥
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 写入文件
        with open(filename, "wb") as f:
            f.write(pem)

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """
        使用公钥加密数据

        Args:
            data: 要加密的数据

        Returns:
            加密后的数据
        """
        if self._public_key is None:
            raise ValueError("没有可用的公钥")

        # 将字符串转换为字节
        if isinstance(data, str):
            data = data.encode("utf-8")

        # RSA加密有大小限制, 这里使用OAEP填充
        ciphertext = self._public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        使用私钥解密数据

        Args:
            ciphertext: 要解密的数据

        Returns:
            解密后的数据
        """
        if self._private_key is None:
            raise ValueError("没有可用的私钥")

        # 解密
        plaintext = self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return plaintext

    def encrypt_large_data(
        self, data: Union[str, bytes], chunk_size: Optional[int] = None
    ) -> bytes:
        """
        加密大型数据 (分块加密)

        Args:
            data: 要加密的数据
            chunk_size: 分块大小, 如果为None则根据密钥大小自动计算

        Returns:
            加密后的数据
        """
        if self._public_key is None:
            raise ValueError("没有可用的公钥")

        if isinstance(data, str):
            data = data.encode("utf-8")

        # 计算最大可加密大小 (密钥大小/8 - OAEP填充开销)
        # OAEP开销 = 2 * hash_size + 2
        # 对于SHA256, hash_size = 32字节, 所以开销是66字节
        max_chunk_size = self._public_key.key_size // 8 - 66

        # 如果提供了chunk_size, 确保不超过最大值
        if chunk_size is None:
            chunk_size = max_chunk_size
        elif chunk_size > max_chunk_size:
            chunk_size = max_chunk_size

        # 分块加密
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
        encrypted_chunks = []

        for i, chunk in enumerate(chunks):
            try:
                encrypted_chunk = self.encrypt(chunk)
                encrypted_chunks.append(encrypted_chunk)
            except Exception as e:
                raise ValueError(f"分块加密失败: {e}")

        # 合并加密块
        result = b""
        for chunk in encrypted_chunks:
            # 存储每个加密块的长度和内容
            result += len(chunk).to_bytes(4, byteorder="big")
            result += chunk

        return result

    def decrypt_large_data(self, data: bytes) -> bytes:
        """
        解密大型数据 (分块解密)

        Args:
            data: 要解密的数据

        Returns:
            解密后的数据
        """
        result = b""
        i = 0

        while i < len(data):
            # 读取块长度
            chunk_len = int.from_bytes(data[i : i + 4], byteorder="big")
            i += 4

            # 提取并解密块
            chunk = data[i : i + chunk_len]
            decrypted_chunk = self.decrypt(chunk)
            result += decrypted_chunk

            i += chunk_len

        return result

    def encrypt_to_base64(self, data: Union[str, bytes]) -> str:
        """
        加密数据并返回Base64编码的结果

        Args:
            data: 要加密的数据

        Returns:
            Base64编码的加密数据
        """
        encrypted = self.encrypt(data)
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt_from_base64(self, encoded_data: str) -> bytes:
        """
        解密Base64编码的加密数据

        Args:
            encoded_data: Base64编码的加密数据

        Returns:
            解密后的数据
        """
        encrypted = base64.b64decode(encoded_data)
        return self.decrypt(encrypted)
