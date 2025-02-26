from abc import ABC, abstractmethod
from typing import Tuple, Union, Optional


class AsymmetricCipher(ABC):
    """非对称加密算法的基类"""

    @abstractmethod
    def generate_key_pair(self, key_size: int) -> Tuple:
        """生成密钥对"""
        pass

    @abstractmethod
    def encrypt(self, data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
        """加密数据"""
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """解密数据"""
        pass

    @abstractmethod
    def save_private_key(self, path: str, password: Optional[str] = None) -> None:
        """保存私钥到文件"""
        pass

    @abstractmethod
    def save_public_key(self, path: str) -> None:
        """保存公钥到文件"""
        pass

    @abstractmethod
    def load_private_key(self, path: str, password: Optional[str] = None) -> None:
        """从文件加载私钥"""
        pass

    @abstractmethod
    def load_public_key(self, path: str) -> None:
        """从文件加载公钥"""
        pass

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """加密文件"""
        chunk_size = 1024 * 1024  # 1MB chunks

        with open(input_path, "rb") as in_file, open(output_path, "wb") as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if not chunk:
                    break
                encrypted_chunk = self.encrypt(chunk, encoding=None)
                out_file.write(len(encrypted_chunk).to_bytes(4, byteorder="big"))
                out_file.write(encrypted_chunk)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """解密文件"""
        with open(input_path, "rb") as in_file, open(output_path, "wb") as out_file:
            while True:
                size_bytes = in_file.read(4)
                if not size_bytes:
                    break
                chunk_size = int.from_bytes(size_bytes, byteorder="big")
                chunk = in_file.read(chunk_size)
                decrypted_chunk = self.decrypt(chunk)
                out_file.write(decrypted_chunk)
