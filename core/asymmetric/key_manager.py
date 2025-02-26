"""
密钥管理模块
提供密钥的生成、导入导出、存储和检索功能
"""

import os
import json
import base64
import datetime
from typing import Dict, List, Optional, Tuple, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from .rsa import RSACipher
from .ecc import ECCCipher


class KeyManager:
    """密钥管理类, 用于管理不同类型的非对称加密密钥"""

    def __init__(self, storage_dir: str = None):
        """
        初始化密钥管理器

        Args:
            storage_dir: 密钥存储目录, 默认为用户主目录下的 .PyCryptoKit 目录
        """
        if storage_dir is None:
            # 默认存储在用户主目录下的 .PyCryptoKit 目录
            self.storage_dir = os.path.join(os.path.expanduser("~"), ".PyCryptoKit")
        else:
            self.storage_dir = storage_dir

        # 确保存储目录存在
        os.makedirs(self.storage_dir, exist_ok=True)

        # 密钥库文件路径
        self.keystore_path = os.path.join(self.storage_dir, "keystore.json")

        # 初始化密钥库
        self.keystore = self._load_keystore()

        # 加密器实例
        self.ciphers = {"RSA": RSACipher(), "ECC": ECCCipher()}

    def _load_keystore(self) -> Dict:
        """
        加载密钥库

        Returns:
            密钥库字典
        """
        if os.path.exists(self.keystore_path):
            with open(self.keystore_path, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return {"keys": []}
        else:
            return {"keys": []}

    def _save_keystore(self) -> None:
        """保存密钥库"""
        with open(self.keystore_path, "w") as f:
            json.dump(self.keystore, f, indent=2)
        # 设置文件权限（仅限 UNIX 系统）
        if os.name == "posix":
            os.chmod(self.keystore_path, 0o600)

    def _derive_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        从密码派生加密密钥

        Args:
            password: 用户密码
            salt: 可选的盐值，如果未提供则生成新的

        Returns:
            (key, salt): 派生的密钥和使用的盐值
        """
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def generate_key_pair(
        self, key_type: str, name: str, password: str = None, **kwargs
    ) -> Dict:
        """
        生成新的密钥对

        Args:
            key_type: 密钥类型 ('RSA', 'ECC')
            name: 密钥名称
            password: 可选的密码保护
            **kwargs: 特定算法的额外参数, 如 RSA 的 key_size

        Returns:
            密钥信息字典
        """
        if key_type not in self.ciphers:
            raise ValueError(f"不支持的密钥类型: {key_type}")

        # 获取对应的加密器
        cipher = self.ciphers[key_type]

        # 根据密钥类型设置特定参数
        if key_type == "RSA" and "key_size" in kwargs:
            private_pem, public_pem = cipher.generate_key_pair(
                key_size=kwargs["key_size"]
            )
        elif key_type == "ECC" and "curve" in kwargs:
            cipher.set_curve(kwargs["curve"])
            private_pem, public_pem = cipher.generate_key_pair()
        else:
            private_pem, public_pem = cipher.generate_key_pair()

        # 生成密钥ID
        key_id = base64.urlsafe_b64encode(os.urandom(12)).decode("utf-8")

        # 创建密钥记录
        key_info = {
            "id": key_id,
            "name": name,
            "type": key_type,
            "created_at": datetime.datetime.now().isoformat(),
            "public_key": base64.b64encode(public_pem).decode("utf-8"),
        }

        # 如果提供了密码，加密私钥
        if password:
            key, salt = self._derive_key(password)
            fernet = Fernet(key)
            encrypted_private_key = fernet.encrypt(private_pem)

            key_info["private_key"] = base64.b64encode(encrypted_private_key).decode(
                "utf-8"
            )
            key_info["salt"] = base64.b64encode(salt).decode("utf-8")
            key_info["is_encrypted"] = True
        else:
            key_info["private_key"] = base64.b64encode(private_pem).decode("utf-8")
            key_info["is_encrypted"] = False

        # 添加特定算法的额外信息
        if key_type == "RSA" and "key_size" in kwargs:
            key_info["key_size"] = kwargs["key_size"]
        elif key_type == "ECC" and "curve" in kwargs:
            key_info["curve"] = kwargs["curve"]

        # 添加到密钥库
        self.keystore["keys"].append(key_info)
        self._save_keystore()

        return key_info

    def import_key_pair(
        self,
        key_type: str,
        name: str,
        private_key: str,
        public_key: str = None,
        password: str = None,
    ) -> Dict:
        """
        导入现有密钥对

        Args:
            key_type: 密钥类型 ('RSA', 'ECC')
            name: 密钥名称
            private_key: PEM 格式的私钥
            public_key: PEM 格式的公钥, 如果为 None 则从私钥派生
            password: 可选的密码保护

        Returns:
            密钥信息字典
        """
        if key_type not in self.ciphers:
            raise ValueError(f"不支持的密钥类型: {key_type}")

        # 获取对应的加密器
        cipher = self.ciphers[key_type]

        # 确保私钥是字节格式
        if isinstance(private_key, str):
            private_key = private_key.encode("utf-8")

        # 加载私钥
        cipher.load_private_key(private_key)

        # 如果未提供公钥，尝试从私钥派生
        if public_key is None:
            # 这里假设加密器在加载私钥后可以访问公钥
            # 实际实现可能需要根据具体加密器调整
            if hasattr(cipher, "_public_key") and cipher._public_key:
                public_key = cipher.save_public_key("temp.pem")
                with open("temp.pem", "rb") as f:
                    public_key = f.read()
                os.remove("temp.pem")
            else:
                raise ValueError("无法从私钥派生公钥, 请提供公钥")
        elif isinstance(public_key, str):
            public_key = public_key.encode("utf-8")

        # 生成密钥ID
        key_id = base64.urlsafe_b64encode(os.urandom(12)).decode("utf-8")

        # 创建密钥记录
        key_info = {
            "id": key_id,
            "name": name,
            "type": key_type,
            "created_at": datetime.datetime.now().isoformat(),
            "public_key": base64.b64encode(public_key).decode("utf-8"),
        }

        # 如果提供了密码，加密私钥
        if password:
            key, salt = self._derive_key(password)
            fernet = Fernet(key)
            encrypted_private_key = fernet.encrypt(private_key)

            key_info["private_key"] = base64.b64encode(encrypted_private_key).decode(
                "utf-8"
            )
            key_info["salt"] = base64.b64encode(salt).decode("utf-8")
            key_info["is_encrypted"] = True
        else:
            key_info["private_key"] = base64.b64encode(private_key).decode("utf-8")
            key_info["is_encrypted"] = False

        # 添加到密钥库
        self.keystore["keys"].append(key_info)
        self._save_keystore()

        return key_info

    def list_keys(self) -> List[Dict]:
        """
        列出所有密钥

        Returns:
            密钥信息列表
        """
        return self.keystore["keys"]

    def get_key(self, key_id: str) -> Optional[Dict]:
        """
        获取指定ID的密钥信息

        Args:
            key_id: 密钥 ID

        Returns:
            密钥信息字典, 如果未找到则返回 None
        """
        for key in self.keystore["keys"]:
            if key["id"] == key_id:
                return key
        return None

    def get_key_by_name(self, name: str) -> Optional[Dict]:
        """
        根据名称获取密钥信息

        Args:
            name: 密钥名称

        Returns:
            密钥信息字典, 如果未找到则返回 None
        """
        for key in self.keystore["keys"]:
            if key["name"] == name:
                return key
        return None

    def delete_key(self, key_id: str) -> bool:
        """
        删除指定ID的密钥

        Args:
            key_id: 密钥ID

        Returns:
            是否成功删除
        """
        for i, key in enumerate(self.keystore["keys"]):
            if key["id"] == key_id:
                del self.keystore["keys"][i]
                self._save_keystore()
                return True
        return False

    def load_cipher(
        self, key_id: str, password: str = None
    ) -> Union[RSACipher, ECCCipher]:
        """
        加载指定ID的密钥到对应的加密器

        Args:
            key_id: 密钥ID
            password: 如果密钥有密码保护，提供密码

        Returns:
            初始化好的加密器实例
        """
        key_info = self.get_key(key_id)
        if key_info is None:
            raise ValueError(f"未找到ID为{key_id}的密钥")

        key_type = key_info["type"]
        if key_type not in self.ciphers:
            raise ValueError(f"不支持的密钥类型: {key_type}")

        # 获取对应的加密器
        cipher = self.ciphers[key_type]

        # 解码公钥
        public_key = base64.b64decode(key_info["public_key"])

        # 加载公钥
        cipher.load_public_key(public_key)

        # 如果有私钥，也加载私钥
        if "private_key" in key_info:
            private_key_data = base64.b64decode(key_info["private_key"])

            # 如果私钥有密码保护
            if key_info.get("is_encrypted", False):
                if password is None:
                    raise ValueError("该密钥有密码保护, 请提供密码")

                salt = base64.b64decode(key_info["salt"])
                key, _ = self._derive_key(password, salt)

                try:
                    fernet = Fernet(key)
                    private_key = fernet.decrypt(private_key_data)
                except Exception:
                    raise ValueError("密码错误或密钥已损坏")
            else:
                private_key = private_key_data

            # 加载私钥
            cipher.load_private_key(private_key)

        # 设置特定算法的参数
        if key_type == "ECC" and "curve" in key_info:
            cipher.set_curve(key_info["curve"])

        return cipher

    def export_key(
        self, key_id: str, private_key: bool = False, password: str = None
    ) -> Dict:
        """
        导出密钥

        Args:
            key_id: 密钥ID
            private_key: 是否导出私钥
            password: 如果密钥有密码保护, 提供密码

        Returns:
            包含密钥数据的字典
        """
        key_info = self.get_key(key_id)
        if key_info is None:
            raise ValueError(f"未找到ID为{key_id}的密钥")

        result = {
            "name": key_info["name"],
            "type": key_info["type"],
            "public_key": base64.b64decode(key_info["public_key"]).decode("utf-8"),
        }

        # 如果需要导出私钥
        if private_key and "private_key" in key_info:
            private_key_data = base64.b64decode(key_info["private_key"])

            # 如果私钥有密码保护
            if key_info.get("is_encrypted", False):
                if password is None:
                    raise ValueError("该密钥有密码保护, 请提供密码")

                salt = base64.b64decode(key_info["salt"])
                key, _ = self._derive_key(password, salt)

                try:
                    fernet = Fernet(key)
                    private_key = fernet.decrypt(private_key_data)
                except Exception:
                    raise ValueError("密码错误或密钥已损坏")
            else:
                private_key = private_key_data

            result["private_key"] = private_key.decode("utf-8")

        return result
