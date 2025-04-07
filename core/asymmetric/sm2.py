"""
SM2加密模块
提供SM2密钥对生成功能
直接调用OpenSSL库实现
支持OpenSSL 3.x
"""

import logging
import xml.etree.ElementTree as ET
import base64
import os
import ctypes
import platform
from ctypes import c_void_p, c_int, c_char_p, c_long, POINTER, create_string_buffer
from typing import Optional, List

# 导入基类
from .base import AsymmetricCipher, AsymmetricKey, KeyPair

# 配置日志
logger = logging.getLogger(__name__)

# SM2使用的曲线是SM2P256v1, 对应的OID是1.2.156.10197.1.301
SM2_CURVE_NAME = "SM2"
SM2_CURVE_NID = 1172  # OpenSSL中SM2曲线的NID

# 支持的SM2密钥大小
_SM2_KEY_SIZES = [256]  # SM2只支持256位密钥

# 尝试加载OpenSSL库
try:
    if os.name == "nt":  # Windows
        try:
            # 尝试加载OpenSSL 3.x
            libssl = ctypes.windll.LoadLibrary("libssl-3.dll")
            libcrypto = ctypes.windll.LoadLibrary("libcrypto-3.dll")
        except OSError:
            # 回退到OpenSSL 1.1.x
            libssl = ctypes.windll.LoadLibrary("libssl-1_1.dll")
            libcrypto = ctypes.windll.LoadLibrary("libcrypto-1_1.dll")
    else:  # Linux/Mac
        # 检测macOS
        if platform.system() == "Darwin":
            libssl = ctypes.cdll.LoadLibrary("libssl.dylib")
            libcrypto = ctypes.cdll.LoadLibrary("libcrypto.dylib")
        # 若不是Windows或macOS，则默认为Linux
        else:
            try:
                libssl = ctypes.cdll.LoadLibrary("libssl.so.3")
                libcrypto = ctypes.cdll.LoadLibrary("libcrypto.so.3")
            except OSError:
                # 回退到OpenSSL 1.1.x
                try:
                    libssl = ctypes.cdll.LoadLibrary("libssl.so.1.1")
                    libcrypto = ctypes.cdll.LoadLibrary("libcrypto.so.1.1")
                except OSError:
                    # 最后尝试不带版本号的库
                    libssl = ctypes.cdll.LoadLibrary("libssl.so")
                    libcrypto = ctypes.cdll.LoadLibrary("libcrypto.so")
except OSError as e:
    logger.error(f"无法加载OpenSSL库: {e}")
    raise ImportError("无法加载OpenSSL库, 请确保已安装OpenSSL")

# 检查OpenSSL版本
try:
    # 在OpenSSL 3.x中, 版本函数已更改
    if hasattr(libcrypto, "OpenSSL_version"):
        libcrypto.OpenSSL_version.argtypes = [c_int]
        libcrypto.OpenSSL_version.restype = c_char_p
        version_str = libcrypto.OpenSSL_version(0).decode("utf-8")
        openssl_3 = "3." in version_str
    elif hasattr(libcrypto, "OPENSSL_version"):
        libcrypto.OPENSSL_version.argtypes = [c_int]
        libcrypto.OPENSSL_version.restype = c_char_p
        version_str = libcrypto.OPENSSL_version(0).decode("utf-8")
        openssl_3 = "3." in version_str
    else:
        # 假设是OpenSSL 3.x
        openssl_3 = True
        version_str = "未知版本"

    logger.info(f"使用OpenSSL版本: {version_str}")
except Exception as e:
    logger.warning(f"无法确定OpenSSL版本: {e}, 假设为OpenSSL 3.x")
    openssl_3 = True

# 定义OpenSSL函数原型
# 基本EC函数
try:
    libcrypto.EC_KEY_new.restype = c_void_p
    libcrypto.EC_KEY_free.argtypes = [c_void_p]
    libcrypto.EC_KEY_generate_key.argtypes = [c_void_p]
    libcrypto.EC_KEY_generate_key.restype = c_int
    libcrypto.EC_KEY_get0_private_key.argtypes = [c_void_p]
    libcrypto.EC_KEY_get0_private_key.restype = c_void_p
    libcrypto.EC_KEY_get0_public_key.argtypes = [c_void_p]
    libcrypto.EC_KEY_get0_public_key.restype = c_void_p
    libcrypto.EC_KEY_set_private_key.argtypes = [c_void_p, c_void_p]
    libcrypto.EC_KEY_set_public_key.argtypes = [c_void_p, c_void_p]
    libcrypto.EC_KEY_new_by_curve_name.argtypes = [c_int]
    libcrypto.EC_KEY_new_by_curve_name.restype = c_void_p
    libcrypto.EC_KEY_get0_group.argtypes = [c_void_p]
    libcrypto.EC_KEY_get0_group.restype = c_void_p

    # BIGNUM函数
    libcrypto.BN_new.restype = c_void_p
    libcrypto.BN_free.argtypes = [c_void_p]
    libcrypto.BN_bin2bn.argtypes = [c_char_p, c_int, c_void_p]
    libcrypto.BN_bin2bn.restype = c_void_p
    libcrypto.BN_bn2bin.argtypes = [c_void_p, c_char_p]
    libcrypto.BN_bn2bin.restype = c_int
    libcrypto.BN_bn2hex.argtypes = [c_void_p]
    libcrypto.BN_bn2hex.restype = c_char_p
    libcrypto.BN_hex2bn.argtypes = [POINTER(c_void_p), c_char_p]
    libcrypto.BN_hex2bn.restype = c_int

    # 在OpenSSL 3.x中, 某些函数名称已更改
    if openssl_3:

        def bn_num_bytes(bn_ptr):
            # 在OpenSSL 3.x中, 可能需要使用其他方法获取BIGNUM大小
            # 这里使用BN_bn2bin先尝试一个大缓冲区
            buf = create_string_buffer(256)  # 假设最大256字节
            length = libcrypto.BN_bn2bin(bn_ptr, buf)
            return length

        # 替换原始函数
        libcrypto.BN_num_bytes = bn_num_bytes
    else:
        # OpenSSL 1.1.x
        libcrypto.BN_num_bytes.argtypes = [c_void_p]
        libcrypto.BN_num_bytes.restype = c_int

    # EC点函数
    libcrypto.EC_POINT_new.argtypes = [c_void_p]
    libcrypto.EC_POINT_new.restype = c_void_p
    libcrypto.EC_POINT_free.argtypes = [c_void_p]
    libcrypto.EC_GROUP_new_by_curve_name.argtypes = [c_int]
    libcrypto.EC_GROUP_new_by_curve_name.restype = c_void_p
    libcrypto.EC_GROUP_free.argtypes = [c_void_p]

    # 点编码函数
    libcrypto.EC_POINT_point2hex.argtypes = [c_void_p, c_void_p, c_int, c_void_p]
    libcrypto.EC_POINT_point2hex.restype = c_char_p
    libcrypto.EC_POINT_hex2point.argtypes = [c_void_p, c_char_p, c_void_p, c_void_p]
    libcrypto.EC_POINT_hex2point.restype = c_void_p

    # 点编码格式常量
    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    # 检查曲线名称函数
    if hasattr(libcrypto, "EC_GROUP_get_curve_name"):
        libcrypto.EC_GROUP_get_curve_name.argtypes = [c_void_p]
        libcrypto.EC_GROUP_get_curve_name.restype = c_int

    # 坐标函数根据OpenSSL版本有所不同
    if openssl_3:
        # OpenSSL 3.x
        if hasattr(libcrypto, "EC_POINT_get_affine_coordinates"):
            libcrypto.EC_POINT_get_affine_coordinates.argtypes = [
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
            ]
            libcrypto.EC_POINT_get_affine_coordinates.restype = c_int
        else:
            logger.warning(
                "EC_POINT_get_affine_coordinates函数不可用, 尝试使用EC_POINT_get_affine_coordinates_GFp"
            )
            libcrypto.EC_POINT_get_affine_coordinates_GFp.argtypes = [
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
            ]
            libcrypto.EC_POINT_get_affine_coordinates_GFp.restype = c_int
            # 创建别名
            libcrypto.EC_POINT_get_affine_coordinates = (
                libcrypto.EC_POINT_get_affine_coordinates_GFp
            )

        if hasattr(libcrypto, "EC_POINT_set_affine_coordinates"):
            libcrypto.EC_POINT_set_affine_coordinates.argtypes = [
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
            ]
            libcrypto.EC_POINT_set_affine_coordinates.restype = c_int
        else:
            logger.warning(
                "EC_POINT_set_affine_coordinates函数不可用, 尝试使用EC_POINT_set_affine_coordinates_GFp"
            )
            libcrypto.EC_POINT_set_affine_coordinates_GFp.argtypes = [
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
                c_void_p,
            ]
            libcrypto.EC_POINT_set_affine_coordinates_GFp.restype = c_int
            # 创建别名
            libcrypto.EC_POINT_set_affine_coordinates = (
                libcrypto.EC_POINT_set_affine_coordinates_GFp
            )
    else:
        # OpenSSL 1.1.x
        libcrypto.EC_POINT_get_affine_coordinates_GFp.argtypes = [
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
        ]
        libcrypto.EC_POINT_get_affine_coordinates_GFp.restype = c_int
        libcrypto.EC_POINT_set_affine_coordinates_GFp.argtypes = [
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
        ]
        libcrypto.EC_POINT_set_affine_coordinates_GFp.restype = c_int
        # 创建别名以便统一API
        libcrypto.EC_POINT_get_affine_coordinates = (
            libcrypto.EC_POINT_get_affine_coordinates_GFp
        )
        libcrypto.EC_POINT_set_affine_coordinates = (
            libcrypto.EC_POINT_set_affine_coordinates_GFp
        )

    # DER/PEM编码函数
    libcrypto.i2d_ECPrivateKey.argtypes = [c_void_p, POINTER(c_char_p)]
    libcrypto.i2d_ECPrivateKey.restype = c_int
    libcrypto.d2i_ECPrivateKey.argtypes = [POINTER(c_void_p), POINTER(c_char_p), c_long]
    libcrypto.d2i_ECPrivateKey.restype = c_void_p
    libcrypto.i2d_EC_PUBKEY.argtypes = [c_void_p, POINTER(c_char_p)]
    libcrypto.i2d_EC_PUBKEY.restype = c_int
    libcrypto.d2i_EC_PUBKEY.argtypes = [POINTER(c_void_p), POINTER(c_char_p), c_long]
    libcrypto.d2i_EC_PUBKEY.restype = c_void_p
    libcrypto.PEM_write_bio_ECPrivateKey.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_char_p,
        c_int,
        c_void_p,
        c_void_p,
    ]
    libcrypto.PEM_write_bio_ECPrivateKey.restype = c_int
    libcrypto.i2d_PKCS8PrivateKey_bio.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_char_p,
        c_int,
        c_void_p,
        c_void_p,
    ]
    libcrypto.i2d_PKCS8PrivateKey_bio.restype = c_int
    libcrypto.PEM_write_bio_EC_PUBKEY.argtypes = [c_void_p, c_void_p]
    libcrypto.PEM_write_bio_EC_PUBKEY.restype = c_int
    libcrypto.PEM_read_bio_ECPrivateKey.argtypes = [
        c_void_p,
        POINTER(c_void_p),
        c_void_p,
        c_void_p,
    ]
    libcrypto.PEM_read_bio_ECPrivateKey.restype = c_void_p
    libcrypto.PEM_read_bio_EC_PUBKEY.argtypes = [
        c_void_p,
        POINTER(c_void_p),
        c_void_p,
        c_void_p,
    ]
    libcrypto.PEM_read_bio_EC_PUBKEY.restype = c_void_p

    # BIO函数
    libcrypto.BIO_new_mem_buf.argtypes = [c_void_p, c_int]
    libcrypto.BIO_new_mem_buf.restype = c_void_p
    libcrypto.BIO_free.argtypes = [c_void_p]
    libcrypto.BIO_free.restype = c_int
    libcrypto.BIO_new.argtypes = [c_void_p]
    libcrypto.BIO_new.restype = c_void_p
    libcrypto.BIO_s_mem.restype = c_void_p
    libcrypto.BIO_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
    libcrypto.BIO_ctrl.restype = c_long

    # 检查asn1标志设置函数
    if hasattr(libcrypto, "EC_KEY_set_asn1_flag"):
        libcrypto.EC_KEY_set_asn1_flag.argtypes = [c_void_p, c_int]
    else:
        # 在OpenSSL 3.x中, 这个函数可能已经被移除
        logger.warning("EC_KEY_set_asn1_flag函数不可用, 将使用空实现")

        # 创建一个空函数作为替代
        def ec_key_set_asn1_flag(key, flag):
            return 1

        libcrypto.EC_KEY_set_asn1_flag = ec_key_set_asn1_flag

    # EVP 和 PKCS#8 相关函数
    libcrypto.EVP_PKEY_new.restype = c_void_p
    libcrypto.EVP_PKEY_free.argtypes = [c_void_p]
    libcrypto.EVP_PKEY_set1_EC_KEY.argtypes = [c_void_p, c_void_p]
    libcrypto.EVP_PKEY_set1_EC_KEY.restype = c_int
    libcrypto.EVP_PKEY_get1_EC_KEY.argtypes = [c_void_p]
    libcrypto.EVP_PKEY_get1_EC_KEY.restype = c_void_p
    libcrypto.PEM_write_bio_PKCS8PrivateKey.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_char_p,
        c_int,
        c_void_p,
        c_void_p,
    ]
    libcrypto.PEM_write_bio_PKCS8PrivateKey.restype = c_int
    libcrypto.PEM_read_bio_PrivateKey.argtypes = [
        c_void_p,
        POINTER(c_void_p),
        c_void_p,
        c_void_p,
    ]
    libcrypto.PEM_read_bio_PrivateKey.restype = c_void_p
    libcrypto.PEM_write_bio_PUBKEY.argtypes = [c_void_p, c_void_p]
    libcrypto.PEM_write_bio_PUBKEY.restype = c_int

    # 加密算法函数
    libcrypto.EVP_aes_256_cbc.argtypes = []
    libcrypto.EVP_aes_256_cbc.restype = c_void_p

except AttributeError as e:
    logger.error(f"函数定义错误: {e}")
    raise ImportError(f"OpenSSL库函数定义错误: {e}")

# BIO控制命令
BIO_CTRL_INFO = 3


# 定义辅助函数
def _bn_to_bytes(bn_ptr) -> bytes:
    """将BIGNUM转换为字节串"""
    if not bn_ptr:
        return b""

    try:
        size = libcrypto.BN_num_bytes(bn_ptr)
        buf = create_string_buffer(size)
        libcrypto.BN_bn2bin(bn_ptr, buf)
        return buf.raw
    except Exception as e:
        logger.error(f"BIGNUM转换为字节串失败: {e}")
        raise ValueError(f"BIGNUM转换为字节串失败: {e}")


def _bn_to_hex(bn_ptr) -> str:
    """将BIGNUM转换为十六进制字符串"""
    if not bn_ptr:
        return ""

    try:
        hex_str = libcrypto.BN_bn2hex(bn_ptr)
        if not hex_str:
            raise ValueError("BN_bn2hex返回NULL")

        result = ctypes.string_at(hex_str).decode("ascii")
        return result.lower()  # 转换为小写, 与Java风格一致
    except Exception as e:
        logger.error(f"BIGNUM转换为十六进制字符串失败: {e}")
        raise ValueError(f"BIGNUM转换为十六进制字符串失败: {e}")


def _bio_to_string(bio) -> bytes:
    """从BIO获取字符串数据"""
    data_ptr = c_char_p()
    data_len = libcrypto.BIO_ctrl(bio, BIO_CTRL_INFO, 0, ctypes.byref(data_ptr))
    if data_len > 0 and data_ptr:
        return ctypes.string_at(data_ptr, data_len)
    return b""


class SM2Key(AsymmetricKey):
    """SM2密钥类, 直接包装OpenSSL的EC_KEY结构"""

    def __init__(self, key_data, key_type: str, password: Optional[bytes] = None):
        super().__init__(key_data, key_type, SM2.algorithm_name())
        self.password = password

        # key_data应该是一个EC_KEY指针
        if not key_data:
            raise ValueError(f"无效的SM2{key_type}密钥")

    def __del__(self):
        """析构函数, 释放EC_KEY"""
        if hasattr(self, "key_data") and self.key_data:
            libcrypto.EC_KEY_free(self.key_data)
            self.key_data = None

    def to_pem(self) -> bytes:
        """将密钥转换为OpenSSL兼容的PEM格式"""
        bio = libcrypto.BIO_new(libcrypto.BIO_s_mem())
        if not bio:
            raise MemoryError("无法创建BIO")

        try:
            if self.key_type == "public":
                # 公钥使用标准的 SubjectPublicKeyInfo 格式 (PUBKEY)
                evp_pkey = libcrypto.EVP_PKEY_new()
                if not evp_pkey:
                    raise MemoryError("无法创建EVP_PKEY")

                try:
                    # 设置 EVP_PKEY 为我们的 EC_KEY
                    result = libcrypto.EVP_PKEY_set1_EC_KEY(evp_pkey, self.key_data)
                    if result != 1:
                        raise ValueError("无法设置EVP_PKEY")

                    # 写入 PUBLIC KEY 格式
                    result = libcrypto.PEM_write_bio_PUBKEY(bio, evp_pkey)
                    if result != 1:
                        raise ValueError("转换公钥到PEM格式失败")

                    return _bio_to_string(bio)
                finally:
                    libcrypto.EVP_PKEY_free(evp_pkey)
            else:
                # 私钥使用 PKCS#8 格式, 与命令行工具生成的格式一致
                evp_pkey = libcrypto.EVP_PKEY_new()
                if not evp_pkey:
                    raise MemoryError("无法创建EVP_PKEY")

                try:
                    # 设置 EVP_PKEY 为我们的 EC_KEY
                    result = libcrypto.EVP_PKEY_set1_EC_KEY(evp_pkey, self.key_data)
                    if result != 1:
                        raise ValueError("无法设置EVP_PKEY")

                    # 写入 PKCS#8 格式
                    if self.password:
                        cipher = libcrypto.EVP_aes_256_cbc()
                        result = libcrypto.PEM_write_bio_PKCS8PrivateKey(
                            bio,
                            evp_pkey,
                            cipher,
                            self.password,
                            len(self.password),
                            None,
                            None,
                        )
                    else:
                        result = libcrypto.PEM_write_bio_PKCS8PrivateKey(
                            bio, evp_pkey, None, None, 0, None, None
                        )

                    if result != 1:
                        raise ValueError("转换私钥到PKCS#8格式失败")

                    return _bio_to_string(bio)
                finally:
                    libcrypto.EVP_PKEY_free(evp_pkey)
        finally:
            libcrypto.BIO_free(bio)

    def to_der(self) -> bytes:
        """将密钥转换为DER格式"""
        if self.key_type == "public":
            # 获取DER编码的公钥长度
            length = libcrypto.i2d_EC_PUBKEY(self.key_data, None)
            if length <= 0:
                raise ValueError("获取公钥DER编码长度失败")

            # 分配内存并获取DER编码
            buf = create_string_buffer(length)
            p_buf = ctypes.cast(buf, POINTER(c_char_p))
            length = libcrypto.i2d_EC_PUBKEY(self.key_data, p_buf)
            if length <= 0:
                raise ValueError("公钥DER编码失败")

            return buf.raw[:length]
        else:
            # 对于私钥，如果有密码则使用PKCS#8格式
            if self.password:
                # 创建EVP_PKEY
                evp_pkey = libcrypto.EVP_PKEY_new()
                if not evp_pkey:
                    raise MemoryError("无法创建EVP_PKEY")

                try:
                    # 设置EVP_PKEY为我们的EC_KEY
                    result = libcrypto.EVP_PKEY_set1_EC_KEY(evp_pkey, self.key_data)
                    if result != 1:
                        raise ValueError("无法设置EVP_PKEY")

                    # 创建内存BIO
                    bio = libcrypto.BIO_new(libcrypto.BIO_s_mem())
                    if not bio:
                        raise MemoryError("无法创建BIO")

                    try:
                        # 使用i2d_PKCS8PrivateKey_bio函数
                        cipher = libcrypto.EVP_aes_256_cbc()
                        result = libcrypto.i2d_PKCS8PrivateKey_bio(
                            bio,
                            evp_pkey,
                            cipher,
                            self.password,
                            len(self.password),
                            None,
                            None,
                        )

                        if result != 1:
                            raise ValueError("转换加密私钥到DER格式失败")

                        # 从BIO获取数据
                        return _bio_to_string(bio)
                    finally:
                        libcrypto.BIO_free(bio)
                finally:
                    libcrypto.EVP_PKEY_free(evp_pkey)
            else:
                # 未加密的私钥使用标准DER格式
                length = libcrypto.i2d_ECPrivateKey(self.key_data, None)
                if length <= 0:
                    raise ValueError("获取私钥DER编码长度失败")

                buf = create_string_buffer(length)
                p_buf = ctypes.cast(buf, POINTER(c_char_p))
                length = libcrypto.i2d_ECPrivateKey(self.key_data, p_buf)
                if length <= 0:
                    raise ValueError("私钥DER编码失败")

                return buf.raw[:length]

    def to_openssh(self) -> bytes:
        """将密钥转换为OpenSSH格式"""
        # SM2不支持OpenSSH格式, 返回PEM格式
        logger.warning("SM2不支持OpenSSH格式, 返回PEM格式")
        return self.to_pem()

    def to_xml(self) -> str:
        """将密钥转换为XML格式"""
        # 获取EC_KEY的group
        group = libcrypto.EC_KEY_get0_group(self.key_data)
        if not group:
            raise ValueError("无法获取EC_KEY的group")

        # 获取公钥点
        point = libcrypto.EC_KEY_get0_public_key(self.key_data)
        if not point:
            raise ValueError("无法获取公钥点")

        # 创建BIGNUM用于存储坐标
        x = libcrypto.BN_new()
        y = libcrypto.BN_new()

        try:
            # 获取点的坐标
            result = libcrypto.EC_POINT_get_affine_coordinates(group, point, x, y, None)
            if result != 1:
                raise ValueError("获取点坐标失败")

            # 转换为字节串
            x_bytes = _bn_to_bytes(x)
            y_bytes = _bn_to_bytes(y)

            # 创建XML根元素
            root = ET.Element("SM2KeyValue")

            # 添加曲线信息
            curve = ET.SubElement(root, "Curve")
            curve.text = SM2_CURVE_NAME

            # 添加X坐标
            x_elem = ET.SubElement(root, "X")
            x_elem.text = base64.b64encode(x_bytes).decode("utf-8")

            # 添加Y坐标
            y_elem = ET.SubElement(root, "Y")
            y_elem.text = base64.b64encode(y_bytes).decode("utf-8")

            # 如果是私钥, 添加私钥值
            if self.key_type == "private":
                priv_key = libcrypto.EC_KEY_get0_private_key(self.key_data)
                if not priv_key:
                    raise ValueError("无法获取私钥值")

                priv_bytes = _bn_to_bytes(priv_key)
                d = ET.SubElement(root, "D")
                d.text = base64.b64encode(priv_bytes).decode("utf-8")

            return ET.tostring(root, encoding="unicode")
        finally:
            libcrypto.BN_free(x)
            libcrypto.BN_free(y)

    def to_hex(self) -> str:
        """
        将密钥转换为纯十六进制字符串格式

        Returns:
            对于公钥: 完整的编码点的十六进制表示
            对于私钥: D值的十六进制表示
        """
        if self.key_type == "public":
            # 获取公钥点的完整编码(非压缩格式)
            group = libcrypto.EC_KEY_get0_group(self.key_data)
            point = libcrypto.EC_KEY_get0_public_key(self.key_data)

            if not group or not point:
                raise ValueError("无法获取公钥点")

            # 使用EC_POINT_point2hex获取十六进制表示
            hex_str = libcrypto.EC_POINT_point2hex(
                group, point, POINT_CONVERSION_UNCOMPRESSED, None
            )
            if not hex_str:
                raise ValueError("无法将公钥点转换为十六进制")

            result = ctypes.string_at(hex_str).decode("ascii")
            return result.lower()  # 转换为小写, 与Java风格一致
        else:
            # 对于私钥, 只返回D值的十六进制表示
            priv_key = libcrypto.EC_KEY_get0_private_key(self.key_data)
            if not priv_key:
                raise ValueError("无法获取私钥值")

            return _bn_to_hex(priv_key)

    def save_to_file(
        self, filepath: str, format: str = "pem", password: Optional[bytes] = None
    ) -> None:
        """
        将密钥保存到文件

        Args:
            filepath: 文件路径
            format: 文件格式 ('pem', 'der', 'xml', 'hex', 'hex-dict')
            password: 加密密码 (仅适用于私钥)
        """
        try:
            # 如果没有提供密码, 但密钥对象有密码, 则使用密钥对象的密码
            if not password and self.password:
                password = self.password

            if format.lower() == "pem":
                # 使用to_pem方法获取PEM格式
                if self.key_type == "private" and password:
                    # 保存密钥时更新密码
                    old_password = self.password
                    self.password = password
                    key_bytes = self.to_pem()
                    self.password = old_password
                else:
                    key_bytes = self.to_pem()

                with open(filepath, "wb") as f:
                    f.write(key_bytes)

            elif format.lower() == "der":
                key_bytes = self.to_der()
                with open(filepath, "wb") as f:
                    f.write(key_bytes)

            elif format.lower() == "openssh":
                logger.warning("SM2不支持OpenSSH格式, 使用PEM格式")
                key_bytes = self.to_pem()
                with open(filepath, "wb") as f:
                    f.write(key_bytes)

            elif format.lower() == "xml":
                key_bytes = self.to_xml().encode("utf-8")
                with open(filepath, "wb") as f:
                    f.write(key_bytes)

            elif format.lower() == "hex":
                # 获取纯十六进制格式
                hex_str = self.to_hex()

                # 写入文件
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(hex_str)

            else:
                raise ValueError(f"不支持的格式: {format}")

            logger.info(f"SM2密钥已保存到 {filepath}")

        except Exception as e:
            logger.error(f"保存SM2密钥失败: {e}")
            raise ValueError(f"保存SM2密钥失败: {e}")


class SM2(AsymmetricCipher):
    """SM2加密算法实现, 直接调用OpenSSL库"""

    @staticmethod
    def algorithm_name() -> str:
        return "SM2"

    @staticmethod
    def get_supported_key_sizes() -> List[int]:
        """获取支持的密钥大小列表"""
        return _SM2_KEY_SIZES

    @staticmethod
    def generate_key_pair(**kwargs) -> KeyPair:
        """
        生成SM2密钥对

        Args:
            **kwargs: 其他参数
                - password: 私钥加密密码 (可选)

        Returns:
            包含公钥和私钥的KeyPair对象
        """
        try:
            # 获取密码
            password = kwargs.get("password")

            # 创建SM2曲线的EC_KEY
            key = libcrypto.EC_KEY_new_by_curve_name(SM2_CURVE_NID)
            if not key:
                raise ValueError("创建SM2 EC_KEY失败")

            # 生成密钥对
            result = libcrypto.EC_KEY_generate_key(key)
            if result != 1:
                libcrypto.EC_KEY_free(key)
                raise ValueError("生成SM2密钥对失败")

            # 设置密钥的NAMED_CURVE标志
            libcrypto.EC_KEY_set_asn1_flag(key, 1)  # OPENSSL_EC_NAMED_CURVE

            # 复制一份公钥
            pub_key = libcrypto.EC_KEY_new_by_curve_name(SM2_CURVE_NID)
            if not pub_key:
                libcrypto.EC_KEY_free(key)
                raise ValueError("创建SM2公钥失败")

            # 获取原始密钥的公钥点
            group = libcrypto.EC_KEY_get0_group(key)
            point = libcrypto.EC_KEY_get0_public_key(key)

            # 设置公钥
            result = libcrypto.EC_KEY_set_public_key(pub_key, point)
            if result != 1:
                libcrypto.EC_KEY_free(key)
                libcrypto.EC_KEY_free(pub_key)
                raise ValueError("设置SM2公钥失败")

            logger.info("成功生成SM2密钥对")

            # 创建并返回密钥对
            return KeyPair(SM2Key(pub_key, "public"), SM2Key(key, "private", password))
        except Exception as e:
            logger.error(f"生成SM2密钥对失败: {e}")
            raise ValueError(f"生成SM2密钥对失败: {e}")
