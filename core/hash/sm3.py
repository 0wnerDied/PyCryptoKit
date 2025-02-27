"""
国密 SM3 哈希算法实现
"""

from typing import Union, Optional
import binascii
from math import ceil
from .base import HashBase

rotl = lambda x, n: ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)
bytes_to_list = lambda data: [i for i in data]

# SM3 初始向量
IV = [
    1937774191,
    1226093241,
    388252375,
    3666478592,
    2842636476,
    372324522,
    3817729613,
    2969243214,
]

# 常量 T_j
T_j = [
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2043430169,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
    2055708042,
]


def sm3_ff_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret


def sm3_gg_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | ((~x) & z)
    return ret


def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))


def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))


def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i * 4, (i + 1) * 4):
            data = data + b_i[k] * weight
            weight = int(weight / 0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = (
            sm3_p_1(w[j - 16] ^ w[j - 9] ^ (rotl(w[j - 3], 15 % 32)))
            ^ (rotl(w[j - 13], 7 % 32))
            ^ w[j - 6]
        )

    w_1 = []
    for j in range(0, 64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j + 4]

    a, b, c, d, e, f, g, h = v_i

    for j in range(0, 64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) + e + (rotl(T_j[j], j % 32))) & 0xFFFFFFFF, 7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xFFFFFFFF
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xFFFFFFFF
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

        a, b, c, d, e, f, g, h = map(lambda x: x & 0xFFFFFFFF, [a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]


def sm3_hash_raw(msg):
    """原始SM3哈希计算函数"""
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7 - i])

    group_count = len(msg) // 64

    B = []
    for i in range(0, group_count):
        B.append(msg[i * 64 : (i + 1) * 64])

    V = []
    V.append(IV)
    for i in range(0, group_count):
        V.append(sm3_cf(V[i], B[i]))

    y = V[i + 1]
    result = ""
    for i in y:
        result = "%s%08x" % (result, i)
    return result


def sm3_kdf(z, klen):  # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen / 32)
    zin = [i for i in bytes.fromhex(z.decode("utf8"))]
    ha = ""
    for i in range(rcnt):
        msg = zin + [i for i in binascii.a2b_hex(("%08x" % ct).encode("utf8"))]
        ha = ha + sm3_hash_raw(msg)
        ct += 1
    return ha[0 : klen * 2]


class SM3Hash(HashBase):
    """SM3 哈希算法实现"""

    def __init__(self):
        """初始化SM3哈希对象"""
        self._buffer = bytearray()

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """
        更新哈希对象的状态

        Args:
            data: 要添加到哈希计算中的字节数据
        """
        # 将数据添加到缓冲区
        self._buffer.extend(data)

    def digest(self) -> bytes:
        """
        返回当前数据的二进制摘要

        Returns:
            bytes: 哈希摘要
        """
        # 计算哈希
        msg_list = bytes_to_list(self._buffer.copy())  # 复制，避免修改原始数据
        digest_hex = sm3_hash_raw(msg_list)
        return binascii.unhexlify(digest_hex)

    def hexdigest(self) -> str:
        """
        返回当前数据的十六进制摘要

        Returns:
            str: 十六进制格式的哈希摘要
        """
        # 计算哈希
        msg_list = bytes_to_list(self._buffer.copy())  # 复制，避免修改原始数据
        return sm3_hash_raw(msg_list)

    def copy(self) -> "SM3Hash":
        """
        返回哈希对象的副本

        Returns:
            SM3Hash: 当前哈希对象的副本
        """
        new_hash = SM3Hash()
        new_hash._buffer = bytearray(self._buffer)
        return new_hash

    def reset(self) -> None:
        """重置哈希对象的状态"""
        self._buffer = bytearray()


def sm3_hash(
    data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
) -> Union[bytes, SM3Hash]:
    """
    计算数据的SM3哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回哈希对象
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, SM3Hash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象
    """
    hash_obj = SM3Hash()
    if data is not None:
        return hash_obj.hash_data(data, encoding)
    return hash_obj


# 兼容性函数，与其他哈希算法保持一致的接口
def SM3(
    data: Optional[Union[str, bytes, bytearray]] = None, encoding: str = "utf-8"
) -> Union[bytes, SM3Hash]:
    """
    计算数据的SM3哈希值

    Args:
        data: 要计算哈希的数据, 如果为None则返回哈希对象
        encoding: 如果data是字符串, 指定编码方式

    Returns:
        Union[bytes, SM3Hash]: 如果提供了数据，返回哈希摘要；否则返回哈希对象
    """
    return sm3_hash(data, encoding)
