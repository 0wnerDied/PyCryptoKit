"""国密SM3哈希算法实现"""

from typing import Union, Optional
import binascii
from math import ceil
from .base import HashBase

# 常量定义
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
T_j = [2043430169] * 16 + [2055708042] * 48


def rotl(x, n):
    n %= 32  # 确保移位数在有效范围内
    return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)


def sm3_ff_j(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def sm3_gg_j(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x) & z))


def sm3_p_0(x):
    return x ^ rotl(x, 9) ^ rotl(x, 17)


def sm3_p_1(x):
    return x ^ rotl(x, 15) ^ rotl(x, 23)


def sm3_cf(v_i, b_i):
    w = [0] * 68
    for i in range(16):
        w[i] = int.from_bytes(b_i[i * 4 : (i + 1) * 4], byteorder="big")

    for j in range(16, 68):
        w[j] = (
            sm3_p_1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15))
            ^ rotl(w[j - 13], 7)
            ^ w[j - 6]
        )

    w_1 = [w[j] ^ w[j + 4] for j in range(64)]

    a, b, c, d, e, f, g, h = v_i

    for j in range(64):
        ss_1 = rotl((rotl(a, 12) + e + rotl(T_j[j], j % 32)) & 0xFFFFFFFF, 7)
        ss_2 = ss_1 ^ rotl(a, 12)
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xFFFFFFFF
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xFFFFFFFF
        d, c, b, a = c, rotl(b, 9), a, tt_1
        h, g, f, e = g, rotl(f, 19), e, sm3_p_0(tt_2)

    return [
        (v_j & 0xFFFFFFFF) ^ v_i[i] for i, v_j in enumerate([a, b, c, d, e, f, g, h])
    ]


def sm3_hash_raw(msg):
    # 填充
    msg_len = len(msg)
    msg = bytearray(msg)
    msg.append(0x80)

    # 补齐长度
    padding_len = 56 - (len(msg) % 64)
    if padding_len <= 0:
        padding_len += 64
    msg.extend([0] * padding_len)

    # 添加消息长度（比特）
    bit_length = msg_len * 8
    msg.extend(bit_length.to_bytes(8, byteorder="big"))

    # 分组处理
    group_count = len(msg) // 64
    v = [IV]

    for i in range(group_count):
        v.append(sm3_cf(v[i], msg[i * 64 : (i + 1) * 64]))

    return "".join(f"{i:08x}" for i in v[-1])


class SM3Hash(HashBase):
    """SM3哈希算法实现"""

    name = "sm3"
    digest_size = 32
    block_size = 64

    def __init__(self):
        self._buffer = bytearray()

    def update(self, data):
        if isinstance(data, (bytes, bytearray, memoryview)):
            self._buffer.extend(data)
        else:
            raise TypeError(f"不支持的数据类型: {type(data).__name__}")
        return self

    def digest(self):
        return binascii.unhexlify(self.hexdigest())

    def hexdigest(self):
        return sm3_hash_raw(self._buffer.copy())

    def copy(self):
        new_hash = SM3Hash()
        new_hash._buffer = bytearray(self._buffer)
        return new_hash

    def reset(self):
        self._buffer = bytearray()

    def hash_data(self, data, encoding="utf-8"):
        self.reset()
        if isinstance(data, str):
            data = data.encode(encoding)
        self.update(data)
        return self.digest()

    def hash_file(self, filename):
        self.reset()
        with open(filename, "rb") as f:
            chunk_size = 8192  # 8KB
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                self.update(chunk)
        return self.digest()


def SM3(data=None, encoding="utf-8"):
    """计算数据的SM3哈希值"""
    hash_obj = SM3Hash()
    if data is None:
        return hash_obj
    return hash_obj.hash_data(data, encoding)
