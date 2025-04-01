# PyCryptoKit 对称加密模块

## 概述

对称加密是一种使用相同密钥进行加密和解密的加密方式。PyCryptoKit 提供了多种对称加密算法的实现，包括 AES、SM4、ChaCha20 和 Salsa20 等，并支持多种加密模式和填充方式。

## 主要特性

- 支持多种对称加密算法（AES、SM4、ChaCha20、Salsa20）
- 支持多种加密模式（ECB、CBC、CFB、OFB、CTR、GCM）
- 支持多种填充方式（PKCS7、ZERO、NONE）
- 提供简单易用的 API 接口
- 支持字符串和二进制数据输入
- 内置 Base64 编码支持
- 工厂模式设计，易于扩展

## 基本用法

### 简单加密/解密

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt, Algorithm, Mode, Padding

# 简单加密
ciphertext = encrypt(
    algorithm=Algorithm.AES,  # 或使用字符串 "AES"
    plaintext="Hello, World!",
    key="my-secret-key",
    mode=Mode.CBC,  # 默认为 CBC 模式
    padding=Padding.PKCS7  # 默认为 PKCS7 填充
)

# 解密
plaintext = decrypt(
    algorithm=Algorithm.AES,
    ciphertext=ciphertext,
    key="my-secret-key",
    mode=Mode.CBC,
    padding=Padding.PKCS7
)
```

### Base64 编码加密/解密

```python
from PyCryptoKit.core.symmetric import encrypt_to_base64, decrypt_from_base64

# 加密并转为 Base64 字符串
ciphertext_b64 = encrypt_to_base64(
    algorithm="AES",
    plaintext="Hello, World!",
    key="my-secret-key"
)

# 从 Base64 字符串解密
plaintext = decrypt_from_base64(
    algorithm="AES",
    ciphertext_b64=ciphertext_b64,
    key="my-secret-key"
)
```

## 支持的算法

### AES

高级加密标准（Advanced Encryption Standard）是目前最广泛使用的对称加密算法。

#### 特性

- 支持多种密钥长度：128、192、256 位
- 支持所有常用加密模式
- 高安全性和良好的性能平衡
- 广泛的兼容性

#### 示例

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt, Mode, Padding

# AES-256-CBC 加密
ciphertext = encrypt(
    algorithm="AES",
    plaintext="Secret message",
    key="32-byte-key-for-aes-256-encryption",
    mode=Mode.CBC,
    padding=Padding.PKCS7
)

# AES-256-CBC 解密
plaintext = decrypt(
    algorithm="AES",
    ciphertext=ciphertext,
    key="32-byte-key-for-aes-256-encryption",
    mode=Mode.CBC,
    padding=Padding.PKCS7
)
```

### SM4

SM4 是中国国家密码管理局发布的分组密码标准，用于替代 DES 和 AES。

#### 特性

- 固定 128 位密钥长度
- 支持所有常用加密模式
- 符合中国密码标准
- 适用于需要符合国家标准的场景

#### 示例

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt

# SM4-CBC 加密
ciphertext = encrypt(
    algorithm="SM4",
    plaintext="Secret message",
    key="16-byte-key-for-sm4",
    iv="16-byte-iv-for-sm4"  # 除 ECB 模式外需要 IV
)

# SM4-CBC 解密
plaintext = decrypt(
    algorithm="SM4",
    ciphertext=ciphertext,
    key="16-byte-key-for-sm4",
    iv="16-byte-iv-for-sm4"
)
```

### ChaCha20

ChaCha20 是一种高速流加密算法，由 Daniel J. Bernstein 设计，是 Salsa20 的改进版本。

#### 特性

- 256 位密钥（32 字节）
- 高性能，适用于软件实现
- 无需填充
- 适用于资源受限环境

#### 示例

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt
import os

# 生成随机 nonce
nonce = os.urandom(12)

# ChaCha20 加密
ciphertext = encrypt(
    algorithm="ChaCha20",
    plaintext="Secret message",
    key="32-byte-key-for-chacha20-algorithm",
    nonce=nonce,
    counter=0  # 可选，默认为 0
)

# ChaCha20 解密
plaintext = decrypt(
    algorithm="ChaCha20",
    ciphertext=ciphertext,
    key="32-byte-key-for-chacha20-algorithm",
    nonce=nonce,
    counter=0  # 必须与加密时相同
)
```

### Salsa20

Salsa20 是一种流加密算法，由 Daniel J. Bernstein 设计，是 ChaCha20 的前身。

#### 特性

- 支持 128 位和 256 位密钥
- 简单、高效的设计
- 无需填充
- 适用于高性能需求场景

#### 示例

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt
import os

# 生成随机 nonce
nonce = os.urandom(8)

# Salsa20 加密
ciphertext = encrypt(
    algorithm="Salsa20",
    plaintext="Secret message",
    key="32-byte-key-for-salsa20-algorithm",
    nonce=nonce
)

# Salsa20 解密
plaintext = decrypt(
    algorithm="Salsa20",
    ciphertext=ciphertext,
    key="32-byte-key-for-salsa20-algorithm",
    nonce=nonce
)
```

## 加密模式

PyCryptoKit 支持多种加密模式，适用于不同的安全需求和场景：

### ECB（电子密码本模式）

- 最简单的加密模式，不需要 IV
- 相同的明文块会加密为相同的密文块
- 不推荐用于加密大于一个块的数据
- 适用场景：加密单个块的数据，如密钥

### CBC（密码块链接模式）

- 每个明文块与前一个密文块进行 XOR 操作
- 需要初始向量（IV）
- 提供良好的保密性
- 适用场景：一般数据加密

### CFB（密码反馈模式）

- 将块密码转换为流密码
- 需要初始向量（IV）
- 支持实时加密
- 适用场景：需要实时处理的数据流

### OFB（输出反馈模式）

- 生成密钥流，与明文进行 XOR 操作
- 需要初始向量（IV）
- 加密错误不会传播
- 适用场景：噪声信道传输

### CTR（计数器模式）

- 将块密码转换为流密码
- 使用递增的计数器生成密钥流
- 支持并行处理
- 适用场景：高性能需求

### GCM（伽罗瓦/计数器模式）

- 结合 CTR 模式和认证
- 提供数据加密和完整性验证
- 支持额外的认证数据（AAD）
- 适用场景：需要认证的加密通信

## 填充方式

对于需要填充的加密模式和算法，PyCryptoKit 支持以下填充方式：

### PKCS7

- 标准填充方式
- 填充值为填充字节数
- 适用于大多数场景

### ZERO

- 使用零字节进行填充
- 适用于二进制数据
- 可能不适合末尾有零字节的数据

### NONE

- 不进行填充
- 要求数据长度是块大小的整数倍
- 适用于已知长度的数据

## 高级用法

### AES-GCM 模式（带认证标签）

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt, Mode

# 使用 GCM 模式加密（带关联数据）
ciphertext = encrypt(
    algorithm="AES",
    plaintext="Secret message",
    key="my-secret-key",
    mode=Mode.GCM,
    associated_data="Additional authenticated data"  # 可选的关联数据
)

# GCM 模式解密（需要验证）
plaintext = decrypt(
    algorithm="AES",
    ciphertext=ciphertext,
    key="my-secret-key",
    mode=Mode.GCM,
    associated_data="Additional authenticated data"  # 必须与加密时相同
)
```

### 使用工厂模式创建加密器

```python
from PyCryptoKit.core.symmetric.factory import SymmetricFactory
from PyCryptoKit.core.symmetric.base import Algorithm, Mode, Padding

# 创建 AES 加密器
cipher = SymmetricFactory.create_cipher(
    algorithm=Algorithm.AES,
    key_size=256,
    mode=Mode.CBC,
    padding=Padding.PKCS7
)

# 使用创建的加密器进行加密
ciphertext = cipher.encrypt(
    plaintext="Secret message",
    key="my-secret-key",
    iv="initialization-vector"
)

# 解密
plaintext = cipher.decrypt(
    ciphertext=ciphertext,
    key="my-secret-key",
    iv="initialization-vector"
)
```

### 处理二进制数据

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt
import os

# 生成随机密钥和 IV
key = os.urandom(32)  # 256 位密钥
iv = os.urandom(16)   # 128 位 IV

# 加密二进制数据
binary_data = b'\x01\x02\x03\x04\x05\x06\x07\x08'
ciphertext = encrypt(
    algorithm="AES",
    plaintext=binary_data,
    key=key,
    iv=iv
)

# 解密二进制数据
plaintext = decrypt(
    algorithm="AES",
    ciphertext=ciphertext,
    key=key,
    iv=iv
)
```

## 最佳实践

1. **选择合适的算法和模式**：
   - 一般场景：AES-256-CBC 或 AES-256-GCM
   - 高性能需求：ChaCha20
   - 需要认证：AES-GCM
   - 符合国密标准：SM4

2. **密钥管理**：
   - 使用足够长的随机密钥
   - 安全存储密钥，避免硬编码
   - 定期轮换密钥
   - 考虑使用密钥派生函数（KDF）从密码生成密钥

3. **IV/Nonce 处理**：
   - 每次加密使用不同的随机 IV/Nonce
   - 不要重用 IV/Nonce，特别是对于流密码
   - 对于 GCM 模式，Nonce 长度应为 12 字节

4. **数据完整性**：
   - 对于需要完整性验证的场景，使用 GCM 模式
   - 或者结合 HMAC 使用其他模式

## 注意事项

1. ECB 模式不适合加密大于一个块的数据
2. GCM 模式的 Nonce 不应重用，否则会严重损害安全性
3. 对于流密码（ChaCha20、Salsa20），密钥和 Nonce 的组合不应重用
4. 密钥长度与安全性成正比，但也会影响性能

## 错误处理

PyCryptoKit 的对称加密模块使用异常来处理错误情况：

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt

try:
    ciphertext = encrypt(
        algorithm="AES",
        plaintext="Secret message",
        key="my-secret-key"
    )
    plaintext = decrypt(
        algorithm="AES",
        ciphertext=ciphertext,
        key="my-secret-key"
    )
except ValueError as e:
    print(f"参数错误: {e}")
except TypeError as e:
    print(f"类型错误: {e}")
except RuntimeError as e:
    print(f"运行时错误: {e}")
```

常见错误包括：
- 不支持的算法或模式
- 密钥长度不正确
- IV/Nonce 缺失或长度不正确
- GCM 模式认证失败
- 填充错误

## 示例场景

### 安全存储敏感配置

```python
from PyCryptoKit.core.symmetric import encrypt_to_base64, decrypt_from_base64
import json

# 敏感配置
config = {
    "api_key": "secret-api-key",
    "password": "super-secret-password",
    "database": "production-db"
}

# 加密配置
encrypted_config = encrypt_to_base64(
    algorithm="AES",
    plaintext=json.dumps(config),
    key="master-encryption-key"
)

# 保存到文件
with open("config.enc", "w") as f:
    f.write(encrypted_config)

# 读取并解密
with open("config.enc", "r") as f:
    encrypted_data = f.read()

decrypted_config = decrypt_from_base64(
    algorithm="AES",
    ciphertext_b64=encrypted_data,
    key="master-encryption-key"
)

config = json.loads(decrypted_config)
```

### 安全通信

```python
from PyCryptoKit.core.symmetric import encrypt, decrypt, Mode
import os

# 发送方
def encrypt_message(message, shared_key):
    # 使用 GCM 模式进行加密和认证
    encrypted_data = encrypt(
        algorithm="AES",
        plaintext=message,
        key=shared_key,
        mode=Mode.GCM,
        associated_data="sender-id:12345"  # 可以包含元数据
    )
    return encrypted_data

# 接收方
def decrypt_message(encrypted_data, shared_key):
    try:
        decrypted_data = decrypt(
            algorithm="AES",
            ciphertext=encrypted_data,
            key=shared_key,
            mode=Mode.GCM,
            associated_data="sender-id:12345"  # 必须匹配
        )
        return decrypted_data, True
    except ValueError:
        # 认证失败或密钥错误
        return None, False
```

## 扩展阅读

- [NIST 密码学标准](https://csrc.nist.gov/publications/fips)
- [AES 算法详解](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [加密模式介绍](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [ChaCha20 和 Salsa20 流密码](https://en.wikipedia.org/wiki/Salsa20)
