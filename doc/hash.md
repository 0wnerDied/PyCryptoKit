# PyCryptoKit 哈希模块

## 概述

哈希算法（也称为摘要算法）是一种将任意长度的数据映射为固定长度输出的单向函数。哈希函数广泛应用于数据完整性校验、密码存储、数字签名等场景。PyCryptoKit 哈希模块提供了多种哈希算法的统一接口，支持各种常见的哈希算法，包括传统算法、现代安全算法以及国密算法。

## 主要特性

- **统一接口**：所有哈希算法实现相同的接口，便于替换和使用
- **丰富的算法支持**：包括 MD5、SHA 系列、SHA-3 系列、BLAKE 系列以及中国国密标准 SM3
- **安全性标识**：明确标识哪些算法是安全的，哪些仅用于兼容性目的
- **易于使用**：提供简单直观的 API，支持链式调用
- **灵活的输入格式**：支持字符串、字节、文件等多种输入形式
- **工厂模式设计**：使用工厂类创建哈希实例，易于扩展

## 基本用法

### 创建哈希对象

使用 `create_hash` 函数可以轻松创建不同算法的哈希对象：

```python
from PyCryptoKit.core.hash import create_hash

# 创建 SHA-256 哈希对象
hash_obj = create_hash("SHA-256")

# 创建 BLAKE2b 哈希对象，指定摘要大小
blake2b = create_hash("BLAKE2b", digest_size=32)

# 创建 SHA3-256 哈希对象
sha3 = create_hash("SHA3-256")
```

### 计算数据哈希值

```python
# 更新数据
hash_obj.update("Hello, ")
hash_obj.update("World!")

# 获取摘要
digest = hash_obj.digest()  # 二进制摘要
hex_digest = hash_obj.hexdigest()  # 十六进制摘要

print(f"SHA-256 摘要: {hex_digest}")

# 链式调用
hex_digest = create_hash("SHA-256").update("Hello, World!").hexdigest()
print(f"SHA-256 摘要: {hex_digest}")
```

### 计算文件哈希值

```python
# 计算文件的哈希值
hash_obj = create_hash("SHA-256")
digest = hash_obj.hash_file("example.txt")
hex_digest = digest.hex()

print(f"文件 SHA-256 摘要: {hex_digest}")
```

## 支持的算法

PyCryptoKit 哈希模块支持多种哈希算法，按安全性和用途分类：

### 传统算法（不安全，仅用于兼容）

- **MD5**：128 位摘要，已知存在碰撞攻击
- **SHA-1**：160 位摘要，已被证明不安全，存在实际可行的碰撞攻击

### SHA-2 系列（安全）

- **SHA-224**：224 位摘要，SHA-256 的截断版本
- **SHA-256**：256 位摘要，最广泛使用的安全哈希算法
- **SHA-384**：384 位摘要，SHA-512 的截断版本
- **SHA-512**：512 位摘要，SHA-2 家族中最安全的标准算法
- **SHA-512/224**：224 位摘要，基于 SHA-512 的变种，使用不同的初始值并截断到 224 位
- **SHA-512/256**：256 位摘要，基于 SHA-512 的变种，在 64 位系统上比 SHA-256 更高效

### SHA-3 系列（安全）

- **SHA3-224**：224 位摘要，基于 Keccak 海绵函数构造
- **SHA3-256**：256 位摘要，提供与 SHA-256 相当的安全性，但结构完全不同
- **SHA3-384**：384 位摘要，提供高安全性
- **SHA3-512**：512 位摘要，SHA-3 标准中最安全的固定长度输出算法

### 可扩展输出函数（XOF）

- **SHAKE128**：可变长度输出，安全强度 128 位
- **SHAKE256**：可变长度输出，安全强度 256 位，提供更高安全性

### BLAKE 系列（高性能安全算法）

- **BLAKE2b**：针对 64 位平台优化，支持 1-64 字节输出，比 MD5 速度更快且安全
- **BLAKE2s**：针对 32 位平台优化，支持 1-32 字节输出，适用于资源受限环境
- **BLAKE3**：现代高性能并行哈希算法，支持无限输出长度、密钥派生和内容寻址

### 国密算法

- **SM3**：中国国家密码管理局发布的密码杂凑算法标准，256 位输出

## 算法特性

### BLAKE2b

#### 特性
- 支持 1-64 字节输出
- 针对 64 位平台优化
- 可选密钥支持（密钥派生）
- 高性能，比 MD5 更快且安全

#### 示例
```python
from PyCryptoKit.core.hash import create_hash

# 创建 BLAKE2b 哈希对象，指定摘要大小
blake2b = create_hash("BLAKE2b", digest_size=32)
blake2b.update("Hello, World!")
hex_digest = blake2b.hexdigest()

print(f"BLAKE2b-256 摘要: {hex_digest}")
```

### SHA-3 系列

#### 特性
- 基于 Keccak 海绵函数构造
- NIST 标准化的新一代哈希函数
- 抗量子计算攻击
- 包含固定长度输出和可变长度输出变体

#### 示例
```python
from PyCryptoKit.core.hash import create_hash

# 创建 SHA3-256 哈希对象
sha3 = create_hash("SHA3-256")
sha3.update("Hello, World!")
hex_digest = sha3.hexdigest()

print(f"SHA3-256 摘要: {hex_digest}")

# 使用 SHAKE256 可扩展输出函数
shake = create_hash("SHAKE256")
shake.update("Hello, World!")
digest_32 = shake.digest(32)  # 32字节 (256位) 输出
digest_64 = shake.digest(64)  # 64字节 (512位) 输出

print(f"SHAKE256-256: {digest_32.hex()}")
print(f"SHAKE256-512: {digest_64.hex()}")
```

### SM3 国密算法

#### 特性
- 中国国家密码管理局发布的标准
- 256 位输出
- 性能与 SHA-256 相当
- 用于数字签名和验证、消息认证

#### 示例
```python
from PyCryptoKit.core.hash import create_hash

# 创建 SM3 哈希对象
sm3 = create_hash("SM3")
sm3.update("Hello, World!")
hex_digest = sm3.hexdigest()

print(f"SM3 摘要: {hex_digest}")
```

## 高级用法

### 使用 SHAKE 可扩展输出函数

```python
from PyCryptoKit.core.hash import create_hash

# 创建 SHAKE256 对象
shake = create_hash("SHAKE256")
shake.update("Hello, World!")

# 获取不同长度的输出
digest_16 = shake.digest(16)  # 16字节 (128位) 输出
digest_32 = shake.digest(32)  # 32字节 (256位) 输出
digest_64 = shake.digest(64)  # 64字节 (512位) 输出

print(f"SHAKE256-128: {digest_16.hex()}")
print(f"SHAKE256-256: {digest_32.hex()}")
print(f"SHAKE256-512: {digest_64.hex()}")
```

### 复制哈希对象状态

```python
from PyCryptoKit.core.hash import create_hash

# 创建并更新哈希对象
hash_obj = create_hash("SHA-256")
hash_obj.update("Hello, ")

# 复制当前状态
hash_copy = hash_obj.copy()

# 两个对象可以独立更新
hash_obj.update("World!")
hash_copy.update("PyCryptoKit!")

print(f"原始对象摘要: {hash_obj.hexdigest()}")
print(f"复制对象摘要: {hash_copy.hexdigest()}")
```

### 重置哈希对象

```python
from PyCryptoKit.core.hash import create_hash

# 创建并更新哈希对象
hash_obj = create_hash("SHA-256")
hash_obj.update("Hello, World!")
print(f"第一次摘要: {hash_obj.hexdigest()}")

# 重置对象状态
hash_obj.reset()
hash_obj.update("Hello, PyCryptoKit!")
print(f"重置后摘要: {hash_obj.hexdigest()}")
```

### 查询支持的算法

```python
from PyCryptoKit.core.hash import list_algorithms, get_algorithm_info

# 列出所有支持的算法
all_algorithms = list_algorithms()
print(f"支持的所有算法: {', '.join(all_algorithms)}")

# 仅列出安全的算法
secure_algorithms = list_algorithms(secure_only=True)
print(f"安全的算法: {', '.join(secure_algorithms)}")

# 获取特定算法的详细信息
info = get_algorithm_info("SHA-256")
print(f"算法名称: {info['name']}")
print(f"算法类: {info['class']}")
print(f"是否安全: {info['secure']}")
print(f"描述: {info['description']}")
```

## 最佳实践

1. **选择合适的算法**：
   - 一般场景：SHA-256 或 BLAKE2b
   - 高安全性要求：SHA-512、SHA3-256 或 SHA3-512
   - 高性能需求：BLAKE2b 或 BLAKE3
   - 资源受限环境：SHA-256 或 BLAKE2s
   - 国密合规场景：SM3

2. **安全性考虑**：
   - 避免使用 MD5 和 SHA-1，它们已被证明不安全
   - 对于安全敏感的应用，使用 SHA-256 及以上强度的算法
   - 考虑使用 SHA-3 系列算法以防御量子计算攻击

3. **性能优化**：
   - 对于大量数据处理，考虑使用 BLAKE2 或 BLAKE3
   - 在 64 位系统上，SHA-512 可能比 SHA-256 更快
   - 对于流式处理，使用 update() 方法分批处理数据

4. **数据验证**：
   - 存储哈希值时同时记录使用的算法
   - 考虑使用 HMAC 而不是纯哈希来防止长度扩展攻击

## 性能比较

不同的哈希算法在性能上有显著差异。以下是各算法在处理大量数据时的相对性能比较（数值越大表示性能越好）：

| 算法 | 相对性能 | 备注 |
|------|--------|------|
| MD5 | 高 | 不安全，仅用于参考 |
| SHA-1 | 中高 | 不安全，仅用于参考 |
| SHA-256 | 中 | 在 32 位系统上表现良好 |
| SHA-512 | 中高 | 在 64 位系统上比 SHA-256 更快 |
| SHA3-256 | 中 | 比 SHA-256 略慢 |
| BLAKE2b | 高 | 在 64 位系统上非常快 |
| BLAKE2s | 高 | 在 32 位系统上非常快 |
| BLAKE3 | 极高 | 支持并行计算，速度最快 |
| SM3 | 中 | 性能与 SHA-256 相当 |

对于大多数应用，BLAKE2 和 BLAKE3 提供了最佳的安全性和性能平衡。

## 错误处理

PyCryptoKit 的哈希模块使用异常来处理错误情况：

```python
from PyCryptoKit.core.hash import create_hash

try:
    # 尝试使用不存在的算法
    hash_obj = create_hash("UNKNOWN-ALGORITHM")
except ValueError as e:
    print(f"错误: {e}")

try:
    # 尝试计算不存在文件的哈希值
    hash_obj = create_hash("SHA-256")
    hash_obj.hash_file("non_existent_file.txt")
except FileNotFoundError as e:
    print(f"错误: {e}")
```

常见错误包括：
- `ValueError`：参数值无效，如不支持的算法名称或无效的摘要大小
- `TypeError`：参数类型错误，如传递了不支持的数据类型
- `FileNotFoundError`：计算文件哈希时文件不存在
- `IOError`：读取文件时发生 I/O 错误

## 注意事项

1. 哈希算法不适用于密码存储，应使用专门的密码哈希函数（如 Argon2、bcrypt）
2. 哈希值不能用于保证数据机密性，仅用于完整性验证
3. 对于防篡改应用，考虑使用 HMAC 或数字签名而非纯哈希
4. 安全敏感应用应避免使用 MD5 和 SHA-1

## 扩展阅读

- [哈希函数简介](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [SHA-3 标准](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [BLAKE2 算法规范](https://www.blake2.net/blake2.pdf)
- [BLAKE3 官方文档](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [SM3 国密算法标准](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf)
