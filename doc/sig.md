# PyCryptoKit 数字签名模块

PyCryptoKit 的数字签名模块提供了一套完整的数字签名功能，支持多种主流签名算法，包括 RSA、ECDSA 和 EdDSA。本模块设计灵活，支持多种密钥格式和哈希算法，可以满足不同场景下的数字签名需求。

## 支持的签名算法

PyCryptoKit 支持以下数字签名算法：

| 算法 | 描述 | 默认参数 |
|------|------|----------|
| RSA_PKCS1v15 | RSA签名 (使用PKCS#1 v1.5填充) | 哈希算法: 可选，默认SHA256 |
| RSA_PSS | RSA-PSS签名 | 哈希算法: 可选，默认SHA256, 盐值长度: 默认32字节 |
| ECDSA | ECDSA签名 | 曲线: 可选，默认SECP256R1, 哈希算法: SHA256 |
| EdDSA | EdDSA签名 (Ed25519/Ed448) | 曲线: 可选，默认Ed25519 |

## 快速入门

### 基本使用

```python
from PyCryptoKit.core.signature import sign_data, verify_signature
from PyCryptoKit.core.asymmetric import generate_key_pair

# 使用非对称加密模块生成密钥对
private_key, public_key = generate_key_pair("RSA", key_size=2048)

# 签名数据
data = "Hello, PyCryptoKit!"
signature = sign_data(data, private_key, "RSA_PKCS1v15")

# 验证签名
is_valid = verify_signature(data, signature, public_key, "RSA_PKCS1v15")
print(f"签名验证结果: {is_valid}")  # 输出: 签名验证结果: True
```

### 使用不同算法

```python
from PyCryptoKit.core.asymmetric import generate_key_pair

# 使用 ECDSA
# 首先生成 ECDSA 密钥对
private_key, public_key = generate_key_pair("EC", curve="SECP256R1")
signature = sign_data(data, private_key, "ECDSA", hash_algorithm="SHA256")
is_valid = verify_signature(data, signature, public_key, "ECDSA")

# 使用 EdDSA (Ed25519)
# 首先生成 Ed25519 密钥对
private_key, public_key = generate_key_pair("ED25519")
signature = sign_data(data, private_key, "EdDSA")
is_valid = verify_signature(data, signature, public_key, "EdDSA")

# 使用 RSA-PSS
# 首先生成 RSA 密钥对
private_key, public_key = generate_key_pair("RSA", key_size=3072)
signature = sign_data(data, private_key, "RSA_PSS", hash_algorithm="SHA384", salt_length=48)
is_valid = verify_signature(data, signature, public_key, "RSA_PSS", hash_algorithm="SHA384", salt_length=48)
```

## 详细功能

### 创建签名算法实例

可以直接创建签名算法实例，以便进行更灵活的操作：

```python
from PyCryptoKit.core.signature import create_signature

# 创建 RSA-PKCS1v15 签名实例
rsa_sig = create_signature("RSA_PKCS1v15", hash_algorithm="SHA256")

# 创建 ECDSA 签名实例
ecdsa_sig = create_signature("ECDSA", curve="SECP384R1", hash_algorithm="SHA384")

# 创建 EdDSA 签名实例
eddsa_sig = create_signature("EdDSA", curve="Ed25519")
```

### 密钥管理

签名模块需要使用非对称加密模块生成的密钥对：

```python
from PyCryptoKit.core.asymmetric import generate_key_pair

# RSA 密钥生成
private_key, public_key = generate_key_pair("RSA", key_size=2048)

# ECDSA 密钥生成
private_key, public_key = generate_key_pair("EC", curve="SECP256K1")

# EdDSA 密钥生成
private_key, public_key = generate_key_pair("ED25519")  # Ed25519
# 或
private_key, public_key = generate_key_pair("ED448")    # Ed448
```

### 密钥格式支持

PyCryptoKit 支持多种密钥格式：

- **PEM**: 标准 PEM 格式
- **DER**: 二进制 DER 格式
- **OpenSSH**: OpenSSH 兼容格式
- **XML**: XML 格式（适用于与 .NET 等系统互操作）

```python
# 加载不同格式的密钥
from PyCryptoKit.core.signature import create_signature

rsa_sig = create_signature("RSA_PKCS1v15")

# 加载 PEM 格式密钥
private_key = rsa_sig.load_private_key("private_key.pem", password=b"your_password")
public_key = rsa_sig.load_public_key("public_key.pem")

# 加载 XML 格式密钥
private_key = rsa_sig.load_private_key("private_key.xml", format="XML")
public_key = rsa_sig.load_public_key("public_key.xml", format="XML")

# 自动检测格式
private_key = rsa_sig.load_private_key("private_key.key", format="Auto")
```

### 哈希算法支持

PyCryptoKit 支持多种哈希算法用于签名：

- MD5 (不推荐用于安全场景)
- SHA1 (不推荐用于安全场景)
- SHA224, SHA256, SHA384, SHA512
- SHA512_224, SHA512_256
- SHA3_224, SHA3_256, SHA3_384, SHA3_512
- SM3 (中国商用密码算法)

```python
# 使用不同的哈希算法
signature = sign_data(data, private_key, "RSA_PKCS1v15", hash_algorithm="SHA384")
```

### 高级功能

#### RSA-PSS 盐值长度设置

```python
# 设置 RSA-PSS 盐值长度
signature = sign_data(data, private_key, "RSA_PSS", salt_length=64)
is_valid = verify_signature(data, signature, public_key, "RSA_PSS", salt_length=64)
```

#### EdDSA 上下文设置

```python
# 设置 EdDSA 上下文 (RFC8032)
eddsa_sig = create_signature("EdDSA")
eddsa_sig.set_context(b"application-specific-context")
signature = eddsa_sig.sign(data, private_key)
is_valid = eddsa_sig.verify(data, signature, public_key)

# 或者在签名和验证时指定
signature = eddsa_sig.sign(data, private_key, context=b"application-specific-context")
is_valid = eddsa_sig.verify(data, signature, public_key, context=b"application-specific-context")
```

## 算法信息查询

PyCryptoKit 提供了一系列函数来查询支持的算法和参数：

```python
from PyCryptoKit.core.signature import list_algorithms, get_algorithm_info

# 列出所有支持的算法
algorithms = list_algorithms()
print(algorithms)  # ['RSA_PKCS1v15', 'RSA_PSS', 'ECDSA', 'EdDSA']

# 获取算法详细信息
info = get_algorithm_info("ECDSA")
print(info)
```

## 安全建议

1. **避免使用弱哈希算法**：不要在安全场景中使用 MD5 或 SHA1 哈希算法进行签名。
2. **密钥长度选择**：
   - RSA: 建议使用 2048 位或更长的密钥
   - ECDSA: 建议使用 P-256 (SECP256R1) 或更强的曲线
   - EdDSA: Ed25519 已经提供了足够的安全性
3. **密钥保护**：私钥应当妥善保管，可以使用密码加密存储。
4. **算法选择**：
   - 一般场景：ECDSA 或 EdDSA 因为它们的密钥较小且性能较好
   - 需要与传统系统兼容：RSA_PKCS1v15
   - 更高安全性：RSA_PSS 或 EdDSA

## 错误处理

PyCryptoKit 在遇到错误时会抛出具体的异常，建议使用 try-except 进行错误处理：

```python
try:
    signature = sign_data(data, private_key, "RSA_PKCS1v15")
    is_valid = verify_signature(data, signature, public_key, "RSA_PKCS1v15")
except ValueError as e:
    print(f"签名或验证过程中出现错误: {e}")
except Exception as e:
    print(f"发生未知错误: {e}")
```

## 性能考虑

不同签名算法的性能特性：

- **EdDSA**: 签名和验证速度最快，密钥最小
- **ECDSA**: 签名和验证速度较快，密钥较小
- **RSA**: 验证速度快但签名较慢，密钥较大

对于需要高性能的应用，建议选择 EdDSA 或 ECDSA。

## 扩展阅读

- [数字签名简介](https://en.wikipedia.org/wiki/Digital_signature)
- [NIST 数字签名标准](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [PKCS#1 v2.2 标准](https://tools.ietf.org/html/rfc8017)
- [EdDSA (RFC 8032)](https://tools.ietf.org/html/rfc8032)
- [RSA-PSS 签名方案](https://tools.ietf.org/html/rfc8017#section-8.1)
