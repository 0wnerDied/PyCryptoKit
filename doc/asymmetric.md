# PyCryptoKit 非对称加密模块

## 概述

非对称加密（也称为公钥加密）是一种使用一对密钥进行加密和解密的加密方式：公钥用于加密，私钥用于解密。PyCryptoKit 提供了多种非对称加密算法的实现，包括 RSA、ECC（椭圆曲线加密）、Edwards 曲线和 ElGamal 等。

## 主要特性

- 支持多种非对称加密算法（RSA、ECC、Edwards、ElGamal）
- 密钥对生成与管理
- 多种密钥格式支持（PEM、DER、OpenSSH、XML）
- 密钥导入导出功能
- 密钥加密保护（使用密码保护私钥）
- 工厂模式设计，易于扩展

## 基本用法

### 创建密钥对

使用 `AsymmetricCipherFactory` 可以轻松创建不同算法的密钥对：

```python
from PyCryptoKit.core.asymmetric.factory import AsymmetricCipherFactory

# 创建 RSA 密钥对（默认 2048 位）
key_pair = AsymmetricCipherFactory.create_key_pair(algorithm="RSA", key_size=2048)

# 创建 ECC 密钥对（默认使用 SECP256R1 曲线）
ecc_key_pair = AsymmetricCipherFactory.create_key_pair(algorithm="ECC", curve="SECP256R1")

# 创建 Edwards 曲线密钥对
ed_key_pair = AsymmetricCipherFactory.create_key_pair(algorithm="Edwards", curve="Ed25519")

# 创建 ElGamal 密钥对
elgamal_key_pair = AsymmetricCipherFactory.create_key_pair(algorithm="ElGamal", key_size=2048)
```

### 保存密钥对

可以将生成的密钥对保存到文件中：

```python
# 保存密钥对到文件
AsymmetricCipherFactory.save_key_pair_to_files(
    key_pair,
    private_key_path="private_key.pem",
    public_key_path="public_key.pem",
    format="pem",
    password=b"your_password"  # 可选，用于加密私钥
)
```

## 支持的算法

### RSA

RSA（Rivest-Shamir-Adleman）是最广泛使用的非对称加密算法之一。它基于大整数分解的困难性。

#### 特性

- 支持多种密钥大小：1024, 2048, 3072, 4096, 8192 位
- 适用于加密和数字签名
- 支持大数据分块加密

#### 示例

```python
from PyCryptoKit.core.asymmetric.factory import AsymmetricCipherFactory

# 创建 RSA 密钥对
key_pair = AsymmetricCipherFactory.create_key_pair(
    algorithm="RSA", 
    key_size=2048,
    public_exponent=65537  # 可选参数
)

# 保存密钥
key_pair.save_to_files(
    private_key_path="rsa_private.pem",
    public_key_path="rsa_public.pem"
)

# 转换为不同格式
pem_data = key_pair.public_key.to_pem()
der_data = key_pair.public_key.to_der()
openssh_data = key_pair.public_key.to_openssh()
xml_data = key_pair.public_key.to_xml()
```

### ECC（椭圆曲线加密）

ECC 使用椭圆曲线数学来提供同等安全性但密钥尺寸更小的加密方案。

#### 特性

- 支持多种标准曲线：SECP256R1（默认）、SECP384R1、SECP521R1 等
- 密钥尺寸小，性能高
- 适用于资源受限环境

#### 支持的曲线

- SECP192R1, SECP224R1, SECP256R1, SECP384R1, SECP521R1
- SECP256K1（比特币使用的曲线）
- SECT163K1, SECT233K1, SECT283K1, SECT409K1, SECT571K1
- SECT163R2, SECT233R1, SECT283R1, SECT409R1, SECT571R1
- BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1

#### 示例

```python
from PyCryptoKit.core.asymmetric.factory import AsymmetricCipherFactory

# 创建 ECC 密钥对
ecc_key_pair = AsymmetricCipherFactory.create_key_pair(
    algorithm="ECC", 
    curve="SECP256R1"  # 指定曲线
)

# 保存密钥
ecc_key_pair.save_to_files(
    private_key_path="ecc_private.pem",
    public_key_path="ecc_public.pem"
)
```

### Edwards 曲线

Edwards 曲线是一种特殊形式的椭圆曲线，在数字签名算法中特别有用（如 Ed25519）。

#### 特性

- 支持 Ed25519 等现代曲线
- 高性能，适用于数字签名
- 更强的安全保证

#### 示例

```python
from PyCryptoKit.core.asymmetric.factory import AsymmetricCipherFactory

# 创建 Edwards 曲线密钥对
ed_key_pair = AsymmetricCipherFactory.create_key_pair(
    algorithm="Edwards", 
    curve="Ed25519"
)

# 保存密钥
ed_key_pair.save_to_files(
    private_key_path="ed25519_private.pem",
    public_key_path="ed25519_public.pem"
)
```

### ElGamal

ElGamal 是基于离散对数问题的非对称加密算法，通常用于加密而非数字签名。

#### 特性

- 基于离散对数问题
- 支持多种密钥大小
- 适用于加密场景

#### 示例

```python
from PyCryptoKit.core.asymmetric.factory import AsymmetricCipherFactory

# 创建 ElGamal 密钥对
elgamal_key_pair = AsymmetricCipherFactory.create_key_pair(
    algorithm="ElGamal", 
    key_size=2048
)

# 保存密钥
elgamal_key_pair.save_to_files(
    private_key_path="elgamal_private.pem",
    public_key_path="elgamal_public.pem"
)
```

## 密钥格式

PyCryptoKit 支持多种密钥格式：

1. **PEM 格式**：带有头部和尾部标记，最常用的格式
2. **DER 格式**：二进制格式，适用于程序间传输
3. **OpenSSH 格式**：用于 SSH 认证的格式
4. **XML 格式**：适用于与 .NET 等平台交互

示例：

```python
# 转换为不同格式
pem_data = key_pair.public_key.to_pem()
der_data = key_pair.public_key.to_der()
openssh_data = key_pair.public_key.to_openssh()
xml_data = key_pair.public_key.to_xml()

# 保存为特定格式
key_pair.public_key.save_to_file("public_key.pem", format="pem")
key_pair.public_key.save_to_file("public_key.der", format="der")
key_pair.public_key.save_to_file("public_key.openssh", format="openssh")
key_pair.public_key.save_to_file("public_key.xml", format="xml")
```

## 高级用法

### 使用密码保护私钥

```python
# 创建密钥对时指定密码
key_pair = AsymmetricCipherFactory.create_key_pair(
    algorithm="RSA", 
    key_size=2048,
    password=b"your_secure_password"
)

# 保存时指定密码
key_pair.save_to_files(
    private_key_path="private_key.pem",
    public_key_path="public_key.pem",
    password=b"your_secure_password"
)
```

### 查询支持的算法和密钥大小

```python
# 列出所有支持的算法
algorithms = AsymmetricCipherFactory.list_algorithms()
print(f"支持的算法: {algorithms}")

# 获取特定算法支持的密钥大小
rsa_key_sizes = AsymmetricCipherFactory.get_supported_key_sizes("RSA")
print(f"RSA 支持的密钥大小: {rsa_key_sizes}")

# 获取 ECC 支持的曲线
from PyCryptoKit.core.asymmetric.ecc import ECC
ecc_curves = ECC.supported_curves()
print(f"支持的 ECC 曲线: {ecc_curves}")
```

## 最佳实践

1. **选择合适的算法和密钥大小**：
   - 一般场景：RSA 2048 位或 ECC SECP256R1
   - 高安全性要求：RSA 4096 位或 ECC SECP384R1/SECP521R1
   - 资源受限环境：ECC 或 Edwards 曲线

2. **私钥保护**：
   - 始终使用密码保护私钥
   - 限制私钥文件的访问权限
   - 考虑使用硬件安全模块存储私钥

3. **密钥管理**：
   - 实施密钥轮换策略
   - 保留密钥备份
   - 建立密钥撤销机制

4. **格式选择**：
   - 一般使用 PEM 格式，最广泛支持
   - 与特定系统集成时选择合适的格式（如与 .NET 集成使用 XML）

## 注意事项

1. RSA 加密有消息大小限制，与密钥大小相关
2. 非对称加密计算开销大，不适合直接加密大量数据
3. 实际应用中通常结合对称加密使用（混合加密）
4. 密钥大小与安全性和性能成反比，需根据场景平衡选择

## 错误处理

PyCryptoKit 的非对称加密模块使用异常来处理错误情况：

```python
try:
    key_pair = AsymmetricCipherFactory.create_key_pair(algorithm="RSA", key_size=2048)
    # 使用密钥对...
except ValueError as e:
    print(f"密钥生成错误: {e}")
except Exception as e:
    print(f"未知错误: {e}")
```

常见错误包括：
- 不支持的算法或参数
- 密钥格式错误
- 密码不正确
- 文件访问权限问题

## 扩展阅读

- [RSA 算法原理](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [椭圆曲线加密简介](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
- [NIST 密钥管理指南](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [XML 格式密钥示例](https://www.w3.org/TR/xmlenc-core1/#sec-XML-Encryption-Data-Types)
