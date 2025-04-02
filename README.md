# PyCryptoKit - 密码学图形工具箱

## 项目概述

PyCryptoKit 是一个基于 Python 开发的密码学图形工具箱，为用户提供直观的图形界面来执行各种密码学操作。本工具箱集成了常见的加密、解密、哈希计算和数字签名等功能，适用于教学演示、安全研究和日常加密需求。

> 本项目为中国民航大学 2023 级信息安全专业密码学课程设计  
> 作者：[github@0wnerDied](https://github.com/0wnerDied)

## 功能特点

- **用户友好的图形界面**：简洁直观的界面设计，无需命令行经验
- **多种哈希算法**：支持 MD5、SHA系列、SHA3系列、BLAKE系列、SM3 等
- **对称加密工具**：AES、ChaCha20、Salsa20、SM4 等算法的加密/解密操作
- **非对称加密工具**：RSA、ECC、ElGamal、Edwards 等公钥密码系统
- **数字签名验证**：支持 RSA 签名、ECDSA 签名、EdDSA 签名等
- **文件操作支持**：可直接处理文件的加密、解密和哈希计算
- **结果可视化**：清晰展示加密/解密结果，支持复制和保存

## 系统要求

- Python 3.10+
- 支持 Windows、macOS 和 Linux

## 主要算法支持

### 哈希算法
- MD5
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
- BLAKE2b, BLAKE2s, BLAKE3
- SM3

### 对称加密
- AES
- ChaCha20
- Salsa20
- SM4

### 非对称加密
- RSA
- ECC (椭圆曲线加密)
- Edwards
- ElGamal

### 数字签名
- RSA 签名
- ECDSA 签名
- EdDSA 签名

## 技术实现

### 架构设计

PyCryptoKit 采用 MV（模型-视图）架构设计：
- **模型层**：核心密码学算法实现
- **视图层**：基于 PySide6 的图形界面

### 目录结构

```
PyCryptoKit/
├── __init__.py          # 包初始化，导出主要API
├── __main__.py          # GUI启动入口点
├── core/                # 核心算法实现
│   ├── __init__.py
│   ├── asymmetric/      # 非对称加密算法
│   │   ├── __init__.py
│   │   ├── ecc.py       # 椭圆曲线加密
│   │   ├── elgamal.py   # ElGamal加密
│   │   ├── factory.py   # 非对称加密工厂
│   │   └── rsa.py       # RSA加密
│   ├── hash/            # 哈希算法
│   │   ├── __init__.py
│   │   ├── base.py      # 哈希基类
│   │   ├── blake.py     # BLAKE系列
│   │   ├── factory.py   # 哈希工厂
│   │   ├── MD5.py       # MD5算法
│   │   ├── sha.py       # SHA系列
│   │   ├── sha3.py      # SHA3系列
│   │   └── SM3.py       # SM3算法
│   ├── signature/       # 数字签名
│   │   ├── __init__.py
│   │   ├── base.py      # 签名基类
│   │   ├── ECDSA_sig.py # ECDSA签名
│   │   ├── EdDSA_sig.py # EdDSA签名
│   │   ├── factory.py   # 签名工厂
│   │   └── RSA_sig.py   # RSA签名
│   └── symmetric/       # 对称加密
│       ├── __init__.py
│       ├── AES.py       # AES加密
│       ├── base.py      # 对称加密基类
│       ├── ChaCha20.py  # ChaCha20加密
│       ├── factory.py   # 对称加密工厂
│       ├── Salsa20.py   # Salsa20加密
│       └── SM4.py       # SM4加密
├── gui/                 # 图形界面
│   ├── __init__.py
│   ├── application.py   # 应用程序
│   ├── main_window.py   # 主窗口
│   └── views/           # 各功能视图
│       ├── __init__.py
│       ├── asymmetric_view.py  # 非对称加密视图
│       ├── hash_view.py        # 哈希计算视图
│       ├── signature_view.py   # 数字签名视图
│       └── symmetric_view.py   # 对称加密视图
└── requirements.txt     # 依赖列表
```

## 构建说明

要将 PyCryptoKit 构建为可执行程序，请按照以下步骤操作：

### 准备工作

1. 确保已安装 Python 3.10 或更高版本
2. 安装 PyInstaller：
   ```bash
   pip install pyinstaller
   ```
3. 安装项目依赖：
   ```bash
   pip install -r requirements.txt
   ```

### 构建步骤

1. 根据您的处理器架构修改 `PyCryptoKit.spec` 文件中的 `target_arch` 参数：
   - 对于 amd64 处理器：
     ```python
     target_arch='x86_64'
     ```
   - 对于 Apple Silicon：
     ```python
     target_arch='arm64'
     ```
   - 对于 x86 处理器：
     ```python
     target_arch='x86'
     ```

2. 执行 PyInstaller 构建命令：
   ```bash
   pyinstaller PyCryptoKit.spec
   ```

3. 构建完成后，可执行程序将位于 `dist` 目录中：
   - Windows: `dist/PyCryptoKit/PyCryptoKit.exe`
   - macOS: `dist/PyCryptoKit.app`
   - Linux: `dist/PyCryptoKit/PyCryptoKit`

### 常见构建问题

- **缺少依赖库**：如果构建过程中报错缺少某些库，请使用 pip 安装对应的库。
- **UPX 压缩错误**：如果遇到 UPX 相关错误，可以在 `PyCryptoKit.spec` 文件中将 `upx=True` 改为 `upx=False`。
- **权限问题**：在 Linux/macOS 上，可能需要使用 `sudo` 或确保有足够的文件权限。

## 常见问题解答

**Q: 如何保证密钥的安全性？**  
A: 除生成后用户手动保存的密钥以外，PyCryptoKit 不会在后台存储任何密钥。所有密钥仅在内存中处理，程序关闭后会被清除。同时，对于需要保存的密钥，建议使用安全的密钥管理工具。

**Q: 工具支持哪些文件格式？**  
A: PyCryptoKit 可以处理任何类型的文件或字符串，进行加密、解密、哈希计算和数字签名，没有格式限制。

**Q: 是否支持批量处理？**  
A: 当前版本主要针对单个文件或文本进行处理，未来版本可能会添加批量处理功能。

**Q: 使用的密码学库是什么？**  
A: PyCryptoKit 主要基于Python的密码学库如cryptography、pycryptodome等构建，确保算法实现的安全性和正确性。

**Q: 如何贡献代码？**
A: 欢迎贡献代码！请在 GitHub 上提交 Pull Request 或 Issue。

## 使用说明

1. 启动应用程序
2. 从上方菜单选择所需功能（哈希计算、对称加密、非对称加密或数字签名）
3. 根据界面提示输入数据、选择算法和参数
4. 点击相应按钮执行操作
5. 查看并复制/保存结果

## 未来计划

- 添加更多加密算法
- 改进用户界面体验
- 增加批量处理功能
- 添加密钥管理功能
- 支持更多文件格式和编码

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。
