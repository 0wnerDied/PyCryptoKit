# PyCryptoKit - 密码学图形工具箱

## 项目概述

PyCryptoKit 是一个基于 Python 开发的密码学图形工具箱，为用户提供直观的图形界面来执行各种密码学操作。本工具箱集成了常见的加密、解密、哈希计算和数字签名等功能，适用于教学演示、安全研究和日常加密需求。

## 功能特点

- **用户友好的图形界面**：简洁直观的界面设计，无需命令行经验
- **多种哈希算法**：支持 MD5、SHA1、SHA256、SHA512、SHA3_256、SM3 等
- **对称加密工具**：AES、SM4 等算法的加密/解密操作
- **非对称加密工具**：RSA、ECC、SM2 等公钥密码系统
- **数字签名验证**：支持 RSA 签名、ECDSA、SM2 签名等
- **文件操作支持**：可直接处理文件的加密、解密和哈希计算
- **结果可视化**：清晰展示加密/解密结果，支持复制和保存

## 系统要求

- Python 3.10+
- 支持 Windows、macOS 和 Linux

## 技术实现

### 架构设计

PyCryptoKit 采用 MVC（模型-视图-控制器）架构设计：
- **模型层**：核心密码学算法实现
- **视图层**：基于 PyQt5 的图形界面
- **控制器层**：连接模型和视图，处理用户交互

### 目录结构

```
PyCryptoKit/
├── __init__.py          # 包初始化，导出主要API
├── __main__.py          # GUI启动入口点
├── core/                # 核心算法实现 (已完成)
│   ├── __init__.py
│   ├── asymmetric/
│   ├── hash/
│   ├── signature/
│   └── symmetric/
├── gui/                 # 图形界面 (待实现)
│   ├── __init__.py
│   ├── resources/
│   ├── views/
│   ├── widgets/
│   ├── main_window.py
│   └── application.py
├── utils/               # 工具函数 (待实现)
│   ├── __init__.py
│   ├── file_utils.py
│   └── config.py
├── tests/                   # 单元测试 (待实现)
├── docs/                    # 文档 (待实现)
├── requirements.txt         # 依赖列表 (待实现)
└── README.md                # 项目说明
```

### 核心算法模块

PyCryptoKit 的核心算法模块基于 Python 的密码学库实现：
- **哈希计算**：使用 hashlib 和 gmssl 库
- **对称加密**：使用 pycryptodome 和 gmssl 库
- **非对称加密**：使用 cryptography 和 gmssl 库
- **数字签名**：使用 cryptography 和 gmssl 库

### 图形界面

图形界面基于 PyQt5 实现，提供以下特性：
- 现代化的界面设计
- 主题切换（明/暗模式）
- 响应式布局，适应不同屏幕尺寸
- 拖放文件支持
- 操作历史记录

## 常见问题解答

**Q: 如何保证密钥的安全性？**  
A: PyCryptoKit 不会在后台存储任何密钥。所有密钥仅在内存中处理，程序关闭后会被清除。对于需要保存的密钥，建议使用安全的密钥管理工具。

**Q: 工具支持哪些文件格式？**  
A: PyCryptoKit 可以处理任何类型的文件或字符串，进行加密、解密和哈希计算，没有格式限制。
