# MCP协议密码套件 (mcp-cryptokit)

[![GitHub](https://img.shields.io/github/license/sansec-ai/mcp-cryptokit)](https://github.com/sansec-ai/mcp-cryptokit)

## 简介

mcp-cryptokit 是一个基于MCP协议的密码套件，旨在为AI应用提供高效的密码学支持。它支持国密标准算法和通用密码算法，并提供密钥管理功能。

**mcp-cryptokit**：提供以下功能：
  - 对称加解密
  - 非对称加解密
  - 签名验签
  - Hash计算
  - 密钥管理

## 功能特点

- **标准MCP协议**：方便AI应用集成
- **支持国密标准算法**：包括SM2/SM3/SM4等
- **支持通用密码算法**：如AES、RSA、SHA等
- **支持密钥管理**：提供安全的密钥生成、存储和管理功能

## 安装与使用

### 安装

```bash
git clone https://github.com/sansec-ai/mcp-cryptokit.git
cd mcp-cryptokit
uv venv
source .venv/bin/activate
# 启动测试
uv run server.py

```
### 使用示例
#### 使用本项目提供的mcp_client.py测试
```bash
#将当前项目路径加入PYTHONPATH
cd mcp-cryptokit
source .venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:`(pwd)`"
python test/mcp_client.py server.py
# 配置阿里百炼大模型平台的api key
export MCP_API_KEY="DASHSCOPE_API_KEY"

```
连接成功将输出如下信息：
```bash
$ python test/mcp-client.py server.py

Connected to server with tools: ['generate_key', 'sm2_encrypt', 'sm2_decrypt', 'sm2_sign', 'sm2_verify', 'sm4_encrypt', 'sm4_decrypt', 'aes_encrypt', 'aes_decrypt', 'rsa_encrypt', 'rsa_decrypt', 'hash_data']

MCP Client Started!
Type your queries or 'quit' to exit.

Query:

```
测试样例：
```bash
Query: 使用sm4算法加密数据：我是明文
assistant: 为了使用SM4算法加密您的数据，我们需要遵循以下步骤：

1. 查询现有的SM4密钥ID列表。如果没有可用的密钥ID，则生成一个新的SM4密钥。
2. 使用获得的密钥ID来加密提供的明文数据。

首先，我将查询现有的SM4密钥ID列表。
assistant: 查询结果显示有多个SM4密钥ID可用。我们将使用第一个查询到的密钥ID，即1，来进行加密操作。

接下来，我将使用密钥ID为1的SM4密钥来加密您的数据"我是明文"。

使用SM4算法和密钥ID为1的密钥加密后的数据为：

\[ JlZf5+d6Xc1WbGTmlah2ZQbhaiaYwhEvVOI5uEW6/4zE1BipOvCcO8FaR/8a6Bkl \]

这是加密后的密文，采用base64编码。如果您需要解密此数据或有其他需求，请随时告知。

# 使用aes算法，由于没有密钥，mcp会自动创建一个
Query: 使用aes算法加密数据：我是明文
assistant: 为了使用AES算法加密您的数据，我们需要遵循以下步骤：

1. 查询现有的AES密钥ID。如果没有可用的AES密钥，我们将生成一个新的AES密钥。
2. 使用找到或生成的AES密钥ID来加密提供的明文数据。

现在，我将开始执行第一个步骤，即查询现有的AES密钥ID。
assistant: 看来目前没有可用的AES密钥，因此我将生成一个新的AES密钥以进行加密操作。接下来，我将调用`generate_key`函数来创建一个新的AES密钥。
assistant: 已成功生成新的AES密钥，其ID为22。现在我将使用这个新生成的AES密钥来加密您的数据"我是明文"。接下来，我会调用`aes_encrypt`函数进行加密。

您的数据"我是明文"已经使用AES加密，生成的密文（以Base64编码）为:
\[ tlj2MgrsqQyCJLOl08OIgHjVPBzNyWq2pnYsFtUNAUo= \]

如果您需要解密此数据或有其他任何操作，请随时告知我。

```

#### 使用编程插件测试

以roo code为例，拉取项目到`/work`目录:
```bash
git clone https://github.com/sansec-ai/mcp-cryptokit.git /work/mcp-cryptokit
```

在mcp server配置文件中增加：
```json
{
  "mcpServers": {
    "CryptoKit": {
      "command": "uv",
      "args": [
        "--directory",
        "/work/mcp-cryptokit",
        "run",
        "server.py"
      ],
      "alwaysAllow": [],
      "disabled": false
    }
  }
}
```


## 贡献指南
欢迎贡献代码或提出改进建议！请参考贡献指南了解如何参与项目。
## 许可证
mcp-cryptokit 遵循 Apache License 2.0 协议，允许自由使用、修改和分发。
## 联系我们
如需进一步了解或技术支持，请访问 GitHub项目页面 或联系项目维护者。