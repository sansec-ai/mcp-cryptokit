import asyncio

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server,stdio
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts.base import Message
import mcp.types as types
from pydantic import AnyUrl
import crypto_utils, kms_utils
import argparse, os, json, base64

# Initialize FastMCP server
server = FastMCP("crypto")

# Constants
NWS_API_BASE = "https://api.cryptokit.gov"
USER_AGENT = "CryptoKit-app/1.0"

notes: dict[str, str] = {}

crypto_util = None
key_mgr = None

# Crypto tools implementation
@server.tool()
async def generate_key(key_type: str) -> int:
    """
    生成新的加密密钥
    参数:
        key_type: 密钥类型 (SM2, SM4, AES, RSA)
    返回:
        key_id: 生成的密钥ID (整数类型)
    """
    global key_mgr
    
    if key_type == "SM2":
        key_id = key_mgr.generate_key("SM2")
    elif key_type == "SM4":
        key_id = key_mgr.generate_key("SM4")
    elif key_type == "AES":
        key_id = key_mgr.generate_key("AES", 256)
    elif key_type == "RSA":
        key_id = key_mgr.generate_key("RSA", 2048)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
        
    key_info = key_mgr.get_key(key_id)
    return key_id
@server.tool()
async def query_keys(key_type: str) -> list[int]:
    """
    查询指定类型的密钥ID列表
    参数:
        key_type: 密钥类型 (SM2/SM4/AES/RSA)
    返回:
        list[int]: 匹配的密钥ID列表，列表元素类型为int
    """
    global key_mgr
    valid_types = ["SM2", "SM4", "AES", "RSA"]
    
    # 参数校验
    if key_type.upper() not in valid_types:
        raise ValueError(f"无效的密钥类型，支持的类型：{', '.join(valid_types)}")
    
    # 获取密钥存储字典
    key_type = key_type.upper()
    matched_keys = [
        key_id for key_id, key_info in key_mgr.keys.items()
        if key_info.get('type', '').upper() == key_type
    ]
    
    return sorted(matched_keys)
@server.tool()
async def sm2_encrypt(plaintext: str, key_id: int) -> str:
    """
    使用SM2密钥ID加密数据
    参数:
        plaintext: 需要加密的数据
        key_id: SM2密钥的ID (整数类型)
    返回:
        ciphertext: 加密后的数据，base64编码
    """
    return crypto_util.sm2_encrypt(plaintext, key_id)

@server.tool()
async def sm2_decrypt(ciphertext: str, key_id: int) -> str:
    """
    使用SM2密钥ID解密数据
    参数:
        ciphertext: 加密后的数据，base64编码
        key_id: SM2密钥的ID (整数类型)
    返回:
        plaintext: 解密后的数据
    """
    return crypto_util.sm2_decrypt(ciphertext, key_id)

@server.tool()
async def sm2_sign(data: str, key_id: int) -> str:
    """
    使用SM2密钥ID对数据进行签名
    参数:
        data: 需要签名的数据
        key_id: SM2密钥的ID (整数类型)
    返回:
        signature: 签名，base64格式
    """
    return crypto_util.sm2_sign(data, key_id)

@server.tool()
async def sm2_verify(data: str, signature: str, key_id: int) -> bool:
    """
    验证SM2签名
    参数:
        data: 原始数据
        signature: 需要验证的签名
        key_id: SM2密钥的ID (整数类型)
    返回:
        bool: 如果签名有效返回True，否则返回False
    """
    return crypto_util.sm2_verify(data, signature, key_id)

@server.tool()
async def sm4_encrypt(plaintext: str, key_id: int) -> str:
    """
    使用SM4加密数据
    参数:
        plaintext: 需要加密的数据
        key_id: SM4密钥的ID (整数类型)
    返回:
        ciphertext: IV(初始化向量) + 加密后的数据，base64编码
    """
    return crypto_util.sm4_encrypt(plaintext, key_id)

@server.tool()
async def sm4_decrypt(ciphertext: str, key_id: int) -> str:
    """
    使用SM4解密数据
    参数:
        ciphertext: IV(初始化向量) + 加密后的数据，base64编码
        key_id: SM4密钥的ID (整数类型)
    返回:
        plaintext: 解密后的数据
    """
    return crypto_util.sm4_decrypt(ciphertext, key_id)

@server.tool()
async def aes_encrypt(plaintext: str, key_id: int) -> str:
    """
    使用AES加密数据
    参数:
        plaintext: 需要加密的数据
        key_id: AES密钥的ID (整数类型)
    返回:
        ciphertext: IV(初始化向量) + 加密后的数据，base64编码
    """
    return crypto_util.aes_encrypt(plaintext, key_id)

@server.tool()
async def aes_decrypt(ciphertext: str, key_id: int) -> str:
    """
    使用AES解密数据
    参数:
        ciphertext: IV(初始化向量) + 加密后的数据，base64编码
        key_id: AES密钥的ID (整数类型)
    返回:
        plaintext: 解密后的数据
    """
    return crypto_util.aes_decrypt(ciphertext, key_id)

@server.tool()
async def rsa_encrypt(plaintext: str, key_id: int) -> str:
    """
    使用RSA密钥ID加密数据
    参数:
        plaintext: 需要加密的数据
        key_id: RSA密钥的ID (整数类型)
    返回:
        ciphertext: 加密后的数据，base64编码
    """
    return crypto_util.rsa_encrypt(plaintext, key_id)

@server.tool()
async def rsa_decrypt(ciphertext: str, key_id: int) -> str:
    """
    使用RSA密钥ID解密数据
    参数:
        ciphertext: 加密后的数据，base64编码
        key_id: RSA密钥的ID (整数类型)
    返回:
        plaintext: 解密后的数据
    """
    return crypto_util.rsa_decrypt(ciphertext, key_id)

@server.tool()
async def hash_data(algorithm: str, data: str) -> str:
    """
    计算数据的哈希值
    参数:
        algorithm: 哈希算法 (md5, sha1, sha256, sha512)
        data: 需要哈希的数据
    返回:
        hash: 哈希值，十六进制格式
    """
    return crypto_util.hash_data(algorithm, data)

# @server.resource("resource://sm4-keys")
# async def get_sm4_keys() -> str:
#     """
#     获取所有sm4密钥
#     """
#     global key_mgr
#     sm4_keys = [key for key_id, key in key_mgr.keys.items() if key['type'] == 'SM4']
#     return json.dumps({
#         "keys": sm4_keys,
#         "count": len(sm4_keys)
#     }, indent=2)

# @server.resource("resource://sm2-keys")
# async def get_sm2_keys() -> str:
#     """
#     获取所有sm2密钥
#     """
#     global key_mgr
#     sm2_keys = [key for key_id, key in key_mgr.keys.items() if key['type'] == 'SM2']
#     return json.dumps({
#         "keys": sm2_keys,
#         "count": len(sm2_keys)
#     }, indent=2)

# @server.resource("resource://aes-keys")
# def get_aes_keys() -> str:
#     """
#     获取所有aes密钥
#     """
#     global key_mgr
#     aes_keys = [key for key_id, key in key_mgr.keys.items() if key['type'] == 'AES']
#     return json.dumps({
#         "keys": aes_keys,
#         "count": len(aes_keys)
#     }, indent=2)

# @server.resource("resource://rsa-keys")
# def get_rsa_keys() -> str:
#     """
#     获取所有rsa密钥
#     """
#     global key_mgr
#     rsa_keys = [key for key_id, key in key_mgr.keys.items() if key['type'] == 'RSA']
#     return json.dumps({
#         "keys": rsa_keys,
#         "count": len(rsa_keys)
#     }, indent=2)

# @server.resource("resource://key/{key_id}")
# def get_key(key_id) -> str:
#     """
#     获取某个指定密钥的详情
#     参数:
#         key_id: 密钥索引编号
#     """
#     global key_mgr
#     try:
#         key_id = int(key_id)
#         key_info = key_mgr.get_key(key_id)
#         return json.dumps(key_info, indent=2)
#     except (ValueError, KeyError) as e:
#         return json.dumps({
#             "error": str(e),
#             "message": "Invalid key ID or key not found"
#         }, indent=2)

@server.prompt()
def create_key_prompt() -> list[Message]:
    """
    密钥生成指导提示
    功能：引导用户正确生成加密密钥
    典型场景：
    - 新系统初始化时需要创建基础密钥
    - 定期轮换业务加密密钥
    - 为不同服务创建隔离密钥
    """
    return [
        {
            "role": "system",
            "content": """请按照以下步骤操作：
1. 使用 generate-key 工具选择密钥类型 (SM2/SM4/AES/RSA)
2. 指定密钥参数 (如RSA-2048/AES-256)
3. 记录返回的 key_id 到安全存储
4. (可选) 配置密钥访问权限"""
        },
        {
            "role": "user",
            "content": "需要为支付系统创建一组SM2密钥对"
        }
    ]
@server.prompt()
def crypt_data(data: str) -> list[Message]:
    """
    数据加密操作提示
    功能：指导结构化数据加密流程
    参数：
    - data: 需要加密的明文数据
    支持场景：
    - 数据库字段加密
    - 文件批量加密
    - API传输数据保护
    """
    return [
        {
            "role": "system",
            "content": f"""加密 {data} 数据步骤：
1. 确认加密算法需求 (SM4/AES适合字段级，SM2适合密钥交换)
2. 如果用户未提供密钥ID，则可调用query_keys查询密钥列表，并使用第1个符合条件的密钥ID。如果密钥列表为空，则需要调用generate_key生成密钥。
3. 调用对应加密工具 (sm4_encrypt/aes_encrypt)
4. 处理加密后数据的存储格式 (HEX/BASE64)"""
        }
    ]
@server.prompt()
def signature_workflow_prompt(data: str) -> list[Message]:
    """
    数字签名验证流程提示
    功能：确保数据完整性和来源可信
    适用场景：
    - API请求签名
    - 文件防篡改验证
    - 交易记录审计
    """
    return [
        {
            "role": "system",
            "content": """签名验证步骤：
1. 确认用户使用的sm2密钥ID
2. 如果用户未提供密钥ID，则可调用query_keys查询密钥列表，并使用第1个符合条件的密钥ID。如果密钥列表为空，则需要调用generate_key生成密钥。
3. 调用 sm2_sign 生成数据签名
4. 验证时调用 sm2_verify"""
        }
    ]
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key_store", 
        type=str, 
        default=os.getcwd() + "/keystore.json",
        help="密钥存储目录 (默认: 当前工作目录)"
    )
    return parser.parse_args()

if __name__ == "__main__":
    # Initialize key manager and crypto utils
    args = parse_args()
    key_mgr = kms_utils.init_key_system(args.key_store)
    crypto_util = crypto_utils.CryptoUtils(key_mgr)

    # Initialize and run the server
    # asyncio.run(stdio_main())
    server.run(transport='stdio')
