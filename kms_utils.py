import os
import json
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from gmssl import sm2, sm4
import base64
import secrets
import gmalg

class UnifiedKeyManager:
    def __init__(self, key_store_path: str, master_key: bytes = None):
        """
        统一密钥管理系统
        :param key_store_path: 密钥库文件路径
        :param master_key: 主加密密钥（用于加密对称密钥）
        """
        self.key_store_path = key_store_path
        self.master_key = master_key
        self.keys = {}
        self.next_key_id = 1
        
        # 初始化密钥库
        self._init_keystore()

    def _init_keystore(self):
        """初始化密钥存储"""
        if os.path.exists(self.key_store_path):
            self._load_keystore()
        else:
            self._create_keystore()

    def _create_keystore(self):
        """创建新密钥库"""
        os.makedirs(os.path.dirname(self.key_store_path), exist_ok=True)
        self._save_keystore()

    def _load_keystore(self):
        """加载现有密钥库"""
        try:
            with open(self.key_store_path, 'r') as f:
                data = json.load(f)
                self.next_key_id = data['meta']['next_key_id']
                self.keys = {
                    int(k): self._decode_key(v) 
                    for k, v in data['keys'].items()
                }
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError("密钥库文件损坏") from e

    def _save_keystore(self):
        """安全保存密钥库（TODO 可优化为原子写入：先写入临时文件，再替换文件名）"""
        with open(self.key_store_path, 'w') as f:
            data = {
                'meta': {
                    'version': '1.0',
                    'created_at': datetime.now().isoformat(),
                    'next_key_id': self.next_key_id,
                },
                'keys': {
                    str(kid): self._encode_key(v) 
                    for kid, v in self.keys.items()
                }
            }
            json.dump(data, f, indent=2)

    def _encrypt_key(self, plain_key: bytes) -> bytes:
        """使用主密钥加密对称密钥"""
        if not self.master_key:
            return plain_key
        return bytes([b ^ self.master_key[i % len(self.master_key)] 
                    for i, b in enumerate(plain_key)])

    def _decrypt_key(self, cipher_key: bytes) -> bytes:
        """解密对称密钥"""
        if not self.master_key:
            return cipher_key
        return bytes([b ^ self.master_key[i % len(self.master_key)] 
                    for i, b in enumerate(cipher_key)])

    def generate_key(self, key_type: str, *args) -> int:
        """
        生成新密钥并返回密钥ID
        :param key_type: 密钥类型 (SM4, AES, RSA, SM2)
        :param params: 类型相关参数
        """
        key_id = self.next_key_id
        key_info = {
            'id': key_id,
            'type': key_type,
            'created_at': datetime.now().isoformat(),
            'public': None,
            'private': None,
        }

        # 生成密钥
        if key_type == 'SM4':
            key_info['private'] = secrets.token_bytes(16)
        elif key_type == 'AES':
            key_size = args[0] if args else 256
            key_info['private'] = secrets.token_bytes(key_size//8)
        elif key_type == 'RSA':
            key_size = args[0] if args else 2048
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            key_info['private'] = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            key_info['public'] = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif key_type == 'SM2':
             # Generate SM2 key pair            
            _sm2 = gmalg.SM2()
            private_key, public_key = _sm2.generate_keypair()
            # private_key = private_key.hex()
            # public_key = public_key.hex()
            # Extract public key from the generated key pair
            key_info['private'] = private_key
            key_info['public'] = public_key
        else:
            raise ValueError(f"不支持的密钥类型: {key_type}")

        self.keys[key_id] = key_info
        self.next_key_id += 1
        self._save_keystore()
        return key_id

    def get_key(self, key_id: int) -> dict:
        """获取密钥信息"""
        if key_id not in self.keys:
            raise KeyError(f"密钥ID不存在: {key_id}")
        return self.keys[key_id]
    def _encode_key(self, key_info: dict) -> dict:
        """统一处理所有密钥的编码"""
        encoded = key_info.copy()
        
        # 处理私钥
        if key_info['private'] is not None:
            if isinstance(key_info['private'], bytes):
                # 对称密钥加密后转base64
                if key_info['type'] in ['SM4', 'AES']:
                    encrypted = self._encrypt_key(key_info['private'])
                    encoded['private'] = base64.b64encode(encrypted).decode()
                # 非对称密钥直接转base64
                else:
                    encoded['private'] = base64.b64encode(
                        key_info['private']
                    ).decode()
        
        # 处理公钥（RSA/SM2）
        if key_info['public'] is not None and isinstance(key_info['public'], bytes):
            encoded['public'] = base64.b64encode(key_info['public']).decode()
            
        return encoded

    def _decode_key(self, key_data: dict) -> dict:
        """统一处理所有密钥的解码"""
        decoded = key_data.copy()
        
        # 处理私钥
        if key_data['private'] is not None:
            if key_data['type'] in ['SM4', 'AES']:
                decrypted = self._decrypt_key(
                    base64.b64decode(key_data['private'])
                )
                decoded['private'] = decrypted
            else:
                decoded['private'] = base64.b64decode(key_data['private'])
        
        # 处理公钥
        if key_data['public'] is not None:
            decoded['public'] = base64.b64decode(key_data['public'])
            
        return decoded

# 初始化示例
def init_key_system(key_store_path):
    if key_store_path is None or key_store_path == "":
        key_store_path = "./keystore.json"        
    print(f"初始化密钥管理系统，密钥存储路径: {key_store_path}")
    # 从环境变量获取主密钥
    master_key = os.environ.get('MCP_CRYPTOKIT_MASTER_KEY')
    if master_key:
        master_key = master_key.encode()
    return UnifiedKeyManager(key_store_path, master_key=master_key)