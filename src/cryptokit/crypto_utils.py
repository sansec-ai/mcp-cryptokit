# 在文件顶部添加导入
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import base64

# AES 加密实现
def aes_encrypt(plaintext: str, key: str) -> str:
    # 生成随机16字节IV
    iv = os.urandom(16)
    
    # 创建加密器（使用CBC模式）
    cipher = Cipher(
        algorithms.AES(key.encode().ljust(32)[:32]),  # 自动处理密钥长度
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # 处理填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # 加密
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 返回 base64 编码的 IV + 密文
    return base64.b64encode(iv + ciphertext).decode()

# AES 解密实现
def aes_decrypt(ciphertext: str, key: str) -> str:
    data = base64.b64decode(ciphertext)
    iv, ciphertext = data[:16], data[16:]
    
    cipher = Cipher(
        algorithms.AES(key.encode().ljust(32)[:32]),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 去除填充
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

# RSA 密钥对生成（建议在服务初始化时生成）
RSA_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()

# RSA 加密
def rsa_encrypt(plaintext: str, public_key: str) -> str:
    ciphertext = RSA_PUBLIC_KEY.encrypt(
        plaintext.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# RSA 解密
def rsa_decrypt(ciphertext: str, private_key: str) -> str:
    data = base64.b64decode(ciphertext)
    plaintext = RSA_PRIVATE_KEY.decrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# 哈希算法实现
def hash_data(algorithm: str, data: str) -> str:
    algo = algorithm.lower()
    if algo not in ['md5', 'sha1', 'sha256', 'sha512']:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hasher = hashlib.new(algo)
    hasher.update(data.encode())
    return hasher.hexdigest()