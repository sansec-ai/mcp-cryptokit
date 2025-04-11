from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from gmssl import sm4, sm2, func
import hashlib
import os
import base64

class CryptoUtils:
    def __init__(self, key_mgr):
        self.key_mgr = key_mgr

    def sm4_encrypt(self, plaintext: str, key_id: int) -> str:
        # Get key from key manager
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'SM4':
            raise ValueError("密钥类型错误，需要SM4密钥")
        key = key_info['private']
        
        # Generate random 16-byte IV
        iv = os.urandom(16)
        
        # Prepare SM4 cipher
        crypt_sm4 = sm4.CryptSM4()
        
        # Process key (16 bytes for SM4)
        key_bytes = key.ljust(16)[:16]
        crypt_sm4.set_key(key_bytes, sm4.SM4_ENCRYPT)
        
        # Apply PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt data
        ciphertext = crypt_sm4.crypt_cbc(iv, padded_data)
        
        # Return IV + ciphertext in base64
        return base64.b64encode(iv + ciphertext).decode()

    # SM4 Decryption
    def sm4_decrypt(self, ciphertext: str, key_id: int) -> str:
        # Get key from key manager
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'SM4':
            raise ValueError("密钥类型错误，需要SM4密钥")
        key = key_info['private']
        
        # Decode base64
        data = base64.b64decode(ciphertext)
        iv, ciphertext = data[:16], data[16:]
        
        # Prepare SM4 cipher
        crypt_sm4 = sm4.CryptSM4()
        key_bytes = key.ljust(16)[:16]
        crypt_sm4.set_key(key_bytes, sm4.SM4_DECRYPT)
        
        # Decrypt data
        padded_plaintext = crypt_sm4.crypt_cbc(iv, ciphertext)
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode()
    # Add these methods to the CryptoUtils class

    def sm2_encrypt(self, plaintext: str, key_id: int) -> str:
        """
        SM2 encryption using public key
        :param plaintext: Data to encrypt
        :param key_id: Key ID of SM2 public key
        :return: Base64-encoded ciphertext
        """
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'SM2':
            raise ValueError("Invalid key type, SM2 required")        

        public_key_hex = key_info['public'].hex()
        
        sm2_public = sm2.CryptSM2(
            public_key=public_key_hex,
            private_key=None,
            mode=1
        )
        ciphertext = sm2_public.encrypt(plaintext.encode())
        return base64.b64encode(ciphertext).decode()

    def sm2_decrypt(self, ciphertext: str, key_id: int) -> str:
        """
        SM2 decryption using private key
        :param ciphertext: Base64-encoded ciphertext
        :param key_id: Key ID of SM2 private key
        :return: Decrypted plaintext
        """
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'SM2':
            raise ValueError("Invalid key type, SM2 required")
            
        private_key_hex = key_info['private'].hex()
        public_key_hex = key_info['public'].hex()
        
        sm2_private = sm2.CryptSM2(
            public_key=public_key_hex,
            private_key=private_key_hex,
            mode=1
        )
        decrypted = sm2_private.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode()

    def sm2_sign(self, data: str, key_id: int) -> str:
        """
        SM2 signature using private key
        :param data: Data to sign
        :param key_id: Key ID of SM2 private key
        :return: Base64-encoded signature
        """
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'SM2':
            raise ValueError("Invalid key type, SM2 required")
        # Convert stored bytes back to hex strings
        public_key_hex = key_info['public'].hex()
        private_key_hex = key_info['private'].hex()

        sm2_crypt = sm2.CryptSM2(
            public_key=public_key_hex,
            private_key=private_key_hex, mode=1
        )
        # Generate proper random K
        k = func.random_hex(sm2_crypt.para_len) 
        # SM3-with-SM2 is the standard combination
        signature = sm2_crypt.sign_with_sm3(data.encode(), k)
        return base64.b64encode(bytes.fromhex(signature)).decode()

    def sm2_verify(self, data: str, signature: str, key_id: int) -> bool:
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'SM2':
            raise ValueError("Invalid key type, SM2 required")

        public_key_hex = key_info['public'].hex()
        
        sm2_public = sm2.CryptSM2(
            public_key=public_key_hex,
            private_key=None,
            mode=1
        )
        
        try:
            # Convert base64 to hex string
            signature_bytes = base64.b64decode(signature)
            signature_hex = signature_bytes.hex()
            
            # Use proper verification with SM3 hash
            return sm2_public.verify_with_sm3(
                signature_hex,  # Must be hex string
                data.encode()    # Raw data (library handles SM3 hashing)
            )
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False
    # AES 加密实现
    def aes_encrypt(self, plaintext: str, key_id: int) -> str:
        # Get key from key manager
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'AES':
            raise ValueError("密钥类型错误，需要AES密钥")
        key = key_info['private']
        
        # 生成随机16字节IV
        iv = os.urandom(16)
        
        # 创建加密器（使用CBC模式）
        cipher = Cipher(
            algorithms.AES(key.ljust(32)[:32]),  # 自动处理密钥长度
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
    def aes_decrypt(self, ciphertext: str, key_id: int) -> str:
        # Get key from key manager
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'AES':
            raise ValueError("密钥类型错误，需要AES密钥")
        key = key_info['private']
        
        data = base64.b64decode(ciphertext)
        iv, ciphertext = data[:16], data[16:]
        
        cipher = Cipher(
            algorithms.AES(key.ljust(32)[:32]),
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
    def rsa_encrypt(self, plaintext: str, key_id: int) -> str:
        # Get key from key manager
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'RSA':
            raise ValueError("密钥类型错误，需要RSA密钥")
        
        # Load public key from PEM format
        public_key = serialization.load_pem_public_key(
            key_info['public'],
            backend=default_backend()
        )
        
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    # RSA 解密
    def rsa_decrypt(self, ciphertext: str, key_id: int) -> str:
        # Get key from key manager
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'RSA':
            raise ValueError("密钥类型错误，需要RSA密钥")
        
        # Load private key from PEM format
        private_key = serialization.load_pem_private_key(
            key_info['private'],
            password=None,
            backend=default_backend()
        )
        
        data = base64.b64decode(ciphertext)
        plaintext = private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    def rsa_sign(self, data: str, key_id: int, hash_algorithm: str = 'SHA256') -> str:
        """
        Sign data using RSA private key
        :param data: Data to be signed
        :param key_id: Key ID of RSA private key
        :param hash_algorithm: Hash algorithm (SHA256, SHA384, SHA512)
        :return: Base64-encoded signature
        """
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'RSA':
            raise ValueError("Invalid key type, RSA required")

        private_key = serialization.load_pem_private_key(
            key_info['private'],
            password=None,
            backend=default_backend()
        )

        # Validate hash algorithm
        hash_map = {
            'SHA256': hashes.SHA256,
            'SHA384': hashes.SHA384,
            'SHA512': hashes.SHA512
        }
        if hash_algorithm.upper() not in hash_map:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

        # Sign using PSS padding
        signature = private_key.sign(
            data.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hash_map[hash_algorithm.upper()]()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hash_map[hash_algorithm.upper()]()
        )
        return base64.b64encode(signature).decode()

    def rsa_verify(self, data: str, signature: str, key_id: int, hash_algorithm: str = 'SHA256') -> bool:
        """
        Verify RSA signature
        :param data: Original data
        :param signature: Base64-encoded signature
        :param key_id: Key ID of RSA public key
        :param hash_algorithm: Hash algorithm used for signing
        :return: True if verification succeeds
        """
        key_info = self.key_mgr.get_key(key_id)
        if key_info['type'] != 'RSA':
            raise ValueError("Invalid key type, RSA required")

        public_key = serialization.load_pem_public_key(
            key_info['public'],
            backend=default_backend()
        )

        # Validate hash algorithm
        hash_map = {
            'SHA256': hashes.SHA256,
            'SHA384': hashes.SHA384,
            'SHA512': hashes.SHA512
        }
        if hash_algorithm.upper() not in hash_map:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

        try:
            public_key.verify(
                base64.b64decode(signature),
                data.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hash_map[hash_algorithm.upper()]()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hash_map[hash_algorithm.upper()]()
            )
            return True
        except Exception as e:
            return False
    # 哈希算法实现
    def hash_data(self, algorithm: str, data: str) -> str:
        algo = algorithm.lower()
        if algo not in ['md5', 'sha1', 'sha256', 'sha512']:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hasher = hashlib.new(algo)
        hasher.update(data.encode())
        return hasher.hexdigest()