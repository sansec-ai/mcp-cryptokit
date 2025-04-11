import unittest,os,sys
# 获取当前文件所在目录的父目录（项目根目录）
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# 将项目根目录添加到模块搜索路径
sys.path.insert(0, project_root)
import crypto_utils,kms_utils

class TestSymmetricCrypto(unittest.TestCase):
    def setUp(self):
        test_file_path = os.path.abspath("test_keystore.json")
        try:
            os.remove(test_file_path)
        except FileNotFoundError:
            pass
        self.key_mgr = kms_utils.init_key_system(test_file_path)
        self.crypto_utils = crypto_utils.CryptoUtils(self.key_mgr)

    def test_sm4_encrypt_decrypt(self):
        self.sm4_key_id = self.key_mgr.generate_key('SM4')
        # Test data
        plaintext = "Hello, SM4!"
        
        # Encrypt
        ciphertext = self.crypto_utils.sm4_encrypt(plaintext, self.sm4_key_id)
        
        # Decrypt
        decrypted_text = self.crypto_utils.sm4_decrypt(ciphertext, self.sm4_key_id)
        # print(f"sm4_ciphertext: {ciphertext}")
        # print(f"sm4_decrypted_text: {decrypted_text}")
        
        # Assert
        self.assertEqual(plaintext, decrypted_text)

    def test_aes_encrypt_decrypt(self):
        self.aes_key_id = self.key_mgr.generate_key('AES', 256)
        # Test data
        plaintext = "Hello, AES!"
        
        # Encrypt
        ciphertext = self.crypto_utils.aes_encrypt(plaintext, self.aes_key_id)
        
        # Decrypt
        decrypted_text = self.crypto_utils.aes_decrypt(ciphertext, self.aes_key_id)
        # print(f"aes_ciphertext: {ciphertext}")
        # print(f"aes_decrypted_text: {decrypted_text}")
        
        # Assert
        self.assertEqual(plaintext, decrypted_text)

    def test_rsa_encrypt_decrypt(self):
        self.rsa_key_id = self.key_mgr.generate_key('RSA', 2048)
        # Test data
        plaintext = "Hello, RSA!"
        
        # Encrypt
        ciphertext = self.crypto_utils.rsa_encrypt(plaintext, self.rsa_key_id)
        
        # Decrypt
        decrypted_text = self.crypto_utils.rsa_decrypt(ciphertext, self.rsa_key_id)
        # print(f"rsa_ciphertext: {ciphertext}")
        # print(f"rsa_decrypted_text: {decrypted_text}")
        
        # Assert
        self.assertEqual(plaintext, decrypted_text)

    def test_rsa_sign_verify(self):
        self.rsa_key_id = self.key_mgr.generate_key('RSA', 2048)
        # Test data
        plaintext = "Hello, RSA Sign/Verify!"
        
        # Sign
        signature = self.crypto_utils.rsa_sign(plaintext, self.rsa_key_id)
        print(f"rsa_signature: {signature}")
        
        # Verify
        verification_result = self.crypto_utils.rsa_verify(plaintext, signature, self.rsa_key_id)
        print(f"rsa_verification_result: {verification_result}")
        
        # Assert
        self.assertTrue(verification_result)

    def test_sm2_encrypt_decrypt(self):
        self.sm2_key_id = self.key_mgr.generate_key('SM2')
        # Test data
        plaintext = "Hello, SM2!"
        
        # Encrypt
        ciphertext = self.crypto_utils.sm2_encrypt(plaintext, self.sm2_key_id)
        print(f"sm2_ciphertext: {ciphertext}")
        
        # Decrypt
        decrypted_text = self.crypto_utils.sm2_decrypt(ciphertext, self.sm2_key_id)
        print(f"sm2_decrypted_text: {decrypted_text}")
        
        # Assert
        self.assertEqual(plaintext, decrypted_text)

    def test_sm2_sign_verify(self):
        self.sm2_key_id = self.key_mgr.generate_key('SM2')
        # Test data
        plaintext = "Hello, SM2 Sign/Verify!"
        
        # Sign
        signature = self.crypto_utils.sm2_sign(plaintext, self.sm2_key_id)
        print(f"sm2_signature: {signature}")
        
        # Verify
        verification_result = self.crypto_utils.sm2_verify(plaintext, signature, self.sm2_key_id)
        print(f"sm2_verification_result: {verification_result}")
        
        # Assert
        self.assertTrue(verification_result)

    def test_hash_algorithms(self):
        # Test data
        plaintext = "Hello, Hash!"
        
        # Test MD5
        md5_hash = self.crypto_utils.hash_data('MD5', plaintext)
        print(f"MD5: {md5_hash}")
        self.assertEqual(len(md5_hash), 32)
        
        # Test SHA1
        sha1_hash = self.crypto_utils.hash_data('SHA1', plaintext)
        print(f"SHA1: {sha1_hash}")
        self.assertEqual(len(sha1_hash), 40)
        
        # Test SHA256
        sha256_hash = self.crypto_utils.hash_data('SHA256', plaintext)
        print(f"SHA256: {sha256_hash}")
        self.assertEqual(len(sha256_hash), 64)
        
        # Test SHA512
        sha512_hash = self.crypto_utils.hash_data('SHA512', plaintext)
        print(f"SHA512: {sha512_hash}")
        self.assertEqual(len(sha512_hash), 128)

if __name__ == '__main__':
    unittest.main()