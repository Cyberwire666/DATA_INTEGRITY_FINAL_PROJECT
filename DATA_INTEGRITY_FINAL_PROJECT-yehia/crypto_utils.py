from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

BLOCK_SIZE = 16

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(file_bytes, key):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(file_bytes))
    return iv + encrypted

def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:BLOCK_SIZE]
    content = encrypted_data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(content))

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
            return hashlib.sha256(file_bytes).hexdigest()
    except Exception as e:
        raise Exception(f"Error reading file for hashing: {str(e)}")

def generate_aes_key():
    return get_random_bytes(32)

