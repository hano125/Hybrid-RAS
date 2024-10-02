from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def decrypt_aes(key, encrypted_data):
    iv = encrypted_data[:16]  # Extract the IV
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_data

def decrypt_rsa(private_key, encrypted_key):
    if isinstance(private_key, bytes):
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key
