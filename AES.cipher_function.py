from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

#AES Encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return ciphertext, nonce, tag

#AES Decryption
def aes_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

#128-bit Algorithm
key = get_random_bytes(16) #128-bit key
plaintext = "Hello, My name is Jeffery D Winchester"
ciphertext, nonce, tag = aes_encrypt(plaintext, key)
decrypted_text = aes_decrypt(ciphertext, nonce, tag, key)

#PRINT: Plaintext, Ciphertext, and Decrypted Text
print("Plaintext:", plaintext)
print("Ciphertext:", binascii.hexlify(ciphertext).decode())
print("Decrypted text:", decrypted_text)