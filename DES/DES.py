from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# DES key 64 bits (8 bytes)


# Size of the key must be 64 bits (8 bytes)
key = b'secretkey'

key1 = get_random_bytes(8)

# Ensure that key is 8 bytes
key = key[:8] if len(key) >= 8 else key.ljust(8, b"\x00")

print(f"random key: {key1}")
print(f"selected key: {key}")


# DES will generate the IV automatically
encrypt_cipher = DES.new(key, DES.MODE_CBC)

iv = encrypt_cipher.IV
print(f"IV: {iv}")
print(f"Block size: {encrypt_cipher.block_size}")

plain_text = b'This is the plain text'
print(f"plaintext: {plain_text}")
padded_plain_text = pad(plain_text, DES.block_size)

cipher_text = encrypt_cipher.encrypt(padded_plain_text)
print(f"ciphertext: {binascii.hexlify(cipher_text)}")

decrypt_cipher = DES.new(key, DES.MODE_CBC, iv)
original_text = decrypt_cipher.decrypt(cipher_text)
original_text = unpad(original_text, DES.block_size).decode()   # decode for get the string

print(f"plaintext after decription: {original_text}")