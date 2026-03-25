
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# Generate a random 8-byte (64-bit) DES key
random_key = get_random_bytes(8)

# Alternatively, use a fixed 8-byte key (for demonstration only; not secure for real use)
fixed_key = b'secretkey'[:8]  # Ensure the key is exactly 8 bytes

print(f"Random key: {random_key}")
print(f"Fixed key: {fixed_key}")

# Choose which key to use for encryption/decryption
key = random_key  # Change to fixed_key if you want to use the fixed one

# Create a new DES cipher object in CBC mode (IV is generated automatically)
encrypt_cipher = DES.new(key, DES.MODE_CBC)
iv = encrypt_cipher.iv

print(f"IV: {iv}")
print(f"Block size: {encrypt_cipher.block_size}")

# Example plaintext to encrypt
plaintext = b'This is the plain text'
print(f"Plaintext: {plaintext}")

# Pad the plaintext to be a multiple of DES block size
padded_plaintext = pad(plaintext, DES.block_size)

# Encrypt the padded plaintext
ciphertext = encrypt_cipher.encrypt(padded_plaintext)
print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")

# Create a new DES cipher for decryption using the same key and IV
decrypt_cipher = DES.new(key, DES.MODE_CBC, iv)

# Decrypt and unpad the ciphertext to get the original plaintext
decrypted_plaintext = unpad(decrypt_cipher.decrypt(ciphertext), DES.block_size)
print(f"Decrypted Plaintext: {decrypted_plaintext.decode()}")