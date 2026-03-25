
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Generate a random 16-byte key for AES-128
key = get_random_bytes(16)

# Example plaintext to encrypt
plaintext = b'This is a secret message that needs to be encrypted using AES encryption.'

# Create a new AES cipher object in CBC mode
cipher = AES.new(key, AES.MODE_CBC)

# Pad the plaintext to be a multiple of AES block size and encrypt
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Print the ciphertext (encrypted message)
print("Ciphertext (hex):", ciphertext.hex())

# The IV (Initialization Vector) is needed for decryption
iv = cipher.iv

# Create a new AES cipher for decryption using the same key and IV
decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt and unpad the ciphertext to get the original plaintext
decrypted_plaintext = unpad(decrypt_cipher.decrypt(ciphertext), AES.block_size)

# Print the decrypted plaintext
print("Decrypted Plaintext:", decrypted_plaintext.decode())