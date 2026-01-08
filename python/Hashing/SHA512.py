from hashlib import sha512
"""
Module for calculating the SHA-512 hash of a string.

This module demonstrates how to use the standard `hashlib` library to generate the SHA-512 hash of a text.
SHA-512 is a cryptographic hash algorithm widely used for data integrity and security.
"""

def sha512_hash(text: str) -> str:
	"""
	Computes the SHA-512 hash of a string.

	Args:
		text (str): The input string to hash.

	Returns:
		str: The SHA-512 hash in hexadecimal format.
	"""
	# Encode the string to bytes and compute the SHA-512 hash
	hash_object = sha512(text.encode('utf-8'))
	sha512_hex = hash_object.hexdigest()
	return sha512_hex


def main():
	"""
	More significant example usage of the sha512_hash function.
	Demonstrates hashing multiple strings, comparing hashes, and hashing a file.
	"""
	# List of example texts
	texts = [
		"Hello, World!",
		"hello, world!",
		"The quick brown fox jumps over the lazy dog",
		"The quick brown fox jumps over the lazy dog."
	]
	print("SHA-512 hashes of different strings:")
	for t in texts:
		print(f"Text: {t}")
		print(f"SHA-512 Hash: {sha512_hash(t)}\n")

	# Compare hashes of similar strings
	print("Comparing hashes of similar strings:")
	s1 = "password123"
	s2 = "password124"
	hash1 = sha512_hash(s1)
	hash2 = sha512_hash(s2)
	print(f"String 1: {s1} -> {hash1}")
	print(f"String 2: {s2} -> {hash2}")
	print(f"Are hashes equal? {'Yes' if hash1 == hash2 else 'No'}\n")


if __name__ == "__main__":
	main()
