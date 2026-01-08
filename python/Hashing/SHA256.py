from hashlib import sha256
"""
Module for calculating the SHA-256 hash of a string.

This module demonstrates how to use the standard `hashlib` library to generate the SHA-256 hash of a text.
SHA-256 is a cryptographic hash algorithm widely used for data integrity and security.
"""

def sha256_hash(text: str) -> str:
	"""
	Computes the SHA-256 hash of a string.

	Args:
		text (str): The input string to hash.

	Returns:
		str: The SHA-256 hash in hexadecimal format.
	"""
	# Encode the string to bytes and compute the SHA-256 hash
	hash_object = sha256(text.encode('utf-8'))
	sha256_hex = hash_object.hexdigest()
	return sha256_hex


def main():
	"""
	More significant example usage of the sha256_hash function.
	Demonstrates hashing multiple strings, comparing hashes, and hashing a file.
	"""
	# List of example texts
	texts = [
		"Hello, World!",
		"hello, world!",
		"The quick brown fox jumps over the lazy dog",
		"The quick brown fox jumps over the lazy dog."
	]
	print("SHA-256 hashes of different strings:")
	for t in texts:
		print(f"Text: {t}")
		print(f"SHA-256 Hash: {sha256_hash(t)}\n")

	# Compare hashes of similar strings
	print("Comparing hashes of similar strings:")
	s1 = "password123"
	s2 = "password124"
	hash1 = sha256_hash(s1)
	hash2 = sha256_hash(s2)
	print(f"String 1: {s1} -> {hash1}")
	print(f"String 2: {s2} -> {hash2}")
	print(f"Are hashes equal? {'Yes' if hash1 == hash2 else 'No'}\n")


if __name__ == "__main__":
	main()
