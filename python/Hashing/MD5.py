from hashlib import md5
"""
Module for calculating the MD5 hash of a string.

This module demonstrates how to use the standard `hashlib` library to generate the MD5 hash of a text.
MD5 is a widely used cryptographic hash algorithm, but it is no longer considered secure for cryptographic applications.
"""

import hashlib

def md5_hash(text: str) -> str:
	"""
	Computes the MD5 hash of a string.

	Args:
		text (str): The input string to hash.

	Returns:
		str: The MD5 hash in hexadecimal format.
	"""
	# Encode the string to bytes and compute the MD5 hash
	hash_object = hashlib.md5(text.encode('utf-8'))
	md5_hex = hash_object.hexdigest()
	return md5_hex


def main():
	"""
	More significant example usage of the md5_hash function.
	Demonstrates hashing multiple strings, comparing hashes, and hashing a file.
	"""
	# List of example texts
	texts = [
		"Hello, World!",
		"hello, world!",
		"The quick brown fox jumps over the lazy dog",
		"The quick brown fox jumps over the lazy dog."
	]
	print("MD5 hashes of different strings:")
	for t in texts:
		print(f"Text: {t}")
		print(f"MD5 Hash: {md5_hash(t)}\n")

	# Compare hashes of similar strings
	print("Comparing hashes of similar strings:")
	s1 = "password123"
	s2 = "password124"
	hash1 = md5_hash(s1)
	hash2 = md5_hash(s2)
	print(f"String 1: {s1} -> {hash1}")
	print(f"String 2: {s2} -> {hash2}")
	print(f"Are hashes equal? {'Yes' if hash1 == hash2 else 'No'}\n")


if __name__ == "__main__":
	main()
