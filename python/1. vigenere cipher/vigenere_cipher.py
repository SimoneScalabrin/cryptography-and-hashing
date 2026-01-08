
# The alphabet used for the Vigenère cipher: all ASCII characters (0-127)
ALPHABET = ''.join([chr(i) for i in range(128)])


def vigenere_encrypt(plain_text, key):
    """
    Encrypt a message using the Vigenère cipher.
    Args:
        plain_text (str): The plaintext message to encrypt.
        key (str): The encryption key.
    Returns:
        str: The encrypted ciphertext.
    """
    cipher_text = ''
    key_index = 0  # Tracks position in the key
    for character in plain_text:
        char_pos = ALPHABET.find(character)
        key_pos = ALPHABET.find(key[key_index])
        if char_pos == -1 or key_pos == -1:
            raise ValueError(f"Character '{character}' or key character '{key[key_index]}' not in ASCII alphabet.")
        index = (char_pos + key_pos) % len(ALPHABET)
        cipher_text += ALPHABET[index]
        key_index = (key_index + 1) % len(key)
    return cipher_text



def vigenere_decrypt(cipher_text, key):
    """
    Decrypt a message encrypted with the Vigenère cipher.
    Args:
        cipher_text (str): The encrypted message.
        key (str): The encryption key.
    Returns:
        str: The decrypted plaintext.
    """
    plain_text = ''
    key_index = 0  # Tracks position in the key
    for character in cipher_text:
        char_pos = ALPHABET.find(character)
        key_pos = ALPHABET.find(key[key_index])
        if char_pos == -1 or key_pos == -1:
            raise ValueError(f"Character '{character}' or key character '{key[key_index]}' not in ASCII alphabet.")
        index = (char_pos - key_pos) % len(ALPHABET)
        plain_text += ALPHABET[index]
        key_index = (key_index + 1) % len(key)
    return plain_text



if __name__ == '__main__':
    # Example plaintext and key
    text = 'Cryptography and Hashing Fundamentals in Python and Java'
    key1 = 'SecretKey'

    # Encrypt the plaintext
    cipher = vigenere_encrypt(text, key1)
    print(f"Ciphertext: {cipher}")

    # Decrypt the ciphertext
    plain = vigenere_decrypt(cipher, key1)
    print(f"Decrypted Plaintext: {plain}")

