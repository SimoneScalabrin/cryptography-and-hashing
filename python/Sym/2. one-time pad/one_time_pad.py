
from random import randint
import matplotlib.pyplot as plt

# The alphabet used for the one-time pad cipher: all 256 possible byte values (0-255)
import string
ALPHABET = bytes([i for i in range(256)])

def random_sequence(text):
    """
    Generate a random key sequence for the one-time pad.
    The key is a list of random integers, each corresponding to a shift for a character in the text.
    Args:
        text (str): The input text to generate a key for.
    Returns:
        list: A list of random integers (key) with the same length as the text.
    """
    key = [randint(0, len(ALPHABET) - 1) for _ in range(len(text))]
    return key

def otp_encrypt(text, key):
    """
    Encrypt a message using the one-time pad cipher.
    Args:
        text (str): The plaintext message to encrypt.
        key (list): The key sequence (list of integers).
    Returns:
        str: The encrypted ciphertext.
    """
    # Convert text to bytes if it's a string
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')
    else:
        text_bytes = text
    cipher_bytes = bytearray()
    for index, byte in enumerate(text_bytes):
        key_index = key[index]
        cipher_bytes.append((byte + key_index) % 256)
    return bytes(cipher_bytes)

def otp_decrypt(cipher_text, key):
    """
    Decrypt a message encrypted with the one-time pad cipher.
    Args:
        cipher_text (str): The encrypted message.
        key (list): The key sequence (list of integers).
    Returns:
        str: The decrypted plaintext.
    """
    # Accept bytes as input
    cipher_bytes = cipher_text if isinstance(cipher_text, (bytes, bytearray)) else cipher_text.encode('utf-8')
    plain_bytes = bytearray()
    for index, byte in enumerate(cipher_bytes):
        key_index = key[index]
        plain_bytes.append((byte - key_index) % 256)
    try:
        return plain_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return plain_bytes  # Return bytes if not valid utf-8

def frequency_analysis(text):
    """
    Perform frequency analysis on the given text.
    Args:
        text (str): The text to analyze.
    Returns:
        dict: A dictionary mapping each letter to its frequency in the text.
    """
    # Accept bytes or string
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')
    else:
        text_bytes = text
    byte_frequency = {i: 0 for i in range(256)}
    for byte in text_bytes:
        byte_frequency[byte] += 1
    return byte_frequency

def plot_distribution(letter_frequency):
    """
    Plot a bar chart of letter frequencies.
    Args:
        letter_frequency (dict): Dictionary of letter frequencies.
    """
    # Only plot nonzero byte values for readability
    nonzero_bytes = [b for b in letter_frequency if letter_frequency[b] > 0]
    values = [letter_frequency[b] for b in nonzero_bytes]
    labels = [chr(b) if 32 <= b < 127 else f"0x{b:02x}" for b in nonzero_bytes]
    plt.bar(labels, values)
    plt.xlabel('Byte (ASCII or hex)')
    plt.ylabel('Frequency')
    plt.title('Byte Frequency Distribution (0-255)')
    plt.show()

if __name__ == '__main__':
    # Example message to encrypt and decrypt
    message = (
        'The one-time pad (OTP) is an encryption technique that cannot be cracked in cryptography. '
        'It requires the use of a single-use pre-shared key that is larger than or equal to the size of the message being sent. '
        'In this technique, a plaintext is paired with a random secret key, also referred to as a one-time pad. '
        'Then each bit or character of the plaintext is encrypted by combining it with the corresponding bit or character from the pad using modular addition.'
    )

    # Generate a random key for the message (length in bytes)
    key1 = random_sequence(message.encode('utf-8'))
    print(f"Key: {key1}")

    # Encrypt the message (returns bytes)
    cipher = otp_encrypt(message, key1)
    print(f"Ciphertext (bytes): {cipher}")

    # Decrypt the message (returns string if possible)
    plain = otp_decrypt(cipher, key1)
    print(f"Decrypted Plaintext: {plain}")

    # Plot the frequency distribution of the ciphertext
    plot_distribution(frequency_analysis(cipher))