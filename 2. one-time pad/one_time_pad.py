from random import randint
import matplotlib.pyplot as plt

ALPHABET = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def random_sequence(text):
    
    random = []
    
    for _ in range(len(text)):
        
        random.append(randint(0, len(ALPHABET)-1))
    
    return random

def otp_encrypt(text, key):

    text = text.upper()
    
    cipher_text = ''
    
    for index, char in enumerate(text):
        # value with we shift the given letter
        key_index = key[index]
        
        # given letter in plain_text
        char_index = ALPHABET.find(char)
        
        cipher_text += ALPHABET[(char_index + key_index) % len(ALPHABET)]
    
    return cipher_text

def otp_decrypt(cipher_text, key):
    
    cipher_text = cipher_text.upper()
    
    plain_text = ''
    
    for index, char in enumerate(cipher_text):
        # value with we shift the given letter
        key_index = key[index]
        
        # given letter in plain_text
        char_index = ALPHABET.find(char)
        
        plain_text += ALPHABET[(char_index - key_index) % len(ALPHABET)]
        
    return plain_text

def frequency_analysis(text):
    
    text = text.upper()
    
    letter_frequency = {}
    
    # initialize the dictionary
    for letter in ALPHABET:
        letter_frequency[letter] = 0
    
    for letter in text:
        # increment the occurrence of the given letter
        if letter in ALPHABET:
            letter_frequency[letter] += 1

    return letter_frequency

def plot_distribution(letter_frequency):
    plt.bar(letter_frequency.keys(), letter_frequency.values())
    plt.show()



if __name__ == '__main__':
    
    message = 'The onetime pad OTP is an encryption technique that cannot be cracked in cryptography It requires the use of a singleuse preshared key that is larger than or equal to the size of the message being sent In this technique a plaintext is paired with a random secret key also referred to as a onetime pad Then each bit or character of the plaintext is encrypted by combining it with the corresponding bit or character from the pad using modular addition'
    
    key1 = random_sequence(message)
    
    print(f"key: {key1}")
    
    cipher = otp_encrypt(message, key1)
    print(f"cipher: {cipher}")
   
    plain =  otp_decrypt(cipher, key1)
    print(f"plain: {plain}")
    
    plot_distribution(frequency_analysis(cipher))