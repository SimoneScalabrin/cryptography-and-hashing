ALPHABET = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def vigenere_encrypt(plain_text, key):
    
    plain_text = plain_text.upper()
    key = key.upper()
    
    cipher_text = ''
    
    # Index of the letters of the key
    key_index = 0
    
    for character in plain_text:
        
        index = (ALPHABET.find(character) + ALPHABET.find(key[key_index])) % len(ALPHABET)
        
        cipher_text = cipher_text + ALPHABET[index]
        
        key_index = (key_index + 1) % len(key)
            
    return cipher_text


def vigenere_decrypt(cipher_text, key):
    
    cipher_text = cipher_text.upper()
    key = key.upper()
    
    plain_text = ''
    
    # Index of the letters of the key
    key_index = 0
    
    for character in cipher_text:
        
        index = (ALPHABET.find(character) - ALPHABET.find(key[key_index])) % len(ALPHABET)
        
        plain_text = plain_text + ALPHABET[index]
        
        key_index = (key_index + 1) % len(key)
        
    return plain_text


if __name__ == '__main__':
    
    text = 'Cryptography and Hashing Fundamentals in Python and Java'
    
    key1 = 'SecretKey'
    
    cipher = vigenere_encrypt(text, key1)
    print(f"cipher: {cipher}")
   
    plain =  vigenere_decrypt(cipher, key1)
    print(f"plain: {plain}")
    
    