from crypto import BlockCipher

if __name__ == "__main__":
    key = b'Sixteen byte key'
    original_plaintext = b'123456789'

    cipher = BlockCipher(key = key)
    ciphertext = cipher.encrypt(original_plaintext)
    print(ciphertext)

    cipher = BlockCipher(key = key)
    decrypted_plaintext = cipher.decrypt(ciphertext)
    print(decrypted_plaintext)
    
