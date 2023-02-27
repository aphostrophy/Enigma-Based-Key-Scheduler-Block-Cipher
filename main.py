from crypto import BlockCipher

if __name__ == "__main__":
    key = b'Sixteen byte key'
    cipher = BlockCipher(key = key)
    plaintext = b'123456789'
    cipher.encrypt(plaintext)
