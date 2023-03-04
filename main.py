from crypto import BlockCipher

if __name__ == "__main__":
    key = b'Sixteen byte key'
    original_plaintext = b'pemilik rumah yang sah bukan anda tetapi ayah ibu anda, jadi jangan bohong lagi!'

    cipher = BlockCipher(key = key)
    ciphertext = cipher.encrypt(original_plaintext)
    print('ciphertext', ciphertext)
    print(len(ciphertext))

    print("=============================")

    cipher = BlockCipher(key = key)
    decrypted_plaintext = cipher.decrypt(ciphertext)
    print('result', decrypted_plaintext)
    print(len(decrypted_plaintext))
    
