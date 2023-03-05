from crypto import BlockCipher
import time

if __name__ == "__main__":
    key = b'Sixteen byte key'
    original_plaintext = b'''Test Plaintext'''

    print('Original Plaintext = ', original_plaintext)
    print("=============================")

    start_time = time.time()

    cipher = BlockCipher(key = key)
    ciphertext = cipher.encrypt(original_plaintext)

    print('Ciphertext = ', ciphertext)
    print("--- %s seconds ---" % (time.time() - start_time))
    print("=============================")

    start_time = time.time()

    cipher = BlockCipher(key = key)
    decrypted_plaintext = cipher.decrypt(ciphertext)
    print('Decrypted Plaintext = ', decrypted_plaintext)
    print("--- %s seconds ---" % (time.time() - start_time))
    