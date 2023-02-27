class BlockCipher():
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError('key length must be of size 16 bytes')

        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        pass

    def decrypt(self, ciphertext: bytes) -> bytes:
        pass
