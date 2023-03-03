from typing import Tuple
from enigma_bytes import EnigmaBytesMachine, EnigmaBytesRotor
class BlockCipher():
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError('key length must be of size 16 bytes')

        self.key = key

    def key_schedule(self, key: bytes, shift: int) -> bytes:
        c_start = key[:8]
        d_start = key[8:]

        c_end = bytes([(c << shift) % 256 for c in c_start])
        d_end = bytes([(d << shift) % 256 for d in d_start])

        three_c = c_end[:3]
        three_d = d_end[:3]

        positions = [int(c) for c in three_c]
        rings = [int(d) for d in three_d]

        encryptor = EnigmaBytesMachine(
            rotors=[EnigmaBytesRotor.I, EnigmaBytesRotor.I, EnigmaBytesRotor.I],
            positions=positions, 
            rings=rings, 
            plugboard={}
        )
        return encryptor.encrypt(key)
    
    def round_function(self, left: bytes, subkey: bytes) -> bytes:
        pass
    
    def feistel_network(self, left: bytes, right: bytes, subkey: bytes) -> Tuple[bytes, bytes]:
        new_left = right
        new_right = bytes(x ^ y for x, y in zip(left, subkey))
        return new_left, new_right


    def encrypt(self, plaintext: bytes) -> bytes:
        # Make sure plaintext is a multiple of 16 bytes (128 bits)
        if len(plaintext) % 16 != 0:
            padding = b'\x00' * (16 - len(plaintext) % 16)
            plaintext = plaintext + padding

        shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

        block_size = len(plaintext)
        
        left = plaintext[:block_size // 2]
        right = plaintext[block_size // 2:]

        subkey = self.key
        for i in range(16):
            subkey = self.key_schedule(subkey, shifts[i])
            left, right = self.feistel_network(left, right, subkey)

        return left + right

    def decrypt(self, ciphertext: bytes) -> bytes:
        shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

        block_size = len(ciphertext)
        
        left = ciphertext[:block_size // 2]
        right = ciphertext[block_size // 2:]

        subkeys = []
        subkey = self.key
        for i in range(16):
            subkeys.append(subkey)
            subkey = self.key_schedule(subkey, shifts[i])

        for i in reversed(range(16)):
            left, right = self.feistel_network(left, right, subkeys[i])

        return left + right
