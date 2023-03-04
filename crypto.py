from typing import List, Tuple
from enigma_bytes import EnigmaBytesMachine, EnigmaBytesRotor
class BlockCipher():
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError('key length must be of size 16 bytes')

        self.key = key

    def build_key_schedule(self, key: bytes, shift: int) -> EnigmaBytesMachine:
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
        return encryptor
    
    def bits(l: bytes):
        for n in l:
            while n:
                b = n & (~n+1)
                yield b
                n ^= b
    
    def apply_pbox(self, input_bytes: bytes, pbox: List[int]) -> bytes:
        # Create an empty byte string to hold the output data
        output_bytes = bytearray()

        for i in range(len(pbox)):
            # Compute the byte and bit index of the input data
            byte_idx = pbox[i] // 8
            bit_idx = pbox[i] % 8

            # Extract the value of the input bit at the computed index
            bit_val = (input_bytes[byte_idx] >> (7 - bit_idx)) & 0x01

            # If the current output byte is full, add a new byte to the output string
            if i % 8 == 0:
                output_bytes.append(0x00)

            # Append the current bit value to the current output byte
            output_bytes[-1] |= bit_val << (7 - (i % 8))

        return bytes(output_bytes)
    
    def expansion(self, data: bytes) -> bytes:
        pbox = [
            0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36, 37, 38, 39, 
            8, 9, 10, 11, 12, 13, 14, 15, 40, 41, 42, 43, 44, 45, 46, 47, 
            16, 17, 18, 19, 20, 21, 22, 23, 48, 49, 50, 51, 52, 53, 54, 55, 
            24, 25, 26, 27, 28, 29, 30, 31, 56, 57, 58, 59, 60, 61, 62, 63, 
            0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36, 37, 38, 39, 
            8, 9, 10, 11, 12, 13, 14, 15, 40, 41, 42, 43, 44, 45, 46, 47, 
            16, 17, 18, 19, 20, 21, 22, 23, 48, 49, 50, 51, 52, 53, 54, 55, 
            24, 25, 26, 27, 28, 29, 30, 31, 56, 57, 58, 59, 60, 61, 62, 63
        ]
        return self.apply_pbox(data, pbox)
    
    # TODO
    def round_function(self, data: bytes, subkey: bytes) -> bytes:
        expansion_result = self.expansion(data)
        assert(len(expansion_result) == len(subkey))
        a = bytes(
            x ^ y 
            for x, y in zip(expansion_result, subkey)
        )
        return a
    
    def feistel_network_for_encrypt(self, left: bytes, right: bytes, subkey: bytes) -> Tuple[bytes, bytes]:
        new_left = right
        new_right = bytes(
            x ^ y 
            for x, y in zip(left, self.round_function(right, subkey))
        )
        return new_left, new_right
    
    def feistel_network_for_decrypt(self, left: bytes, right: bytes, subkey: bytes) -> Tuple[bytes, bytes]:
        new_right = left
        new_left = bytes(
            x ^ y 
            for x, y in zip(right, self.round_function(left, subkey))
        )
        return new_left, new_right

    def encrypt(self, plaintext: bytes) -> bytes:
        # Make sure plaintext is a multiple of 16 bytes (128 bits)
        if len(plaintext) % 16 != 0:
            padding = b'\x00' * (16 - len(plaintext) % 16)
            plaintext = plaintext + padding

        shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

        block_counts = len(plaintext) // 16

        result = bytearray()
        key_schedules = []

        for block in range(block_counts):
            index = block * 16

            left = plaintext[index : index + 8]
            right = plaintext[index + 8: index + 16]

            subkey = self.key
            for i in range(16):
                if i < len(key_schedules):
                    key_schedule = key_schedules[i]
                else:
                    key_schedule =  self.build_key_schedule(subkey, shifts[i])
                    key_schedules.append(key_schedule)

                subkey = key_schedule.encrypt(subkey)
                left, right = self.feistel_network_for_encrypt(left, right, subkey)
            
            result.extend(left + right)

        return bytes(result)

    def decrypt(self, ciphertext: bytes) -> bytes:
        shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

        block_counts = len(ciphertext) // 16

        result = bytearray()
        key_schedules = []

        for block in range(block_counts):
            index = block * 16

            left = ciphertext[index : index + 8]
            right = ciphertext[index + 8: index + 16]

            subkeys = []
            subkey = self.key
            for i in range(16):
                if i < len(key_schedules):
                    key_schedule = key_schedules[i]
                else:
                    key_schedule = self.build_key_schedule(subkey, shifts[i])
                    key_schedules.append(key_schedule)

                subkey = key_schedule.encrypt(subkey)
                subkeys.append(subkey)

            for i in reversed(range(16)):
                left, right = self.feistel_network_for_decrypt(left, right, subkeys[i])
            
            result.extend(left + right)

        return bytes(result)
