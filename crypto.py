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
    
    def apply_sbox(self, input_bytes: bytes, sboxes: List[List[List[int]]]) -> bytes:
        # Split the 16-byte data into 8 2-byte blocks
        blocks = [input_bytes[i:i+2] for i in range(0, len(input_bytes), 2)]
        
        # Apply substitution to each block using the corresponding S-box
        for i in range(len(blocks)):
            sbox = sboxes[i]
            block = blocks[i]

            row = ((block[0] & 0b10000000) >> 7) ^ (block[1] >> 7)
            col = block[0] & 0b00001111

            blocks[i] = sbox[row][col].to_bytes(1, byteorder='big')
        
        # Concatenate the substituted blocks into a 16-byte data
        return b''.join(blocks)
    
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
    
    def round_function(self, data: bytes, subkey: bytes) -> bytes:
        expansion_result = self.expansion(data)
        assert(len(expansion_result) == len(subkey))
        a = bytes(
            x ^ y 
            for x, y in zip(expansion_result, subkey)
        )

        sboxes = {
            0: [
                [0x7E, 0x16, 0x75, 0x14, 0x18, 0x09, 0x78, 0x3F, 0x24, 0x6D, 0x1B, 0x52, 0x2A, 0x3D, 0x67, 0x45],
                [0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B],
            ],
            1: [
                [0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
                [0x6B, 0x6A, 0x69, 0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x5F, 0x5E, 0x5D, 0x5C],
            ],
            2: [
                [0x45, 0x67, 0x3D, 0x2A, 0x1B, 0x24, 0x52, 0x6D, 0x3F, 0x78, 0x09, 0x18, 0x14, 0x75, 0x16, 0x7E],
                [0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D],
            ],
            3: [
                [0x7E, 0x16, 0x75, 0x14, 0x18, 0x09, 0x78, 0x3F, 0x24, 0x6D, 0x1B, 0x52, 0x2A, 0x3D, 0x67, 0x45],
                [0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B],
            ],
            4: [
                [0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
                [0x6B, 0x6A, 0x69, 0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x5F, 0x5E, 0x5D, 0x5C],
            ],
            5: [
                [0x45, 0x67, 0x3D, 0x2A, 0x1B, 0x24, 0x52, 0x6D, 0x3F, 0x78, 0x09, 0x18, 0x14, 0x75, 0x16, 0x7E],
                [0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D],
            ],
            6: [
                [0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D],
                [0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
            ],
            7: [
                [0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B],
                [0x45, 0x67, 0x3D, 0x2A, 0x1B, 0x24, 0x52, 0x6D, 0x3F, 0x78, 0x09, 0x18, 0x14, 0x75, 0x16, 0x7E],
            ]
        }

        b = self.apply_sbox(a, sboxes)

        return b
    
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
