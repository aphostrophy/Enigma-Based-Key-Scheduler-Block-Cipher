import random

random.seed(314)

rotor_wiring = b'3\xb1\x95o\x06A\x9f\xc4H\xaf\xd71.g*\xe2a\xe6\xb3\x93\xefi\xc9\xc5\x91M\xba\x1e\xff\x0b\x08m_\x11\x9c<9k\xa9+\x03wF\xa6\x04\xfa\xe5\xd9Z|\xdf\xa0\xa4\x15;\xcd\x18:@\x9b\xc2Px4(\xfcS\x1f\x96\xe0]\xb5\x8fR\x1c\xfe\xe1v\x13\xeb>)\xc6\x81\'\x90\xbfz\\\xb9eBp\x8c\x10\x9a\xfd\x17\x1b\xf7d\xa7s7\xaef\xce\x98\x86\x07\xcf\x88E~\x16 \xc7TY8\xb8\xf5\x82=5-\xc1\xfb\x1a\x000\x87\xbe\xa1%\x8b\xea\x14[\x89/l2\xf1\xab\xca\xe8\xe4\xcb\n\xed\xf0\x9e\x92\x12U\x7f?\xf2\x01\xd0y\x80\x85\xda\xc3\xaa\xcc\xec\xe9\xa3Kj\x83\xc0\xdd\xbc\xf4q\xf8\xd1h\xe7V\xbbu\x05\xa5G\xf3\xd5\xd3\xad\x0e\x02W,\x8enr$\x9d\xd2\xde\r!\xa2I"\xb7&Nb\xbd\xd6J\xd8`\t\xb4\xd4\xb2\xe3\x1d\x0c\xa8c\xf6#6\xdbDL\xb6\x19\xc8\xdc\xac}\x0f\xf9\x94{QC\x8a\xeet\x8dO\x97X^\xb0\x99\x84'

def scramble_wiring(wiring):
    # Shuffle the list randomly
    random.shuffle(wiring)

    # Convert the shuffled list back to a bytes object
    scrambled_bytes = b''.join(wiring)

    return scrambled_bytes

scrambled_wiring = scramble_wiring([bytes([i]) for i in rotor_wiring])
print(scrambled_wiring)
print(len(set(scrambled_wiring)))

# Get inverse wiring for alphabet
wiring = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
inverse_wiring = bytearray(len(wiring))
for i in range(len(wiring)):
    inverse_wiring[ord(wiring[i]) - 65] = i + 65
inverse_wiring = bytes(inverse_wiring)
print(inverse_wiring)

def get_inverse_wiring_bytes(wiring: bytes) -> bytes:
    inverse_wiring = bytearray(len(wiring))
    for i, byte in enumerate(wiring):
        inverse_wiring[byte] = i
    return bytes(inverse_wiring)

print(get_inverse_wiring_bytes(rotor_wiring))

def generate_reflector():
    reflector = dict()
    byte_set = set(range(256))
    while byte_set:
        byte1 = random.choice(list(byte_set))
        byte_set.remove(byte1)
        byte2 = random.choice(list(byte_set))
        byte_set.remove(byte2)
        reflector[bytes([byte1])] = bytes([byte2])
        reflector[bytes([byte2])] = bytes([byte1])
    return reflector

reflector = generate_reflector()
print("Reflector")
print("============")
print(reflector)
# Verify commutative property
print(reflector[b'0'])
print(reflector[b'd'])

print(reflector[b'\x00'])
print(reflector[b'F'])

for i in range(256):
    assert(reflector[reflector[bytes([i])]] == bytes([i]))