from typing import List, Dict
from enum import Enum

class EnigmaBytesRotor(Enum):
    I = 0

    @classmethod
    def get_wiring(cls, rotor: 'EnigmaBytesRotor'):
        if rotor == EnigmaBytesRotor.I:
            return b'`\xaa\xdc\xa7\x9a\x88\t\xb3\xef\xe7\x94\xd70\xc89p\x93:5\xf1\x17\xab\xaf\xe5\xa9S\x9c\x01K\x87\x03\xcf\x18\n\xe6;\x91V\xb4\xc3\xf9u\x96NAYT\xfb\x0e\x8e\xd6I\x13\xbd<B\xfe\xf0\x8cZ2\x98r+\xac\xd5\xae\x0f\xdb\x9f\x99cJ\x92LR#\x08\xa5\x82\x95U\xe0\x19q\xe2\x8d\xa3l\xfd\x8f\x1dD\x10\xc58]\xbb\xd9\x81\xc0\x00M\xf4\x14j\xf3%\x16fe\r\xce\xbah\xdaw,W\xa2\xcb\xa6\xd2FX(_\x0b-\xd4\x9d\x8bP\xad\xe9\x0c\xb6\x1bQn\x06^\xd1$/\x85\x7f\xe1\xb2~\\H@4\x12\xbcm\xf2\'\x1f\xc1a\x86\xb1\xde\xa0v!\x9eo\xdft.\x05\xb5\xa4C\xedz\x07\xee\x1a}\x02\xeb\xe3i\xec\xb0\xa1=\xe4\x83\xf7\xb8\xdd\xc91\xf8b)|\xea\x90\xd8&G{\xf5\xa8E\x97[\x84\xcc\xbf?\xcd\xd3\xca\xbe>\xb7\xc6\xb9k\x8ag\xfc\xe8\xc2\xc46x"\x1e\x11\xfaO\x80* \xf6\x897\x15s\x9b\x1c\xd0y3\x04\xff\xc7d'
    
    @classmethod
    def get_inverse_wiring(cls, rotor: 'EnigmaBytesRotor'):
        if rotor == EnigmaBytesRotor.I:
            return b'e\x1b\xb7\x1e\xfc\xad\x8c\xb3M\x06!\x7f\x87o0C]\xec\x9a4h\xf5l\x14 S\xb5\x89\xf8[\xeb\x9f\xf1\xa7\xeaL\x8fk\xcd\x9e}\xc8\xf0?u\x80\xac\x90\x0c\xc5<\xfb\x99\x12\xe8\xf4_\x0e\x11#6\xbe\xdd\xd8\x98,7\xb0\\\xd2{\xce\x973H\x1cJf+\xee\x84\x8aK\x19.Q%v|-;\xd4\x96`\x8d~\x00\xa1\xc7G\xffnm\xe3r\xbai\xe1X\x9c\x8b\xa9\x0fT>\xf6\xab)\xa6t\xe9\xfa\xb2\xcf\xc9\xb6\x95\x92\xefcO\xc0\xd5\x91\xa2\x1d\x05\xf3\xe2\x83:V1Z\xcb$I\x10\nP*\xd3=F\x04\xf7\x1a\x82\xa8E\xa5\xbdwW\xafNy\x03\xd1\x18\x01\x15@\x85B\x16\xbc\xa3\x94\x07&\xae\x88\xde\xc2\xe0qa\x9b5\xdc\xd7d\xa0\xe6\'\xe7^\xdf\xfe\r\xc4\xdbx\xd6\xd9p\x1f\xf9\x8ez\xda\x81A2\x0b\xccbsD\x02\xc3\xa4\xaaR\x93U\xb9\xbf\x17"\t\xe5\x86\xca\xb8\xbb\xb1\xb4\x089\x13\x9djg\xd0\xf2\xc1\xc6(\xed/\xe4Y8\xfd'

    @classmethod
    def get_turnover_notch(cls, rotor: 'EnigmaBytesRotor'):
        if rotor == EnigmaBytesRotor.I:
            return int.from_bytes(b';',byteorder="big")
        
class EnigmaBytesMachine:
    REFLECTOR = {b'\xf0': b'\x10', b'\x10': b'\xf0', b'\xce': b'\n', b'\n': b'\xce', b'\x06': b')', b')': b'\x06', b'\xcb': b'@', b'@': b'\xcb', b'\xa5': b'\xc6', b'\xc6': b'\xa5', b'\xea': b';', b';': b'\xea', b'\x14': b'M', b'M': b'\x14', b'J': b'%', b'%': b'J', b'\x8e': b'~', b'~': b'\x8e', b'\x87': b"'", b"'": b'\x87', b'}': b'o', b'o': b'}', b'\xde': b'\x02', b'\x02': b'\xde', b'|': b'i', b'i': b'|', b'8': b'-', b'-': b'8', b'c': b'y', b'y': b'c', b'\x8b': b'\x11', b'\x11': b'\x8b', b'\x91': b'\x05', b'\x05': b'\x91', b'\xda': b'\xc2', b'\xc2': b'\xda', b'\xcd': b'D', b'D': b'\xcd', b'\xca': b'\xd3', b'\xd3': b'\xca', b'\xc3': b'B', b'B': b'\xc3', b'\xf7': b'\xcf', b'\xcf': b'\xf7', b'\x9e': b'\xa2', b'\xa2': b'\x9e', b'\xcc': b'\xff', b'\xff': b'\xcc', b'\x81': b'\x16', b'\x16': b'\x81', b'W': b'\xfa', b'\xfa': b'W', b'\xb1': b'[', b'[': b'\xb1', b'\x1d': b'*', b'*': b'\x1d', b'\x9b': b'\x19', b'\x19': b'\x9b', b'\xac': b'\x83', b'\x83': b'\xac', b'\x84': b'9', b'9': b'\x84', b'z': b'\xc8', b'\xc8': b'z', b'#': b'\x8a', b'\x8a': b'#', b'\x0b': b'f', b'f': b'\x0b', b'g': b'A', b'A': b'g', b'Y': b'\xf4', b'\xf4': b'Y', b']': b'?', b'?': b']', b'\x00': b'F', b'F': b'\x00', b'>': b'\x0f', b'\x0f': b'>', b'\x97': b'\x95', b'\x95': b'\x97', b'\xe8': b'\x9d', b'\x9d': b'\xe8', b'a': b'\xe1', b'\xe1': b'a', b'\xd6': b't', b't': b'\xd6', b'\x1f': b'\xed', b'\xed': b'\x1f', b',': b'\x1c', b'\x1c': b',', b'I': b'\xfd', b'\xfd': b'I', b'\xc4': b'_', b'_': b'\xc4', b'\x03': b'\xe4', b'\xe4': b'\x03', b'\x93': b'\x1a', b'\x1a': b'\x93', b' ': b'\xb0', b'\xb0': b' ', b'\xf6': b'\x82', b'\x82': b'\xf6', b'\x92': b'3', b'3': b'\x92', b'7': b'\x15', b'\x15': b'7', b'\x12': b'\x8d', b'\x8d': b'\x12', b'\xae': b'5', b'5': b'\xae', b'\xee': b'V', b'V': b'\xee', b'0': b'd', b'd': b'0', b'\xb6': b'x', b'x': b'\xb6', b'O': b'\xd4', b'\xd4': b'O', b'&': b'\r', b'\r': b'&', b'\xa9': b'\xd2', b'\xd2': b'\xa9', b'\xb8': b'C', b'C': b'\xb8', b'\x1b': b'S', b'S': b'\x1b', b'\xd5': b'(', b'(': b'\xd5', b'\xa3': b'\xec', b'\xec': b'\xa3', b'\xa7': b'\xe2', b'\xe2': b'\xa7', b'\x9a': b'2', b'2': b'\x9a', b'\x88': b'\xbb', b'\xbb': b'\x88', b'\xc0': b'{', b'{': b'\xc0', b'\t': b'n', b'n': b'\t', b'N': b'\xb5', b'\xb5': b'N', b'l': b'\xbe', b'\xbe': b'l', b'\x18': b'\x07', b'\x07': b'\x18', b'\x85': b'\xa8', b'\xa8': b'\x85', b'=': b'\x9f', b'\x9f': b'=', b'\xb9': b'\xf8', b'\xf8': b'\xb9', b'\x04': b'u', b'u': b'\x04', b'X': b'\xa6', b'\xa6': b'X', b'.': b'r', b'r': b'.', b'p': b'!', b'!': b'p', b'\xfe': b'G', b'G': b'\xfe', b'w': b'6', b'6': b'w', b'<': b'1', b'1': b'<', b'\xbc': b'\x99', b'\x99': b'\xbc', b'\xe0': b'\x9c', b'\x9c': b'\xe0', b'\xc7': b'\xbd', b'\xbd': b'\xc7', b'\xe7': b'P', b'P': b'\xe7', b'\x8f': b'\xe6', b'\xe6': b'\x8f', b'j': b'`', b'`': b'j', b'\xbf': b'm', b'm': b'\xbf', b'U': b'\x01', b'\x01': b'U', b'R': b'b', b'b': b'R', b'\xd1': b'\xdb', b'\xdb': b'\xd1', b'\xaf': b'\xf2', b'\xf2': b'\xaf', b'\x0e': b'\xaa', b'\xaa': b'\x0e', b'\xdd': b'\x90', b'\x90': b'\xdd', b'\x98': b'\xe3', b'\xe3': b'\x98', b'\xa0': b'Z', b'Z': b'\xa0', b'\xdc': b'4', b'4': b'\xdc', b'\xeb': b'e', b'e': b'\xeb', b'\xab': b'H', b'H': b'\xab', b'\x96': b'+', b'+': b'\x96', b'\xb2': b'\x94', b'\x94': b'\xb2', b'\xf5': b'k', b'k': b'\xf5', b'q': b'\xf9', b'\xf9': b'q', b'\xfb': b's', b's': b'\xfb', b'\x13': b'\xd8', b'\xd8': b'\x13', b'L': b'\xf1', b'\xf1': b'L', b'\xb7': b'\x86', b'\x86': b'\xb7', b'/': b'T', b'T': b'/', b'\xef': b'\xc1', b'\xc1': b'\xef', b'\x7f': b'\xfc', b'\xfc': b'\x7f', b'\x0c': b'\xc9', b'\xc9': b'\x0c', b'\x08': b'v', b'v': b'\x08', b'h': b'Q', b'Q': b'h', b'\xb3': b'\x8c', b'\x8c': b'\xb3', b'"': b'K', b'K': b'"', b'\xd9': b'\xa4', b'\xa4': b'\xd9', b'E': b'\xc5', b'\xc5': b'E', b'\xe9': b'\xd0', b'\xd0': b'\xe9', b':': b'\x89', b'\x89': b':', b'^': b'\xad', b'\xad': b'^', b'\xe5': b'\xba', b'\xba': b'\xe5', b'$': b'\xdf', b'\xdf': b'$', b'\x17': b'\x80', b'\x80': b'\x17', b'\x1e': b'\xb4', b'\xb4': b'\x1e', b'\\': b'\xa1', b'\xa1': b'\\', b'\xf3': b'\xd7', b'\xd7': b'\xf3'}

    '''
    Enigma Machine constructor
    Arguments:
        rotors: 3 positional EnigmaBytesRotor (left to right).
        rings: 3 positional rotor offset
    '''
    def __init__(self, rotors:List[EnigmaBytesRotor], positions: List[int], rings: List[int], plugboard: Dict[bytes,bytes]) -> None:
        self.rotors = rotors
        self.rotor_positions = positions
        self.rings = rings
        self.plugboard = plugboard

    def _plugboard_substitution(self, letter: bytes) -> bytes:
        if letter in self.plugboard:
            return self.plugboard[letter]
        else:
            return letter

    def _reflector_substitution(self, letter:int) -> bytes:
        return int.from_bytes(self.REFLECTOR[bytes([letter])], byteorder="big")

    def _forward_substitution(self, letter:bytes)->bytes:
        rotor_positions = self.rotor_positions
        rotors = self.rotors
        rings = self.rings
        for i in range(len(rotors)-1,-1,-1):
            rotor = rotors[i]
            rotor_wiring = EnigmaBytesRotor.get_wiring(rotor)
            shift = rotor_positions[i] - rings[i]

            letter = rotor_wiring[(letter + shift) % 256]
            letter = (letter + 256 - shift) % 256

        return letter

    def _backward_substitution(self, letter:int)->int:
        rotor_positions = self.rotor_positions
        rotors = self.rotors
        rings = self.rings
        for i in range(len(rotors)):
            rotor = rotors[i]
            rotor_inverse_wiring = EnigmaBytesRotor.get_inverse_wiring(rotor)
            shift = rotor_positions[i] - rings[i]

            letter = rotor_inverse_wiring[(letter + shift) % 256]
            letter = (letter + 256 - shift) % 256

        return letter

    def _advance_rotors(self):
        if self.rotor_positions[1] == EnigmaBytesRotor.get_turnover_notch(self.rotors[1]):
            print("Advance Var 2")
            self.rotor_positions[1] = (self.rotor_positions[1] + 1) % 256
            self.rotor_positions[0] = (self.rotor_positions[0] + 1) % 256
        if self.rotor_positions[2] == EnigmaBytesRotor.get_turnover_notch(self.rotors[2]):
            print("Advance Var 1")
            self.rotor_positions[1] = (self.rotor_positions[1] + 1) % 256
        self.rotor_positions[2] = (self.rotor_positions[2] + 1) % 256

    def encrypt(self, message: bytes) -> bytes:
        cipher_text = b""
        for letter in message:
            self._advance_rotors()
            letter = self._plugboard_substitution(letter)
            letter = self._forward_substitution(letter)
            letter = self._reflector_substitution(letter)
            letter = self._backward_substitution(letter)
            letter = self._plugboard_substitution(letter)
            cipher_text += bytes([letter])
        return cipher_text
    
encryptor = EnigmaBytesMachine(rotors=[EnigmaBytesRotor.I, EnigmaBytesRotor.I, EnigmaBytesRotor.I],
                          positions=[1,3,245], rings=[1,200,100], plugboard={})
original_plaintext = b'3\xb1\x95o\x06A\x9f\xc4H\xaf\xd71.g*\xe2a\xe6\xb3\x93\xefi\xc9\xc5\x91M\xba\x1e\xff\x0b\x08m_\x11\x9c<9k\xa9+\x03wF\xa6\x04\xfa\xe5\xd9Z|\xdf\xa0\xa4\x15;\xcd\x18:@\x9b\xc2Px4(\xfcS\x1f\x96\xe0]\xb5\x8fR\x1c\xfe\xe1v\x13\xeb>)\xc6\x81\'\x90\xbfz\\\xb9eBp\x8c\x10\x9a\xfd\x17\x1b\xf7d\xa7s7\xaef\xce\x98\x86\x07\xcf\x88E~\x16 \xc7TY8\xb8\xf5\x82=5-\xc1\xfb\x1a\x000\x87\xbe\xa1%\x8b\xea\x14[\x89/l2\xf1\xab\xca\xe8\xe4\xcb\n\xed\xf0\x9e\x92\x12U\x7f?\xf2\x01\xd0y\x80\x85\xda\xc3\xaa\xcc\xec\xe9\xa3Kj\x83\xc0\xdd\xbc\xf4q\xf8\xd1h\xe7V\xbbu\x05\xa5G\xf3\xd5\xd3\xad\x0e\x02W,\x8enr$\x9d\xd2\xde\r!\xa2I"\xb7&Nb\xbd\xd6J\xd8`\t\xb4\xd4\xb2\xe3\x1d\x0c\xa8c\xf6#6\xdbDL\xb6\x19\xc8\xdc\xac}\x0f\xf9\x94{QC\x8a\xeet\x8dO\x97X^\xb0\x99\x843\xb1\x95o\x06A\x9f\xc4H\xaf\xd71.g*\xe2a\xe6\xb3\x93\xefi\xc9\xc5\x91M\xba\x1e\xff\x0b\x08m_\x11\x9c<9k\xa9+\x03wF\xa6\x04\xfa\xe5\xd9Z|\xdf\xa0\xa4\x15;\xcd\x18:@\x9b\xc2Px4(\xfcS\x1f\x96\xe0]\xb5\x8fR\x1c\xfe\xe1v\x13\xeb>)\xc6\x81\'\x90\xbfz\\\xb9eBp\x8c\x10\x9a\xfd\x17\x1b\xf7d\xa7s7\xaef\xce\x98\x86\x07\xcf\x88E~\x16 \xc7TY8\xb8\xf5\x82=5-\xc1\xfb\x1a\x000\x87\xbe\xa1%\x8b\xea\x14[\x89/l2\xf1\xab\xca\xe8\xe4\xcb\n\xed\xf0\x9e\x92\x12U\x7f?\xf2\x01\xd0y\x80\x85\xda\xc3\xaa\xcc\xec\xe9\xa3Kj\x83\xc0\xdd\xbc\xf4q\xf8\xd1h\xe7V\xbbu\x05\xa5G\xf3\xd5\xd3\xad\x0e\x02W,\x8enr$\x9d\xd2\xde\r!\xa2I"\xb7&Nb\xbd\xd6J\xd8`\t\xb4\xd4\xb2\xe3\x1d\x0c\xa8c\xf6#6\xdbDL\xb6\x19\xc8\xdc\xac}\x0f\xf9\x94{QC\x8a\xeet\x8dO\x97X^\xb0\x99\x84'
cipher = encryptor.encrypt(original_plaintext)

decryptor = EnigmaBytesMachine(rotors=[EnigmaBytesRotor.I, EnigmaBytesRotor.I, EnigmaBytesRotor.I],
                           positions=[1,3,245], rings=[1,200,100],  plugboard={})
plaintext = decryptor.encrypt(cipher)
print(cipher)
print("=======")
print(plaintext)

assert(plaintext == original_plaintext)

print("==============================")