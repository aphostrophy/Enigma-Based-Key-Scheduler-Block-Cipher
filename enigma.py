'''
    Enigma Machine

    Based on one of the many variants of the Enigma Machine.
    Engima M3 UKW-B Reflector
'''


from typing import List, Dict
from enum import Enum

class EnigmaRotor(Enum):
    I = 0
    II = 1
    III = 2
    IV = 3

    '''
    Motor wiring reference
    https://en.wikipedia.org/wiki/Enigma_rotor_details
    '''
    @classmethod
    def get_wiring(cls, rotor: 'EnigmaRotor'):
        if rotor == EnigmaRotor.I:
            return "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
        if rotor == EnigmaRotor.II:
            return "AJDKSIRUXBLHWTMCQGZNPYFVOE"
        if rotor == EnigmaRotor.III:
            return "BDFHJLCPRTXVZNYEIWGAKMUSQO"
        if rotor == EnigmaRotor.IV:
            return "ESOVPZJAYQUIRHXLNFTGKDCMWB"

        raise ValueError()

    @classmethod
    def get_inverse_wiring(cls, rotor: 'EnigmaRotor'):
        if rotor == EnigmaRotor.I:
            return "UWYGADFPVZBECKMTHXSLRINQOJ"
        if rotor == EnigmaRotor.II:
            return "AJPCZWRLFBDKOTYUQGENHXMIVS"
        if rotor == EnigmaRotor.III:
            return "TAGBPCSDQEUFVNZHYIXJWLRKOM"
        if rotor == EnigmaRotor.IV:
            return "HZWVARTNLGUPXQCEJMBSKDYOIF"

        raise ValueError()

    @classmethod
    def get_turnover_notch(cls, rotor: 'EnigmaRotor'):
        if rotor == EnigmaRotor.I:
            return "Q"
        if rotor == EnigmaRotor.II:
            return "E"
        if rotor == EnigmaRotor.III:
            return "V"
        if rotor == EnigmaRotor.IV:
            return "J"

        raise ValueError()

class EnigmaMachine:
    REFLECTOR = {
        "A":"Y",
        "Y":"A",
        "B":"R",
        "R":"B",
        "C":"U",
        "U":"C",
        "D":"H",
        "H":"D",
        "E":"Q",
        "Q":"E",
        "F":"S",
        "S":"F",
        "G":"L",
        "L":"G",
        "I":"P",
        "P":"I",
        "J":"X",
        "X":"J",
        "K":"N",
        "N":"K",
        "M":"O",
        "O":"M",
        "T":"Z",
        "Z":"T",
        "V":"W",
        "W":"V"
    }

    '''
    Enigma Machine constructor
    Arguments:
        rotors: 3 positional EnigmaRotor (left to right). 
        rings: 3 positional rotor offset
    '''
    def __init__(self, rotors:List[EnigmaRotor], positions: List[int], rings: List[int], plugboard: Dict[str,str]) -> None:
        self.rotors = rotors
        self.rotor_positions = positions
        self.rings = rings
        self.plugboard = plugboard

    def _plugboard_substitution(self, letter: str) -> str:
        if letter in self.plugboard:
            return self.plugboard[letter]
        else:
            return letter

    def _reflector_substitution(self, letter:str) -> str:
        return self.REFLECTOR[letter]

    def _forward_substitution(self, letter:str)->str:
        rotor_positions = self.rotor_positions
        rotors = self.rotors
        rings = self.rings
        for i in range(len(rotors)-1,-1,-1):
            rotor = rotors[i]
            rotor_wiring = EnigmaRotor.get_wiring(rotor)
            shift = rotor_positions[i] - rings[i]

            letter = rotor_wiring[(ord(letter) - ord("A") + shift) % 26]
            letter = chr(ord("A") + (ord(letter) - ord("A") + 26 - shift) % 26)

        return letter

    def _backward_substitution(self, letter:str)->str:
        rotor_positions = self.rotor_positions
        rotors = self.rotors
        rings = self.rings
        for i in range(len(rotors)):
            rotor = rotors[i]
            rotor_inverse_wiring = EnigmaRotor.get_inverse_wiring(rotor)
            shift = rotor_positions[i] - rings[i]

            letter = rotor_inverse_wiring[(ord(letter) - ord("A") + shift) % 26]
            letter = chr(ord("A") + (ord(letter) - ord("A") + 26 - shift) % 26)

        return letter

    def _advance_rotors(self):
        if chr(self.rotor_positions[1]  + ord('A')) == EnigmaRotor.get_turnover_notch(self.rotors[1]):
            self.rotor_positions[1] = (self.rotor_positions[1] + 1) % 26
            self.rotor_positions[0] = (self.rotor_positions[0] + 1) % 26
        if chr(self.rotor_positions[2]  + ord('A')) == EnigmaRotor.get_turnover_notch(self.rotors[2]):
            self.rotor_positions[1] = (self.rotor_positions[1] + 1) % 26

        self.rotor_positions[2] = (self.rotor_positions[2] + 1) % 26

    def encrypt(self, message: str) -> str:
        cipher_text = ""
        for letter in message:
            self._advance_rotors()
            letter = self._plugboard_substitution(letter)
            print("initial plugboard", letter)
            letter = self._forward_substitution(letter)
            print("forward sub", letter)
            letter = self._reflector_substitution(letter)
            print("reflector sub", letter)
            letter = self._backward_substitution(letter)
            print("backward sub", letter)
            letter = self._plugboard_substitution(letter)
            print("final plugboard", letter)
            cipher_text += letter
            print("============")
        return cipher_text

encryptor = EnigmaMachine(rotors=[EnigmaRotor.III, EnigmaRotor.IV, EnigmaRotor.II], 
                          positions=[24,9,3], rings=[1,3,6], plugboard={})
cipher = encryptor.encrypt("H")

decryptor = EnigmaMachine(rotors=[EnigmaRotor.III, EnigmaRotor.IV, EnigmaRotor.II],
                           positions=[24,9,3], rings=[1,3,6],  plugboard={})
plaintext = decryptor.encrypt(cipher)
print(cipher)
print(plaintext)
