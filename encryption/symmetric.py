from PCSS import encrypt, decrypt, process_key
from typing import Union
from bitarray import bitarray


class Symmetric:
    def __init__(self, key):
        self.key = process_key(key)

    def encrypt(self, data: Union[str, bytes, bitarray, int]) -> bitarray:
        return encrypt(data, final_key=self.key)

    def decrypt(self, encrypted_data: Union[str, bytes, bitarray, int]) -> bitarray:
        return decrypt(encrypted_data, final_key=self.key)
