# Importing necessary modules
from typing import Union
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class Asymmetric:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, message: Union[bytes, str]):
        # Instantiating PKCS1_OAEP object with the public key for encryption
        cipher = PKCS1_OAEP.new(key=self.public_key)
        # Encrypting the message with the PKCS1_OAEP object
        cipher_text = cipher.encrypt(bytes(message))
        return cipher_text

    def decrypt(self, cipher_text: Union[bytes, str]):
        # Instantiating PKCS1_OAEP object with the private key for decryption
        decrypt = PKCS1_OAEP.new(key=self.private_key)
        # Decrypting the message with the PKCS1_OAEP object
        decrypted_message = decrypt.decrypt(cipher_text)
        return decrypted_message

    def save(
        self, public_key_file="public_key.pem", private_key_file="private_key.pem"
    ):
        if public_key_file:
            # Save public key to file
            with open(public_key_file, "wb") as file:
                file.write(self.public_key.export_key())
        if private_key_file:
            # Save private key to file
            with open(private_key_file, "wb") as file:
                file.write(self.private_key.export_key())

    @classmethod
    def load(
        self, public_key_file="public_key.pem", private_key_file="private_key.pem"
    ):
        if public_key_file:
            # Load public key from file
            with open(public_key_file, "rb") as file:
                public_key = RSA.import_key(file.read())
        else:
            public_key = None
        if private_key_file:
            # Load private key from file
            with open(private_key_file, "rb") as file:
                private_key = RSA.import_key(file.read())
        else:
            private_key = None
        return Asymmetric(public_key, private_key)

    @classmethod
    def generateKeys(self, size=4096):
        # Generating private key (RsaKey object) of key length of size bits
        private_key = RSA.generate(size)
        # Generating the public key (RsaKey object) from the private key
        public_key = private_key.public_key()
        return Asymmetric(public_key, private_key)
