__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

import rsa


class RSA:

    def __init__(self):
        """Constructor creates public and private keys"""
        self.public_key, self.private_key = rsa.newkeys(512)

    def encrypt(self, message, key=None):
        """Encodes given message
        takes a message to encode as a string
        and public key provided by the receiver
        if no given key it uses the class variable generated by contructor
        it can be be changed by the method set_public_key too
        returns byte array"""
        if key is None:
            key = self.public_key
        byte_message = message.encode("utf-8")
        crypto = rsa.encrypt(byte_message, key)
        return crypto

    def set_public_key(self, key):
        """sets the public key in object to be able to encode message for other objects"""
        self.public_key = key

    def get_public_key(self):
        """returns public key
        it must be send to our correspondent before encoding any message"""
        return self.public_key

    def decrypt(self, message):
        """decrypt message using own private key"""
        return rsa.decrypt(message, self.private_key).decode("utf-8")