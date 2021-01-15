__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from Crypto.PublicKey import DSA as dsa
from Crypto.Signature import DSS
from Crypto.Hash import SHA


class DSA:
    def __init__(self, message):
        """
        Constructor. Prepares private key and hash of message.
        """
        self.key = dsa.generate(1024)
        byte_message = message.encode("utf8")
        self.hash_obj = SHA.new(byte_message)

    def get_public_key(self):
        """
        Getter for public key.
        """
        return self.key.publickey()

    def get_hash_object(self):
        """
        Getter for hash object
        """
        return self.hash_obj

    def sign(self):
        """
        Method making signature for later validation of hash
        INPUTS - none
        RETURNS - signature
        """
        sig = DSS.new(self.key, 'fips-186-3')
        signature = sig.sign(self.hash_obj)
        return signature


def verify(public_key, hash_obj, signature):
    """
    Verification of hash object (displays info to console)
    INPUTS - public_key, hash_object, signature
    RETURNS - 1 if passed validation and 0 if not
    """
    verifier = DSS.new(public_key, 'fips-186-3')

    try:
        verifier.verify(hash_obj, signature)
        print("Oki")
        return 1
    except ValueError:
        print("Incorrect signature")
        return 0


if __name__ == '__main__':
    message = 'Hello'.encode("utf8")

    c = DSA(message)

    signature = c.sign()

    verify(c.get_public_key(), c.get_hash_object(), signature)
