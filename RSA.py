import rsa
import CryptoUtils as Cu


class RSA:

    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)

    def encrypt(self, message):
        byte_message = message.encode("utf-8")
        crypto = rsa.encrypt(byte_message, self.public_key)
        return crypto

    def get_public_key(self):
        return self.public_key

    def decrypt(self, message):
        return rsa.decrypt(message, self.private_key).decode("utf-8")


if __name__ == '__main__':
    c = RSA()

    encoded = c.encrypt("Ala ma kota")

    decoded = c.decrypt(encoded)

    print(Cu.Hash(decoded))
    print(Cu.Salted_Hash(decoded))