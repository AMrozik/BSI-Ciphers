__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from des import DesKey

def DES_encode(key, message):
    """
    Encrypting function for DES algorithm \n
    INPUT -  <bytearray> key, <bytes> message to encrypt \n
    RETURN - encrypted <bytes> message
    """

    key0 = DesKey(key)
    ciphertext = key0.encrypt(message, padding=True)
    return ciphertext


def DES_decode(key, ciphertext):
    """
    Decrypting function for DES algorithm \n
    INPUT - <bytearray> key, <bytes> message to decrypt \n
    RETURN - decrypted <bytes> message
    """

    key0 = DesKey(key)
    msg = key0.decrypt(ciphertext, padding=True)
    return msg
