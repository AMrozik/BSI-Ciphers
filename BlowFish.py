__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from Crypto.Cipher import Blowfish
from struct import pack


def Bf_encode(key, message):
    """
    Encrypting function for Blowfish algorithm \n
    INPUT - <bytearray> key, <bytes> message to encrypt \n
    RETURN - encrypted <bytes> message
    """

    bs = Blowfish.block_size
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    plen = bs - len(message) % bs
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    msg = cipher.iv + cipher.encrypt(message + padding)
    return msg


def Bf_decode(key, ciphertext):
    """
    Decrypting function for Blowfish algorithm \n
    INPUT - <bytearray> key, <bytes> message to decrypt \n
    RETURN - decrypted <bytes> message
    """

    bs = Blowfish.block_size
    iv = ciphertext[:bs]
    ciphertext = ciphertext[bs:]

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    msg = cipher.decrypt(ciphertext)

    last_byte = msg[-1]
    msg = msg[:- (last_byte if type(last_byte) is int else last_byte)]
    return repr(msg)
