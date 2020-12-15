from Crypto.Cipher import AES, Blowfish
from des import DesKey


def AES_encode(key, message):
    """
    Encrypting function for AES algorithm \n
    INPUT - <bytearray> key, <bytes> message to encrypt \n
    RETURN - nonce, encrypted <bytes> message
    """

    cipher = AES.new(key, AES.MODE_EAX)

    nonce = cipher.nonce

    # Bytes to bytearray required by encrypt function
    # msg = bytearray()
    # msg.extend(map(ord, message))

    ciphertext, tag = cipher.encrypt_and_digest(message)

    return nonce, ciphertext


def AES_decode(key, nonce, ciphertext):
    """
    Decrypting function for AES algorithm \n
    INPUT - <bytearray> key, nonce, <bytes> message to decrypt \n
    RETURN - decrypted <bytes> message
    """

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext
