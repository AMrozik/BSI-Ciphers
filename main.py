"""
Quick documentation
AES -   XOR on each state byte and round key byte
        for each round (defined by key)
            change each bate with another from lookup table
            shift rows by it's number
            multiply each column linearly
        repeat all till last round
        do steps "for each round" without multiplication

Blowfish -  Algorithm splits the 32-bit input into four eight-bit quarters, and uses the quarters as input to the S-boxes
            The S-boxes accept 8-bit input and produce 32-bit output
            The outputs are added modulo 2^32 and XORed to produce the final 32-bit output

DES -   First text is separated in 64 bit block (for making it easier for machines to encript it)
        Algorithm with 16 cycles works on two 32 bit sized sides of block and does the Feistel's functions on them,
        then two parts are combined in 64 bit block
        Lastly makes final permutation
"""

__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from Crypto.Cipher import AES, Blowfish
from struct import pack
from des import DesKey

# pip install pycryptodome
# pip install des


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


def ask_for_data(key_bit_size=8):
    """
    Gathers data from user and pass them to factory \n
    INPUT - <int> mode (0 - code, 1 - decode), <int> (default = 8) encoding function key bit size\n
    RETURN - <bytearray> key and <bytes> message
    """
    while True:
        print("Tell me the ", key_bit_size, "-bit key")
        key = str(input(">"))
        if len(key) < key_bit_size:
            print("The key is to short")
            print()

        elif len(key) > key_bit_size:
            print("The key is too long")
            print()

        else:
            break

    while True:
        print("Tell me your message")
        message = str(input(">"))

        if len(message) < 1:
            print("There is no message to encrypt")
            print()
        else:
            break

    key, message = key_n_message_factory(key, message)
    return key, message


def key_n_message_factory(key, message):
    """
    Factory that takes key and message and converts them into <byte> and <bytearray> \n
    INPUTS - <str> key, <str> message, <int> mode (0 - code, 1 - decode)
    RETURNS - <bytearray> key, <bytes> message
    """
    key_bytearray = bytearray()
    key_bytearray.extend(map(ord, key))

    # TODO: make something with this shit ! (wrong byte converion when \ is in text)
    # message_bytearray = bytearray()
    # message_bytearray.extend(map(ord, message))

    # if mode == 0:
    message_bytes = bytes(message, 'utf-8')
    # else:
    #     message_bytes = message

    return key_bytearray, message_bytes


def message_back_to_string(message):
    """
    Factory that converts message back to strings \n
    INPUTS - <bytes> message
    RETURNS - <str> message
    """
    message = str(message)
    message = message[2:-1]

    return message


if __name__ == '__main__':

    while True:
        print("What cipher function you want to use? \n"
            "1.DES \n"
            "2.Blowfish \n"
            "3.AES \n"
            "0.Exit")
        console_in = input(">")

        if console_in == "1" or console_in == "DES" or console_in == "des":

            # DES
            key, message = ask_for_data()
            szyfr_des = DES_encode(key, message)
            print("Zaszyfrowana wiadomosc: ")
            print(szyfr_des)
            message = DES_decode(key, szyfr_des)
            print("Odszyfrowana wiadomosc: " + message_back_to_string(message))
            print()

        elif console_in == "2" or console_in == "BlowFish" or console_in == "Blowfish" or console_in == "blowfish":
            key, message = ask_for_data()

            # BlowFish
            szyfr_bf = Bf_encode(key, message)
            print("Zaszyfrowana wiadomosc: ")
            print(szyfr_bf)
            message = Bf_decode(key, szyfr_bf)
            print("Odszyfrowana wiadomosc: " + message_back_to_string(message))
            print()

        elif console_in == "3" or console_in == "AES" or console_in == "aes":
            key, message = ask_for_data(16)

            # AES
            nonce, szyfr_aes = AES_encode(key, message)
            print("Zaszyfrowana wiadomosc: ")
            print(szyfr_aes)
            message = AES_decode(key, nonce, szyfr_aes)
            print("Odszyfrowana wiadomosc: " + message_back_to_string(message))
            print()

        elif console_in == "0" or console_in == "Exit" or console_in == "exit" or console_in == "EXIT" or console_in == "e":
            break

#     TODO:
#         handle exceptions about key length basically everywhere
#         make it OO, SOLID and DRY
#         sources of cipher modules

