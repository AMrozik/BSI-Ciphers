__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from Crypto.Hash import SHA256
import random


def Hash(message):
    """
    Hashes given message
    take string object
    returns hashed value using sha256
    """
    return SHA256.new(data=message.encode("utf=8")).hexdigest()


def Salted_Hash(message, salt_value=None):
    """
    Hashes given message extended by salt
    if no salt value given random salt is generated
    """
    gen_core = [chr(i) for i in range(65, 91)] + [chr(j) for j in range(48, 58)]
    print(gen_core)
    if salt_value is None:
        salt_value = "".join([random.choice(gen_core) for i in range(16)])
    to_hash = message + salt_value
    return SHA256.new(data=to_hash.encode("utf=8")).hexdigest()


def ask_for_data(key_bit_size=8):
    """
    Gathers data from user and pass them to factory \n
    INPUT - <int> (default = 8) encoding function key bit size\n
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
    INPUTS - <str> key, <str> message
    RETURNS - <bytearray> key, <bytes> message
    """
    key_bytearray = bytearray()
    key_bytearray.extend(map(ord, key))

    message_bytes = bytes(message, 'utf-8')

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


def ask_for_data_asy():
    """
    Functiona that asks for data used by asymetric algorythms
    INPUTS - none
    RETURNS - <str> message
    """
    print("Tell me you's message")
    message = input(">")
    return message


if __name__ == '__main__':
    print(Salted_Hash("Alice"))