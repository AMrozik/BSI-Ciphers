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

RSA - The RSA algorithm involves four steps: key generation, key distribution, encryption, and decryption.

    A basic principle behind RSA is the observation that it is practical to find three very large positive integers e, d,
    and n, such that with modular exponentiation for all integers m (with 0 ≤ m < n):

    (m^e)^d ≡ m*(mod n)

    and that knowing e and n, or even m, it can be extremely difficult to find d. The triple bar (≡) here denotes modular
    congruence.

    In addition, for some operations it is convenient that the order of the two exponentiations can be changed and that
    this relation also implies:

    (m^d)^e ≡ m*(mod n)

    RSA involves a public key and a private key. The public key can be known by everyone, and it is used for encrypting messages.
    The intention is that messages encrypted with the public key can only be decrypted in a reasonable amount of time by using
    the private key. The public key is represented by the integers n and e; and, the private key, by the integer d (although n
    is also used during the decryption process, so it might be considered to be a part of the private key, too). m represents the
    message (previously prepared with a certain technique explained below).

DSA - Validates hash object with public key and signature (made out of hash object + private key)


sources:
https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
https://pypi.org/project/des/
https://pycryptodome.readthedocs.io/en/latest/src/cipher/blowfish.html
https://stuvel.eu/python-rsa-doc/usage.html

# pip install pycryptodome
# pip install des
# pip install rsa
"""

__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from AES import *
from DES import *
from BlowFish import *
from RSA import *
from DSA import *
import time
from CryptoUtils import *

if __name__ == '__main__':

    while True:
        print("What type of cipher do you want? \n"
              "1.Symetric\n"
              "2.Asymetric \n"
              "0.Exit")
        console_in = input(">")

        # Symetric
        if console_in == "1" or console_in == "Symetric" or console_in == "s":
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

                # BlowFish
                key, message = ask_for_data()
                szyfr_bf = Bf_encode(key, message)
                print("Zaszyfrowana wiadomosc: ")
                print(szyfr_bf)
                message = Bf_decode(key, szyfr_bf)
                print("Odszyfrowana wiadomosc: " + message_back_to_string(message))
                print()

            elif console_in == "3" or console_in == "AES" or console_in == "aes":

                # AES
                key, message = ask_for_data(16)
                nonce, szyfr_aes = AES_encode(key, message)
                print("Zaszyfrowana wiadomosc: ")
                print(szyfr_aes)
                message = AES_decode(key, nonce, szyfr_aes)
                print("Odszyfrowana wiadomosc: " + message_back_to_string(message))
                print()

        # Asymetric
        elif console_in == "2" or console_in == "Asymetric" or console_in == "a":
            print("What cipher function you want to use? \n"
                  "1.RSA \n"
                  "2.DSA")
            console_in = input(">")

            if console_in == "1" or console_in == "RSA" or console_in == "rsa":
                print("RSA")

                # There are two correspondents, everyone has own tuple (public_key, private_key)
                Alice = RSA()
                Bob = RSA()

                # Before any communication they must exchange their public keys
                temp_key = Alice.get_public_key()
                Alice.set_public_key(Bob.get_public_key())
                Bob.set_public_key(temp_key)
                del temp_key

                message = ask_for_data_asy()

                # Now Alice can send message encrypted by Bob's public key so he can read it
                # and vice versa
                encoded = Alice.encrypt(message)
                print("Message encoded: ", encoded)

                decoded = Bob.decrypt(encoded)
                print("Message decoded: ", decoded)

                start = time.time()
                dec = Bob.encrypt("Alice have a cat")
                Alice.decrypt(dec)
                print("execution time: ", time.time() - start)

                print("Hashed message: ", Hash(message))
                print("Salted message: ", Salted_Hash(message))

            elif console_in == "2" or console_in == "DSA" or console_in == "dsa":
                print("DSA")
                message = ask_for_data_asy()

                start = time.time()
                dsa = DSA(message)

                signature = dsa.sign()
                verify(dsa.get_public_key(), dsa.get_hash_object(), signature)
                print("execution time: ", time.time() - start)

                print("Hashed message: ", Hash(message))
                print("Salted message: ", Salted_Hash(message))

        # Exiting
        elif console_in == "0" or console_in == "Exit" or console_in == "exit" \
                or console_in == "EXIT" or console_in == "e":
            break

        else:
            print("Nie ma takiej opcji")
