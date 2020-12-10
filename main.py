from Crypto.Cipher import AES, Blowfish
from struct import pack
from des import DesKey

# pip install pycryptodome
# pip install des


def AES_encode(key, message):
    cipher = AES.new(key, AES.MODE_EAX)

    nonce = cipher.nonce

    # String to bytearray required by encrypt function
    msg = bytearray()
    msg.extend(map(ord, message))

    ciphertext, tag = cipher.encrypt_and_digest(msg)

    return nonce, ciphertext


def AES_decode(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext


def Bf_encode(key, message):
    bs = Blowfish.block_size
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    plen = bs - len(message) % bs
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    msg = cipher.iv + cipher.encrypt(message + padding)
    return msg


def Bf_decode(key, ciphertext):
    bs = Blowfish.block_size
    iv = ciphertext[:bs]
    ciphertext = ciphertext[bs:]

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    msg = cipher.decrypt(ciphertext)

    last_byte = msg[-1]
    msg = msg[:- (last_byte if type(last_byte) is int else last_byte)]
    return repr(msg)


def DES_encode(key, message):
    key0 = DesKey(key)
    ciphertext = key0.encrypt(message, padding=True)
    return ciphertext


def DES_decode(key, ciphertext):
    key0 = DesKey(key)
    msg = key0.decrypt(ciphertext, padding=True)
    return msg


if __name__ == '__main__':
    # def pad(text):
    #     n = len(text) % 8
    #     return text + (b' ' * n)
    #
    #
    # key = b'hello123'
    # text1 = b'Python is the Best Language!'
    #
    # des = DES.new(key, DES.MODE_ECB)
    #
    # padded_text = pad(text1)
    # encrypted_text = des.encrypt(padded_text)
    #
    # print(encrypted_text)
    # print(des.decrypt(encrypted_text))


    key = b'klucz123'
    message = b'BSI to fajny przedmiot'

    # DES
    szyfr_des = DES_encode(key, message)
    print(szyfr_des)
    message = DES_decode(key, szyfr_des)
    print(message)

    # BlowFish
    szyfr_bf = Bf_encode(key, message)
    print(szyfr_bf)
    message = Bf_decode(key, szyfr_bf)
    print(message)

    # AES
    key = b"16 bytes key aes"
    nonce, szyfr_aes = AES_encode(key, message)
    print(szyfr_aes)
    message = AES_decode(key, nonce, szyfr_aes)
    print(message)

#     TODO:
#         try again to use DES from pycryptodome module
#         CLI
#         handle exceptions about key length basically everywhere
#         documentation
#         make it OO, SOLID and DRY
#         header with authors and quick documentation of algorithms
#         sources of cipher modules

