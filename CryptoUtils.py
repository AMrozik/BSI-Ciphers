__author__ = "Kamil Skrzypkowski, Andrzej Mrozik"

from Crypto.Hash import SHA256
import hashlib


def Hash(message):
    return SHA256.new(data=message.encode("utf=8")).hexdigest()


def Salted_Hash(message, salt_value="235GDA6Y6256234BGH54367JHS"):
    to_hash = message + salt_value
    return SHA256.new(data=to_hash.encode("utf=8")).hexdigest()
