import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# Create key and public key for client
key = RSA.generate(1024)
private_key = PKCS1_OAEP.new(key)

# Setting up socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((sys.argv[1], 8080))
except IndexError:
    client.connect(('0.0.0.0', 8080))

# Handshaking
client.send(key.publickey().exportKey())
server_key = RSA.importKey(client.recv(4096))
server_key = PKCS1_OAEP.new(server_key)
print("Handshaking - DONE")

# Message to send
print("Type your message")
msg = input(">")
msg = server_key.encrypt(msg.encode())
client.send(bytes(msg))

client.close()
