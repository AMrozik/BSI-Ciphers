import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# TODO: UI to jest czad

key = RSA.generate(1024)
my_kurwa_key = PKCS1_OAEP.new(key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('0.0.0.0', 8080))

client.send(key.publickey().exportKey())

server_msg = client.recv(4096)

server_key = RSA.importKey(client.recv(4096))
server_key = PKCS1_OAEP.new(server_key)
encrypted_shit = server_key.encrypt("chuj ci w dupe tez".encode())


msg = client.recv(4096)
print(msg)
print(len(msg))
print(my_kurwa_key.decrypt(msg))


client.send(bytes(encrypted_shit))


client.close()

print(server_msg)