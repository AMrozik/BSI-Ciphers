import socket
import signal, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# https://docs.python.org/3/howto/sockets.html

def handler(signum, frame):
    print("Shutting down")
    exit(0)

signal.signal(signal.SIGINT, handler)

# create an INET, STREAMing socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# bind the socket to a public host, and a well-known port
serversocket.bind(('0.0.0.0', 8080))
# become a server socket
serversocket.listen(5)

key = RSA.generate(1024)
my_kurwa_key = PKCS1_OAEP.new(key)

while True:

    connection, addr = serversocket.accept()

    try:
        client_key = RSA.importKey(connection.recv(4096))
        client_key = PKCS1_OAEP.new(client_key)
        encrypted_shit = client_key.encrypt("chuj ci w dupe".encode())
        connection.send(b"Handshaking...")
        connection.send(key.publickey().exportKey())

    except ValueError and IndexError and TypeError:
        print("kij ci w pupe") # TODO: napisać coś milszego xD

    print(encrypted_shit)
    connection.send(bytes(encrypted_shit))
    print(len(encrypted_shit))

    msg = connection.recv(4096)
    print(my_kurwa_key.decrypt(msg))


    # while True:
    #     data = connection.recv(4096)
    #     if not data: break
    #     client_msg = str(data)
    #     print(client_msg)

    # connection.send(b"I am Server\n")
    connection.close()
    print("client disconnected")
