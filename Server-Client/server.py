import socket
import signal
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# https://docs.python.org/3/howto/sockets.html


def handler(signum, frame):
    '''
    Handling Ctrl+C to shutdown sever.
    '''

    print("\nShutting down")
    exit(0)


def setup_socket(ipv4, port):
    '''
    Setting up socket on ipv4 and port form arguments. Returns connection.
    '''
    # create an INET, STREAMing socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to a public host, and a well-known port
    server_socket.bind((ipv4, port))
    # turning on listening on this socket
    server_socket.listen(5)

    return server_socket


def handshaking():
    '''
    Handshaking with client. Returns None if failed.
    '''
    try:
        # receive client public key
        received_key = RSA.importKey(connection.recv(4096))
        received_key = PKCS1_OAEP.new(received_key)
        # send my public key
        connection.send(key.publickey().exportKey())

    except ValueError and IndexError and TypeError:
        received_key = None

    return received_key


def receive_message(size, decryption_key):
    message = connection.recv(size)
    decryption_key.decrypt(message)
    print(message)
    return message
    # .decode("utf-8")


if __name__ == "__main__":
    # Signal to close server (might be redo with console input)
    signal.signal(signal.SIGINT, handler)

    # Setup socket
    socket = setup_socket('0.0.0.0', 8080)
    print("Setting up socket - DONE")

    # Setting key and public key for server
    key = RSA.generate(1024)
    private_key = PKCS1_OAEP.new(key)
    print("Generating keys - DONE")

    # Server main loop
    print("Server is ready\n")
    while True:
        connection, address = socket.accept()
        print("Accepting connection from: {}".format(address))

        # # Make handshake with client
        client_key = handshaking()
        if client_key is None:
            print("Handshaking failed. Closing connection")
            connection.close()
        else:
            print("Handshaking - DONE")

        # Receiving message form client
        msg = connection.recv(4096)
        msg = private_key.decrypt(msg)
        print("Client's message: {}".format(msg.decode("utf-8")))

        # Closing connection
        connection.close()
        print("client disconnected")
main()
