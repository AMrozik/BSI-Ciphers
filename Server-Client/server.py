import socket
import signal, os

# https://docs.python.org/3/howto/sockets.html

def handler(signum, frame):
    print("Shutting down")
    exit(0)


# create an INET, STREAMing socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# bind the socket to a public host, and a well-known port
serversocket.bind(('0.0.0.0', 8080))
# become a server socket
serversocket.listen(5)

while True:
    signal.signal(signal.SIGINT, handler)
    connection, addr = serversocket.accept()

    while True:
        data = connection.recv(4096)
        if not data: break
        client_msg = str(data)
        print(client_msg)

        connection.send(b"I am Server\n")
    connection.close()
    print("client disconnected")
