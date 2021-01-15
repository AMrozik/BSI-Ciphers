import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('0.0.0.0', 8080))

client.send(b"I am Client\n")

server_msg = client.recv(4096)

client.close()

print(server_msg)