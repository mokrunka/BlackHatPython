import socket

target_host = "127.0.0.1"
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client to the target
client.connect((target_host, target_port))

# send some test data
client.send(b'here is some test things to send to the server')

# receive the response
response = client.recv(4096)

print(f'[RECEIVED] {response.decode()}')
client.close()