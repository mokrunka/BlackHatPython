import socket
import threading

IP = '0.0.0.0'
PORT = 80

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((IP, PORT))


def start_server():
    server.listen()
    print(f"[LISTENING] on {IP}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn,))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}\n")


def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'i acknowledge your test things')


print("[STARTING] server is starting...")
start_server()
