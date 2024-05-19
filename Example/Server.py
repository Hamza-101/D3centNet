import socket
import threading
from datetime import datetime

def handle_client(client_socket):
    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break
        print(f"Received from client: {data}")

        if data == "Hello":
            response = "Hi there!"
        elif data == "Time":
            response = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elif data == "Bye":
            response = "Goodbye!"
            client_socket.sendall(response.encode())
            break
        else:
            response = "Unknown command"

        client_socket.sendall(response.encode())
    
    client_socket.close()

def server_program():
    host = '127.0.0.1'  # localhost
    port = 5000  # port to listen on

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Server is listening...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} has been established.")
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    server_program()
