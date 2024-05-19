import socket

def client_program():
    host = '127.0.0.1'  # server's IP address
    port = 5000  # server's port

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    while True:
        message = input("Enter command (Hello, Time, Bye, or other): ")
        client_socket.sendall(message.encode())
        
        data = client_socket.recv(1024).decode()
        print(f"Received from server: {data}")

        if message == "Bye":
            break

    client_socket.close()

if __name__ == "__main__":
    client_program()
