import json
import os
import socket
import threading
import re

def handle_client(connection, address):
    print(f"Connected to {address}")
    try:
        while True:
            data_received = connection.recv(1024)
            if not data_received:
                break
            print(f"Received from {address}: {data_received.decode()}")
            # Respond to file metadata request
            if data_received == b"GET_METADATA":
                metadata = file_metadata("your_directory_path_here")  # Change this to your directory path
                connection.sendall(json.dumps(metadata).encode())
            else:
                connection.sendall(data_received)
    except Exception as e:
        print(f"Error with {address}: {e}")
    finally:
        print(f"Disconnected from {address}")

def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    print(f"Server started on {ip}:{port}")

    while True:
        client_socket, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()

def file_metadata(directory):
    metadata = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            if "chunk" in filename:
                chunks = set()
                max_chunk_number = 0
                pattern = re.compile(r'chunk(\d+)_of_(\d+)')
                match = pattern.search(filename)
                if match:
                    chunk_number = int(match.group(1))
                    total_chunks = int(match.group(2))
                    chunks.add(chunk_number)
                    max_chunk_number = max(max_chunk_number, chunk_number)
                metadata[filename] = {
                    "chunks": sorted(chunks),
                    "max_chunk_number": max_chunk_number,
                    "total_chunks": total_chunks
                }
    return metadata

if __name__ == "__main__":
    start_server('your_server_ip', 12345)  # Change 'your_server_ip' to your server's IP address
