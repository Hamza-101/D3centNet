import os
import json
import socket
import threading
from datetime import datetime

# Move to another file
Directories = {
    "Path": "Files",
    "YellowBook": "yellowbook.json",
    "NetworkDevices": "network_devices.json",
    "HeartBeat_Port": 5001
}

# Backup

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode().strip()
            if not data:
                break
            
            if data == "UpdateFiles":
                update_files(client_socket)
            elif data.startswith("GetFile"):
                _, filename, chunks = data.split(',')
                chunk_numbers = list(map(int, chunks.split()))
                send_chunks(client_socket, filename, chunk_numbers)
            elif data == "Heartbeat":
                client_socket.sendall("Alive".encode())
            else:
                client_socket.sendall("Unknown command".encode())
        except Exception as e:
            print(f"Error handling client: {e}")
            break
    
    client_socket.close()

def update_files(client_socket):
    metadata = MetaData()
    client_socket.sendall(json.dumps(metadata).encode())

def send_chunks(client_socket, filename, chunknumbers):
    for chunk_number in chunknumbers:
        chunk_filename = f"chunk{chunk_number}_of_{len(chunknumbers)}"
        chunk_path = os.path.join(Directories["Path"], chunk_filename)
        
        if os.path.exists(chunk_path):
            with open(chunk_path, 'rb') as chunk_file:
                chunk_data = chunk_file.read()
                client_socket.sendall(chunk_data)
                client_socket.sendall(b"-------")
        else:
            client_socket.sendall(f"Chunk {chunk_number} does not exist.".encode())

def MetaData():
    if not os.path.exists(Directories["Path"]):
        print(f"Error: Directory {Directories['Path']} does not exist.")
        return None
    
    subdirectories = [name for name in os.listdir(Directories["Path"]) if os.path.isdir(os.path.join(Directories["Path"], name))]
    directory_info = {}
    for subdirectory_name in subdirectories:
        subdirectory_path = os.path.join(Directories["Path"], subdirectory_name)
        subdirectory_files = os.listdir(subdirectory_path)
        
        file_name = subdirectory_name
        max_chunks, available_chunks = ChunkInfo(subdirectory_files)
                    
        directory_info[file_name] = {
            'max_chunks': max_chunks,
            'available_chunks': available_chunks
        }
    
    return directory_info

def ChunkInfo(subdirectory_files):
    max_chunks = 0
    available_chunks = set()
    for file_name in subdirectory_files:
        parts = file_name.split('_')
        if len(parts) >= 3 and parts[-2] == 'of':
            try:
                chunk_number = int(parts[-1])
                max_chunks = max(max_chunks, chunk_number)
                available_chunks.add(chunk_number)
            except ValueError:
                pass
    return max_chunks, sorted(available_chunks)

def server_program():
    host = '0.0.0.0'
    port = Directories["HeartBeat_Port"]

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server is listening on port {port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} has been established.")
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    server_program()
