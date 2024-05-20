import socket
import time
import json
import os

def heartbeat_check(client_socket):
    client_socket.send(str(200).encode())

def heartbeat_status(client_socket):
    return int(client_socket.recv(1024).decode())

def connect_to_server(ip, port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, port))
            print(f"Connected to {ip}:{port}")
            while True:
                command = input("Enter command (ECHO, TIME, REVERSE) or 'exit' to quit: ")
                if command.lower() == 'exit':
                    break
                s.sendall(command.encode())
                if command.startswith("TIME"):
                    metadata_json = s.recv(4096).decode()
                    file_metadata = json.loads(metadata_json)
                    print(f"Received file metadata: {file_metadata}")
                    check_and_request_missing_chunks(s, file_metadata)
                else:
                    if command.startswith("ECHO"):
                        heartbeat_check(s)
                        if heartbeat_status(s) == 200:
                            data = s.recv(1024).decode()
                            print(f"Received from server: {data}")
                        else:
                            print("Heartbeat check failed")
                    else:
                        data = s.recv(1024).decode()
                        print(f"Received from server: {data}")
        except socket.error as e:
            print(f"Failed to connect to {ip}:{port}, error: {e}")
            return False
    return True

def read_ips_from_file(file_path):
    with open(file_path, 'r') as file:
        ips = file.read().splitlines()
    return ips

def try_connecting_to_ips(file_path):
    ips = read_ips_from_file(file_path)
    for ip in ips:
        if connect_to_server(ip):
            return
    print("All connection attempts failed. Retrying in 30 seconds.")
    time.sleep(30)
    try_connecting_to_ips(file_path)

def check_and_request_missing_chunks(client_socket, file_metadata):
    for filename, metadata in file_metadata.items():
        local_chunks = set()
        for i in range(1, metadata['total_chunks'] + 1):
            chunk_filename = f"{filename}_chunk{i}_of_{metadata['total_chunks']}"
            if os.path.isfile(chunk_filename):
                local_chunks.add(i)
        
        missing_chunks = set(range(1, metadata['total_chunks'] + 1)) - local_chunks
        if missing_chunks:
            print(f"Missing chunks for {filename}: {missing_chunks}")
            for chunk in missing_chunks:
                client_socket.sendall(f"REQUEST_CHUNK {filename} {chunk}".encode())
                chunk_data = client_socket.recv(4096)
                if chunk_data:
                    chunk_filename = f"{filename}_chunk{chunk}_of_{metadata['total_chunks']}"
                    with open(chunk_filename, 'wb') as f:
                        f.write(chunk_data)
                    print(f"Saved missing chunk {chunk} for {filename}")

if __name__ == "__main__":
    ip_file_path = 'ips.txt'  # The file containing IP addresses to try
    try_connecting_to_ips(ip_file_path)
