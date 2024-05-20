
import os
import re
import json
import socket
import threading

Config = {
    "FilesPath": "Files",
    "Devices": "devices.json",
    "AbortedTransfer": "aborts.json",
    "TransferLog": "transfers.json",
    "MetaData": "details.json",
    "HeartbeatPort": 5000,
    "Port": 1234,
    "HeartbeatInterval": 15,
    "MetadataClock": 25,
    "BackupCheck": 15
}

def ensure_files_exist():
    for file in [Config["Devices"], Config["AbortedTransfer"], Config["TransferLog"], Config["MetaData"]]:
        if not os.path.isfile(file):
            with open(file, 'w') as f:
                json.dump({}, f)

def file_metadata(directory):
    file_metadata = {}
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
                file_metadata[filename] = {
                    "chunks": sorted(chunks),
                    "max_chunk_number": max_chunk_number,
                    "total_chunks": total_chunks
                }
    return file_metadata

def send_file_metadata(client_socket, directory):
    file_metadata = file_metadata(directory)
    metadata_json = json.dumps(file_metadata)
    client_socket.send(metadata_json.encode())

def receive_file_metadata(server_socket, address):
    metadata_json = server_socket.recv(4096).decode()
    file_metadata = json.loads(metadata_json)
    if os.path.isfile(Config["MetaData"]):
        with open(Config["MetaData"], 'r') as f:
            existing_metadata = json.load(f)
    else:
        existing_metadata = {}
    existing_metadata[address[0]] = file_metadata
    with open(Config["MetaData"], 'w') as f:
        json.dump(existing_metadata, f)

def send_file(client_socket, file_name, chunks):
    file_path = os.path.join(Config["FilesPath"], file_name)
    if os.path.isdir(file_path):
        for chunk_index in chunks:
            pattern = re.compile(rf"chunk{chunk_index}_of_\d+")
            for filename in os.listdir(file_path):
                if pattern.match(filename):
                    chunk_file_path = os.path.join(file_path, filename)
                    with open(chunk_file_path, "rb") as chunk_file:
                        chunk_data = chunk_file.read()
                        client_socket.send(chunk_data)
                    break
            else:
                print(f"Chunk file for index {chunk_index} not found.")
    else:
        print(f"File {file_name} not found.")

def heartbeat_check(client_socket):
    heartbeat = int(client_socket.recv(1024).decode())
    return heartbeat

def heartbeat_status(client_socket):
    heartbeat_signal = str(200)
    client_socket.send(heartbeat_signal.encode())

def handle_request(request, data):
    if request == "Echo":
        heartbeat_check(data)
    else:
        filename, chunks = extract_info(data)
        if request == "Fetch":
            send_file(data['client_socket'], filename, chunks)

def extract_info(data):
    filename, chunks_str = data.split(':', 1)
    chunks = list(map(int, chunks_str.split(',')))
    return filename, chunks

def inject_info(filename, chunks):
    return f"{filename}:{','.join(map(str, chunks))}"

def existing_chunks(filename):
    file_path = os.path.join(Config["FilesPath"], filename)
    if os.path.isdir(file_path):
        chunk_indices = []
        for chunk_filename in os.listdir(file_path):
            match = re.match(r'chunk(\d+)_of_\d+', chunk_filename)
            if match:
                chunk_indices.append(int(match.group(1)))
        return chunk_indices if chunk_indices else [0]
    else:
        return [0]

def handle_file(filename):
    chunks = existing_chunks(filename)
    file_details = inject_info(filename, chunks)
    if isinstance(chunks, list) and len(chunks) == 1 and chunks[0] == 0:
        handle_request("Fetch", file_details)
    else:
        handle_request("Fetch", file_details)

def connect_client(client_socket, client_address):
    print(f"Accepted connection from {client_address}")
    try:
        while True:
            request_data = client_socket.recv(4096)
            if not request_data:
                break
            request_str, data_str = request_data.decode().split(':', 1)
            request = request_str.strip()
            data = {"client_socket": client_socket, "data": data_str.strip()}
            handle_request(request, data)
    except ConnectionResetError:
        print(f"Connection reset by {client_address}")
    finally:
        print(f"Closed connection from {client_address}")
        client_socket.close()

def server():
    ensure_files_exist()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', Config["Port"]))
    server_socket.listen(5)
    print(f"Server listening on port {Config['Port']}")
    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=connect_client, args=(client_socket, client_address))
        client_thread.start()

def main():
    server_thread = threading.Thread(target=server)
    server_thread.start()
    server_thread.join()

if __name__ == "__main__":
    main()
