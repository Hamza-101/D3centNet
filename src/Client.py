
import os
import re
import json
import socket

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

def receive_file(server_socket, file_name, chunks, max_chunks):
    directory_path = os.path.join(Config["FilesPath"], file_name)
    if not os.path.isdir(directory_path):
        os.makedirs(directory_path)
    while True:
        chunk_data = server_socket.recv(1024)
        if not chunk_data:
            break
        for chunk_index in chunks:
            chunk_file_path = os.path.join(directory_path, f"chunk{chunk_index}_of_{max_chunks}")
            with open(chunk_file_path, "wb") as chunk_file:
                chunk_file.write(chunk_data)
            break

def fetch_file_chunks(filename):
    ip_chunks_map = get_file_chunks_details(filename)
    if not ip_chunks_map:
        print(f"No chunk details found for file {filename} in {Config['MetaData']}")
        return
    file_directory = os.path.join(Config["FilesPath"], filename)
    if not os.path.exists(file_directory):
        os.makedirs(file_directory)
    existing_chunks = set()
    if os.path.isdir(file_directory):
        for chunk_filename in os.listdir(file_directory):
            chunk_match = re.match(r'chunk(\d+)_of_\d+', chunk_filename)
            if chunk_match:
                existing_chunks.add(int(chunk_match.group(1)))
    total_chunks = 0
    for ip, chunks in ip_chunks_map.items():
        total_chunks = max(total_chunks, max(chunks))
    for ip, chunks in sorted(ip_chunks_map.items(), key=lambda item: len(item[1]), reverse=True):
        for chunk_index in chunks:
            if chunk_index in existing_chunks:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((ip, Config["Port"]))
                    request = f"Fetch:{filename}:{chunk_index}"
                    s.send(request.encode())
                    chunk_file_path = os.path.join(file_directory, f"chunk{chunk_index}_of_{total_chunks}")
                    with open(chunk_file_path, "wb") as chunk_file:
                        while True:
                            chunk_data = s.recv(4096)
                            if not chunk_data:
                                break
                            chunk_file.write(chunk_data)
                    existing_chunks.add(chunk_index)
                    print(f"Chunk {chunk_index} fetched from {ip}")
                    if len(existing_chunks) == total_chunks:
                        print(f"All chunks for {filename} have been fetched.")
                        return
            except (ConnectionRefusedError, socket.timeout):
                print(f"Failed to connect to {ip} to fetch chunk {chunk_index}.")
                continue
    if len(existing_chunks) < total_chunks:
        print(f"Unable to fetch all chunks for {filename}. Missing chunks: {set(range(1, total_chunks + 1)) - existing_chunks}")

def get_file_chunks_details(filename):
    if not os.path.isfile(Config["MetaData"]):
        return {}
    with open(Config["MetaData"], 'r') as f:
        metadata = json.load(f)
    file_chunks = {}
    for ip, files in metadata.items():
        if filename in files:
            file_chunks[ip] = files[filename]["chunks"]
    return file_chunks

def connect_to_server(server_ip, request):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, Config["Port"]))
            s.send(request.encode())
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"Error occurred: {e}")

def main():
    ensure_files_exist()
    while True:
        try:
            filename = input("Enter the file name: ")
            fetch_file_chunks(filename)
        except Exception as e:
            print(f"Error occurred: {e}")

if __name__ == "__main__":
        main()
