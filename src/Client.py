import socket
import threading
import datetime
import os
import json
import re

Config = {
    "Devices": "devices.json",
    "AbortedTransfer": "aborted_transfer.json",
    "TransferLog": "transfer_log.json",
    "MetaData": "metadata.json"
}

def _files_exist():
    for file in [Config["Devices"], Config["AbortedTransfer"], Config["TransferLog"], Config["MetaData"]]:
        if not os.path.isfile(file):
            with open(file, 'w') as f:
                json.dump({}, f)

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

def send_file_metadata(client_socket, directory):
    metadata = file_metadata(directory)
    metadata_json = json.dumps(metadata)
    client_socket.send(metadata_json.encode())

def send_file_chunk(client_socket, filename, chunk_number):
    chunk_filename = f"{filename}_chunk{chunk_number}_of_{chunk_number}"
    if os.path.isfile(chunk_filename):
        with open(chunk_filename, 'rb') as f:
            chunk_data = f.read()
        client_socket.sendall(chunk_data)
    else:
        client_socket.sendall(b'')

def handle_echo(data, client_socket):
    heartbeat_status(client_socket)
    heartbeat = heartbeat_check(client_socket)
    if heartbeat == 200:
        return f"Echo: {data}"
    else:
        return "Heartbeat check failed"

def handle_time(client_socket):
    _files_exist()
    send_file_metadata(client_socket, ".")
    return f"Server time: {datetime.datetime.now()}"

def handle_reverse(data):
    return f"Reversed: {data[::-1]}"

def heartbeat_check(client_socket):
    heartbeat = int(client_socket.recv(1024).decode())
    return heartbeat

def heartbeat_status(client_socket):
    heartbeat_signal = str(200)
    client_socket.send(heartbeat_signal.encode())

def client_handler(conn, addr):
    print(f"Connected by {addr}")
    with conn:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            command, *params = data.split()
            if command == "ECHO":
                response = handle_echo(" ".join(params), conn)
            elif command == "TIME":
                response = handle_time(conn)
            elif command == "REVERSE":
                response = handle_reverse(" ".join(params))
            elif command == "REQUEST_CHUNK":
                filename, chunk_number = params
                send_file_chunk(conn, filename, int(chunk_number))
                continue  # No need to send a standard response for this command
            else:
                response = "Unknown command"

            if command != "TIME" and command != "REQUEST_CHUNK":  # Send the response only for non-TIME and non-REQUEST_CHUNK commands
                conn.sendall(response.encode())

def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=client_handler, args=(conn, addr))
            thread.start()

if __name__ == "__main__":
    start_server()
