import os
import json
import socket
import threading
import time

Directories = {
    "Path": "./Files",
    "NetworkDevices": "network_devices.json",
    "YellowBook": "yellowbook.json",
    "HeartBeat_Port": 12345
}

def scan_network():
    devices = {}
    while True:
        try:
            for ip in range(1, 256):
                address = f"192.168.1.{ip}"
                if address != "192.168.1.1" and is_port_open(address):
                    devices[address] = {"Status": "1"}  # Alive

            DeviceLog(devices)

            for ip in devices.keys():
                get_files_info(ip)

            time.sleep(30)
        except KeyboardInterrupt:
            break

def is_port_open(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex((ip, Directories["HeartBeat_Port"]))
        return result == 0

def DeviceLog(devices):
    if not os.path.exists(Directories["NetworkDevices"]):
        with open(Directories["NetworkDevices"], 'w') as f:
            json.dump({}, f)

    with open(Directories["NetworkDevices"], 'w') as f:
        json.dump(devices, f, indent=4)

def get_files_info(ip):
    # Placeholder function. Implement logic to fetch file info from the device.
    pass

def MetaData():
    try:
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

    except Exception as e:
        print(f"Error: {e}")
        return None

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

def FileDetails():
    hostname = socket.gethostname()
    LocalIP = socket.gethostbyname(hostname)

    deviceIP = LocalIP

    Info = MetaData()
    if Info is None:
        return

    existing_info = {}

    if os.path.exists(Directories["YellowBook"]):
        with open(Directories["YellowBook"], 'r') as f:
            existing_info = json.load(f)

    existing_info[deviceIP] = Info

    with open(Directories["YellowBook"], 'w') as f:
        json.dump(existing_info, f, indent=4)

def SendChunks(client_socket, filename, chunknumbers):
    for chunk_number in chunknumbers:
        chunk_filename = f"chunk{chunk_number}_of_{len(chunknumbers)}"
        chunk_path = os.path.join(Directories["Path"], chunk_filename)

        if os.path.exists(chunk_path):
            with open(chunk_path, 'rb') as chunk_file:
                chunk_data = chunk_file.read()
                client_socket.sendall(chunk_data)
            client_socket.sendall(b"-------")
        else:
            print(f"Chunk {chunk_number} does not exist.")

def HandleCommand(client_socket):
    commands = []
    while True:
        try:
            command = client_socket.recv(1024).decode().strip()
            if command == "-------":
                break
            else:
                commands.append(command)
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None

    # Process the received commands here
    return

def client_handler(client_socket, addr):
    print(f"Connection from {addr}")
    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break
        # Process data and respond
        HandleCommand(client_socket)
    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', Directories["HeartBeat_Port"]))
    server_socket.listen(5)
    print("Server listening...")

    while True:
        client_socket, addr = server_socket.accept()
        client_thread = threading.Thread(target=client_handler, args=(client_socket, addr))
        client_thread.start()

if __name__ == "__main__":
    if not os.path.exists(Directories["YellowBook"]):
        with open(Directories["YellowBook"], 'w') as f:
            json.dump({}, f)

    if not os.path.exists(Directories["NetworkDevices"]):
        with open(Directories["NetworkDevices"], 'w') as f:
            json.dump({}, f)

    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    scan_thread = threading.Thread(target=scan_network)
    scan_thread.start()
