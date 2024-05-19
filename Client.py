import os
import json
import time
import socket
import threading

Directories = {
    "Path": "Files",
    "YellowBook": "yellowbook.json",
    "NetworkDevices": "network_devices.json",
    "HeartBeat_Port": 5001
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
            
            time.sleep(30)
        except KeyboardInterrupt:
            break

def is_port_open(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex((ip, Directories["HeartBeat_Port"]))
        return result == 0

def DeviceLog(devices):
    with open(Directories["NetworkDevices"], 'w') as f:
        json.dump(devices, f)

def FetchFile(client_socket, file, chunks):
    client_socket.sendall(f"GetFile,{file},{' '.join(map(str, chunks))}".encode())
    client_socket.sendall(b"-------")
    receive_chunks(client_socket, chunks)

def receive_chunks(client_socket, chunk_indices):
    os.makedirs(Directories["Path"], exist_ok=True)
    received_chunks = set()
    while not received_chunks.issubset(chunk_indices):
        chunk_data = client_socket.recv(1024)
        
        if chunk_data == b"-------":
            break
        
        chunk_number = len(received_chunks)
        chunk_filename = f"chunk{chunk_number}_of_{len(chunk_indices)}"
        output_path = os.path.join(Directories["Path"], chunk_filename)
        
        with open(output_path, 'wb') as chunk_file:
            chunk_file.write(chunk_data)
        
        received_chunks.add(chunk_number)
    
    print(f"Received {len(received_chunks)} chunks.")

def GetFile(filename):
    devices_with_chunks = []

    relevant_devices = {}
    with open(Directories["YellowBook"], "r") as file:
        transfer_meta = json.load(file)
        for ip, directory_info in transfer_meta.items():
            if filename in directory_info:
                chunks_info = directory_info[filename]["chunks"]
                relevant_devices[ip] = {
                    "chunks": chunks_info
                }

    for ip, directory_info in relevant_devices.items():
        total_chunks = len(directory_info["chunks"])
        devices_with_chunks.append((ip, total_chunks))
    
    sorted_devices = sorted(devices_with_chunks, key=lambda x: x[1], reverse=True)

    for server_ip, _ in sorted_devices:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_ip, Directories["HeartBeat_Port"]))
            chunks = relevant_devices[server_ip]["chunks"]
            FetchFile(client_socket, filename, chunks)

def main():
    scan_thread = threading.Thread(target=scan_network)
    scan_thread.start()

    while True:
        try:
            filename = input("Enter filename to fetch: ")
            if filename.lower() == "quit":
                break
            if filename:
                GetFile(filename)
        except KeyboardInterrupt:
            break

    print("Exiting program.")

if __name__ == "__main__":
    main()
