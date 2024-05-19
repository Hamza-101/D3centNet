import os
import json
import time
import socket
import subprocess
import threading
from Config import *

# Thread 1
#######################
def scan_network():
    devices={}
    while True:
        try:
            for ip in range(1, 256):
                address = f"192.168.1.{ip}"
                if address != "192.168.1.1" and is_port_open(address):
                    devices[address] = {"Status": "1"} #Alive
                 
            DeviceLog(devices)
            
            for ip, _ in devices.items():
                get_files_info(ip)
              
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
########################

#Change names
# Thread 2
########################

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
        
        Device_FileDetails(directory_info)

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

    deviceIP.sendall("UpdateFiles".encode())
    deviceIP.sendall("-------".encode())
    server_socket.recv().decode()

    Info = {}
    files_directory = os.path.join(Directories["Path"], 'ChunkedFiles')
    Info = MetaData(files_directory)

    existing_info = {}

    if os.path.exists(Directories["YellowBook"]):
        with open(Directories["YellowBook"], 'r') as f:
            existing_info = json.load(f)

    if deviceIP:
        existing_info[deviceIP] = Info

        with open(Directories["YellowBook"], 'w') as f:
            json.dump(existing_info, f, indent=4)
    else:
        print("Failed to retrieve the local IP address.")
    
##########################

#Thread 3
# def bind_socket(port):
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(('localhost', port))
#     server_socket.listen()
#     print(f"Server is listening on port {port}...")
#     return server_socket

# def establish_connection(port, file_request):
#     server_socket = bind_socket(port)
#     while True:
#         client_socket, client_address = server_socket.accept()
#         print(f"Connection established with {client_address}")
#         client_thread = threading.Thread(target=handle_client, args=(client_socket, file_request))
#         client_thread.start()


def SendChunks(filename, chunknumbers):

    for chunk_number in chunknumbers:
        chunk_filename = f"chunk{chunk_number}_of_{len(chunknumbers)}"
        chunk_path = os.path.join(Directories["Path"], chunk_filename)
        
        if os.path.exists(chunk_path):
            with open(chunk_path, 'rb') as chunk_file:
                chunk_data = chunk_file.read()
                client_socket.sendall(chunk_data)
            client_socket.sendall("-------")

        else:
            print(f"Chunk {chunk_number} does not exist.")

def ReceiveData_File(client_socket, save_dir):
    n = []
    while True:
        filename = client_socket.recv(1024).decode()
        if not filename:
            break
        
        _, chunk_number = filename.split("_chunk_")
        chunk_number = int(chunk_number)

        received_data = ""
        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            if data.strip() == "-------":
                break
            received_data += data
        
        file_path = os.path.join(save_dir, filename)
        with open(file_path, "w") as file:
            file.write(received_data)
        
    print(f"Received chunk [{n}] of'{filename}'")



    #Multi-Transfer

def GetFile(filename):
    done = False
    devices_with_chunks = []

    relevant_devices = {}
    with open(Directories["YellowBook"], "r") as file:
        transfer_meta = json.load(file)
        for ip, directory_info in transfer_meta.items():
            #--------------------------------------------
            if filename in directory_info:
                chunks_info = directory_info[filename]["chunks"]
                relevant_devices[ip] = {
                    "chunks": chunks_info
                }
    for ip, directory_info in devices.items():
        total_chunks = sum(len(chunks) for chunks in directory_info.values())
        devices_with_chunks.append((ip, total_chunks))
    
    sorted_devices = sorted(devices_with_chunks, key=lambda x: x[1], reverse=True)

    for server in sorted_devices:

        done = FetchFile(server, chunk_indices)

        if(done==True):
            print("File Fetched")
            break
    
    print("Transfer still in progress and will be completed ASAP")

    return 
#Chunks is array 
def FetchFile(client_socket, file, chunks):

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    client_socket.sendall(IPAddr.encode())
    client_socket.sendall(file.encode())
    client_socket.sendall(chunks.encode())
    client_socket.sendall("-------".encode())
    receive_chunks(client_socket, chunks)

def receive_chunks(client_socket, chunk_indices):
        os.makedirs(Directories["Path"], exist_ok=True)
        
        received_chunks = []
        while not receive_chunks.issubset(chunk_indices):
            chunk_data = client_socket.recv(1024)  # Adjust buffer size as needed
            
            # Check if the received data indicates the end of the chunks
            if chunk_data == b"-------":
                break
            
            chunk_filename = f"chunk{received_chunks}_of_{chunk_indices}"
            output_path = os.path.join(Directories["Path"], chunk_filename)
            
            with open(output_path, 'wb') as chunk_file:
                chunk_file.write(chunk_data)
            
            received_chunks += 1
        
        print(f"Received {received_chunks} chunks.")

def HandleCommand(server_socket):
    commands = []
    while True:
        try:
            command = str(server_socket.recv().decode().strip())
            if(command=="-------"):
                break
            else:
                commands.append(command)

        except Exception as e:
            print(f"Error receiving data: {e}")
            return None
    
    # elif(command[0] == "Backup"):
    #     duplication()
            
    return


# def duplication():

#     return

#Thread 4
#Logging

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', General["HeartBeat_Port"]))
    server_socket.listen()

    filename=""
    scan_thread = threading.Thread(target=scan_network())
    scan_thread.start()
    Transfer = threading.Thread(target=HandleCommand(server_socket))
    Transfer.start()

    while True:
        try:
            if filename.lower() == "quit":
                break
            else:
                #Add the functionality for file type distinction
                filename = input("Enter filename to fetch: ")
                if filename:
                    transfer_status = GetFile(filename)
                    if transfer_status == 0:
                        print(f"Error: File doesn't exist or filename is incorrect '{filename}'")
                        print()
                    else:
                        print(f"Information for directory '{filename}':")
                        print(transfer_status)
                        print("---Comeplete---")
                        
        except KeyboardInterrupt:
            break

    print("Exiting program.")

if __name__ == "__main__":
    main()