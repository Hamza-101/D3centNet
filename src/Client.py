import json
import os
import socket
import threading
from FindIPs import FindIPs
import nmap
import base64
import re
import time
# Add to a file
Config = {
    "Network" : "data/devices.json",
    "FileInfo" : "files.json",
    "FileDir" : "Files",
    "BackupTimeout" : 75,     #Change if needed
    "ConnTimeout": 60,
    "Heartbeat" : 45,     #Change if needed
    "FetchInfoTimeout": 5, #Metadata
    #Add IP
    # See of more needed
    "PORT" : 5000 
}

# Ensure the 'metadata.json' file exists
if not os.path.exists(Config["Network"]):
    with open(Config["Network"], "w") as file:
        json.dump({}, file)

if not os.path.exists("files.json"):
    with open("files.json", "w") as file:
        json.dump({}, file)

def encode_data(data_string, string_name, chunks_number):
    """
    Encodes a string, string name, and number of chunks together into a single encoded string.
    
    Args:
        data_string (str): The string data to encode.
        string_name (str): The name of the string.
        chunks_number (int): The number of chunks.
        
    Returns:
        str: The encoded string containing all the input data.
    """
    # Concatenate the data into a single string
    combined_string = f"{data_string}|{string_name}|{chunks_number}"
    
    # Convert the combined string to bytes
    combined_bytes = combined_string.encode('utf-8')
    
    # Encode the bytes using Base64
    encoded_bytes = base64.b64encode(combined_bytes)
    
    # Convert the encoded bytes back to a string
    encoded_string = encoded_bytes.decode('utf-8')
    
    return encoded_string

def decode_data(encoded_string):
    """
    Decodes an encoded string back into the original data.
    
    Args:
        encoded_string (str): The encoded string to decode.
        
    Returns:
        tuple: A tuple containing the data string, string name, and number of chunks.
    """
    # Convert the encoded string to bytes
    encoded_bytes = encoded_string.encode('utf-8')
    
    # Decode the bytes using Base64
    decoded_bytes = base64.b64decode(encoded_bytes)
    
    # Convert the decoded bytes back to a string
    decoded_string = decoded_bytes.decode('utf-8')
    
    # Split the combined string into its components
    data_string, string_name, chunks_number = decoded_string.split('|')
    
    return data_string, string_name, int(chunks_number)

# Function to handle file request
def TransferFile(device_socket, filename, chunks):
    encoded_string = encode_data("GET", filename, chunks)
    try:
        device_socket.sendall(encoded_string.encode())
        receive_file_chunks(device_socket, filename, chunks)
    except Exception as e:
        print(f"Error sending message to device: {e}")
        

def receive_file_chunks(device_socket, filename, chunks):
    file_dir = Config["FileDir"]
    file_path = os.path.join(file_dir, filename)
    if not os.path.exists(file_dir):
        os.makedirs(file_dir)

    try:
        with open(file_path, 'wb') as f:
            for chunk_idx in chunks:
                chunk_data = device_socket.recv()  
                if not chunk_data:
                    print(f"Device disconnected while receiving {filename}")
                    return
                f.write(chunk_data)
                chunk_filename = f"chunk{chunk_idx}_of_{len(chunks)}"
                chunk_path = os.path.join(file_dir, chunk_filename)
                with open(chunk_path, 'wb') as chunk_file:
                    chunk_file.write(chunk_data)
    except Exception as e:
        print(f"Error receiving file chunks: {e}")

# Complete        
def Heartbeat(ip, devices_file):
    """
    Pings a device to check if it's online using Nmap.
    
    Args:
        ip (str): The IP address of the device to ping.
        devices_file (str): The path to the file containing device information.
        
    Returns:
        bool: True if the device is online (responds to ping), False otherwise.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sn')
        if ip in nm.all_hosts():
            print(f"Device with IP {ip} is online.")
            update_device_status(ip, 1, devices_file)  # Update device status to online (1)
            return True
        else:
            print(f"Device with IP {ip} is offline or not reachable.")
            update_device_status(ip, 0, devices_file)  # Update device status to offline (0)
            return False
        
    except Exception as e:
        print(f"An error occurred while pinging the device with IP {ip}: {e}")
        update_device_status(ip, 0, devices_file)  # Update device status to offline (0)
        return False

def update_device_status(ip, status):
    """
    Updates the status of a device in the devices file.
    
    Args:
        ip (str): The IP address of the device.
        status (int): The status code (0 for offline, 1 for online).
        devices_file (str): The path to the file containing device information.
    """
    try:
        with open(Config["Network"], 'r') as file:
            devices = json.load(file)
        
        if ip in devices:
            devices[ip]['status'] = status
            with open(Config["Network"], 'w') as file:
                json.dump(devices, file, indent=4)
            print(f"Device status updated: IP {ip}, Status {status}")
        else:
            print(f"Device with IP {ip} not found in the devices file.")
    
    except Exception as e:
        print(f"Error updating device status: {e}")

# Complete
def Metadata():
    people = []
    
    try:
        # Read the device information from the network file
        with open(Config["Network"], 'r') as file:
            data = json.load(file)
    except Exception as e:
        print(f"Error reading devices file: {e}")
        return

    # Collect IPs of online devices
    for device_ip, device_info in data.items():
        if device_info.get("status") == 1:  # Device is online
            people.append(device_ip)

    # Attempt to connect to each online device and request metadata
    for peeps in people:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # Set a timeout for the connection attempt
            
            print(f"Attempting to connect to {peeps} on port 12345")
            sock.connect((peeps, 12345))  # Assume port 12345 for connection
            
            print(f"Connection established with {peeps}")
            encoded_string = encode_data("Get Status", "", 0)
            sock.sendall(encoded_string.encode('utf-8'))
            
            try:
                response = sock.recv(4096).decode('utf-8')
                if response:
                    print(f"Received metadata from {peeps}: {response}")
                    handle_response(peeps, response)
                else:
                    print(f"No response received from {peeps}.")
            except socket.timeout:
                print(f"Timeout waiting for response from {peeps}.")
            except Exception as e:
                print(f"Error receiving response from {peeps}: {e}")

            sock.close()
        except socket.error as e:
            print(f"Error connecting to {peeps}: {e}")
        finally:
            sock.close()

# Complete
def handle_response(ip, metadata):
    try:
        with open(Config["Network"], 'r') as file:
            devices = json.load(file)
        
        if ip in devices:
            devices[ip]['Files'] = metadata
            with open(Config["Network"], 'w') as file:
                json.dump(devices, file, indent=4)
            print(f"Updated with file metadata for {ip}")
        else:
            print(f"Device with IP {ip} not found in.")
    
    except Exception as e:
        print(f"Error updating : {e}")

def GetIp(filename):
    """
    Gets the keys from the "Network" section of the Config dictionary that have the specified filename in the "Files" section.

    Args:
        config (dict): The configuration dictionary containing the "Network" section.
        filename (str): The filename to check for in the "Files" section.

    Returns:
        list: A list of keys (IP addresses) that have the specified filename in their "Files" section.
    """

    with open(Config["Network"], 'r') as file:
        data = json.load(file)
    
    devices_with_filename_and_chunks = []

    for device in data:
        ip = device.get("ip")
        status = device.get("status")
        files = device.get("Files", {})
        
        if status == 1 and filename in files:
            chunks = files[filename]["Chunks"]
            devices_with_filename_and_chunks.append((ip, chunks))
        elif status == 1 and filename not in files:
            return None

    sorted_devices = sorted(devices_with_filename_and_chunks, key=lambda x: len(x[1]), reverse=True)
    
    return sorted_devices

def FindMissingChunks(name):
    existing_chunks = []
    path = os.path.exists(os.path.join(Config["Network"], name))
    if (not path) or len(os.listdir(path)) == 0:
        existing_chunks=None
    else:
        pattern = re.compile(r'chunk(\d+)_of_(\d+)')
        for filename in os.listdir(Config["FileDir"]):
            match = pattern.search(filename)
            if match:
                chunk_index = int(match.group(1))
                existing_chunks.append(chunk_index)
    return existing_chunks

def GetMaxChunks(filename):
    max_chunks = 0

    with open(Config["FileInfo"], 'r') as file:
        data = json.load(file)

    max_chunks = data[filename].get("maxChunks", 0)
    return max_chunks
    
def FetchChunksInfo(filename):
    chunks = []

    with open(Config["FileInfo"], 'r') as file:
        data = json.load(file)

    chunks = data[filename].get("AllChunks", 0)
    return chunks

def EnumFileChunks(filename):
    chunk_pattern = re.compile(r'chunk(\d+)_of_(\d+)')
    existing_chunks = set()
    for file_name in os.listdir(os.path.join(Config["FileDir"], filename)):
        match = chunk_pattern.search(file_name)
        if match and match.group(0) == filename:
            existing_chunks.add(int(match.group(1)))  # Add the chunk index to the set
    return sorted(existing_chunks)  

# Change Metadata
def HandleInput(input):

    chunks = []
    sortedDevices = GetIp(input)
     
    if sortedDevices == None:
        print("No devices have the requested file")
        return
    
    if len(sortedDevices) == 0:
        print("No devices online")
        return

    ChunksNumber = GetMaxChunks(input)  
    ExistingChunks = FindMissingChunks(input)  
    if (ExistingChunks == None):
        for i in range(0, ChunksNumber + 1):
             chunks.append(i) 
    else:
        for i in range(0, ChunksNumber + 1):
            if (i not in ExistingChunks):
                chunks.append(i) 

    for device in sortedDevices:
        ip, _ = device
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10) 
        sock.connect((ip, Config["PORT"]))
        sock.connect((ip, 12345))  
        TransferFile(sock, input, chunks)
        sock.close()
        
# Complete
def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# Function to update client status in the JSON data
def update_status(data, ip, status):
    data[ip]['status'] = status
    save_json(Config["Network"], data)

def save_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def process_input(user_input):
    print(f"Starting file transfer: {user_input}")
    HandleInput(user_input)

def find_ips(interval=60):
    while True:
        FindIPs()
        # print(f"Waiting for {interval} seconds before next FindIPs execution...")
        time.sleep(interval)


def updatemetadata(interval=15):
    while True:
        Metadata()
        # print(f"Metadata updated.")
        time.sleep(interval)



if __name__ == "__main__":
    FindIPs()

    threading.Thread(target=find_ips, args=(60,), daemon=True).start()
    threading.Thread(target=updatemetadata, args=(15,), daemon=True).start()

    while True:
        user_input = input("Enter something (type 'quit' to exit): ").strip()
        if user_input.lower() == 'quit':
            print("Exiting...")
            break
        process_input(user_input)
