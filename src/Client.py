import json
import os
import socket
import threading
from FindIPs import FindIPs
import nmap
import base64

# Add to a file
Config = {
    "Network" : "devices.json",
    "FileInfo" : "files.json",
    "FileDir" : "Files",
    "CopyTimeout" : 15,     #Change if needed
    "ConnTimeout": 5
}

# Ensure the 'metadata.json' file exists
if not os.path.exists("devices.json"):
    with open("devices.json", "w") as file:
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
        device_socket.sendall(encoded_string.encode('utf-8'))
        receive_file_chunks(device_socket, filename, chunks)
    except Exception as e:
        print(f"Error sending message to device: {e}")
        
# Function to receive file chunks and save them

def receive_file_chunks(device_socket, filename, chunks):
    """
    Receives file chunks from the device socket and saves them.
    
    Args:
        device_socket: The socket connected to the device.
        filename (str): The name of the file.
        chunks (list): List of chunk indices to receive.
    """
    file_dir = Config["FileDir"]
    file_path = os.path.join(file_dir, filename)

    if not os.path.exists(file_dir):
        os.makedirs(file_dir)

    with open(file_path, 'wb') as f:
        for chunk_idx in chunks:
            chunk_data = device_socket.recv(1024)  # Adjust buffer size as needed
            f.write(chunk_data)
            chunk_filename = f"chunk{chunk_idx}_of_{len(chunks)}"
            chunk_path = os.path.join(file_dir, chunk_filename)
            with open(chunk_path, 'wb') as chunk_file:
                chunk_file.write(chunk_data)
            print(f"Chunk {chunk_idx} of file '{filename}' received and saved.")
            
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

def update_device_status(ip, status, devices_file):
    """
    Updates the status of a device in the devices file.
    
    Args:
        ip (str): The IP address of the device.
        status (int): The status code (0 for offline, 1 for online).
        devices_file (str): The path to the file containing device information.
    """
    try:
        with open(devices_file, 'r') as file:
            devices = json.load(file)
        
        if ip in devices:
            devices[ip]['status'] = status
            with open(devices_file, 'w') as file:
                json.dump(devices, file, indent=4)
            print(f"Device status updated: IP {ip}, Status {status}")
        else:
            print(f"Device with IP {ip} not found in the devices file.")
    
    except Exception as e:
        print(f"Error updating device status: {e}")

def Metadata(device_socket):
        
    encoded_string = encode_data("Get Status", "", 0)

    device_socket.sendall(encoded_string.encode('utf-8'))

    # Receive the response
    response = device_socket.recv().decode()
    handle_response(response)

#Change name
def handle_response(device_socket, metadata, devices_file):

    ip = device_socket.getpeername()[0]

    """
    Updates the devices.json file with file metadata.
    
    Args:
        ip (str): The IP address of the device.
        metadata (dict): The file metadata to be stored.
        devices_file (str): The path to the devices.json file.
    """
    try:
        with open(devices_file, 'r') as file:
            devices = json.load(file)
        
        if ip in devices:
            devices[ip]['Files'] = metadata
            with open(devices_file, 'w') as file:
                json.dump(devices, file, indent=4)
            print(f"Updated devices.json with file metadata for {ip}")
        else:
            print(f"Device with IP {ip} not found in devices.json.")
    
    except Exception as e:
        print(f"Error updating devices.json: {e}")

def HandleInput(device_socket, APICall):

    request, name, chunks = decode_data(APICall)

    if(request=="Get"):
        TransferFile(device_socket, name, chunks)

    elif(request=="GetStatus"):
        Heartbeat(device_socket, name)

    elif(request=="FetchInfo"):
        Metadata(device_socket, name)
    

# Function to read JSON data from a file
def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# Function to update client status in the JSON data
def update_status(data, ip, status):
    data[ip]['status'] = status
    save_json("devices.json", data)

def attempt_connection(ip, data, success_counter):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Set a timeout for the connection attempt
        sock.connect((ip, 12345))  # Assume port 12345 for connection
        update_status(data, ip, 1)  # Update status to connected (1)
        print(f"Successfully connected to {ip}")
        success_counter.append(ip)  # Increment the counter for successful connections
    except Exception as e:
        print(f"Failed to connect to {ip}: {e}")
        update_status(data, ip, 0)  # Update status to disconnected (0)

def start_connection_attempts(data):
    success_counter = []  # List to store successful connections
    threads = []
    for device in data:
        ip = device['ip']
        if device['status'] == 0:
            thread = threading.Thread(target=attempt_connection, args=(ip, data, success_counter))
            thread.start()
            threads.append(thread)
    for thread in threads:
        thread.join()
    return len(success_counter)  # Return the number of successful connections

def save_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def main(file_path):
    data = read_json(file_path)
    success_count = start_connection_attempts(data)
    if success_count > 0:
        print(f"Successfully connected to {success_count} devices.")
    else:
        print("No connections made.")

def process_input(user_input):
    # This function will process the user input
    # Replace this with your actual processing logic
    print(f"Processing input: {user_input}")

if __name__ == "__main__":
    FindIPs()
    main(Config['Network'])

    while True:
        try:
            # Get input from the user
            user_input = input("Enter something (type 'quit' to exit): ").strip()

            # If the user types 'quit', exit the loop
            if user_input.lower() == 'quit':
                print("Exiting...")
                break

            # Pass the input to the processing function
            process_input(user_input)
        except Exception as e:
