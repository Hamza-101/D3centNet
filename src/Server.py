import json
import os
import socket
import threading
import re
import base64

Config = {
    "FileDir" : "Files",
}

# Function to read JSON data from a file
def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# Decode what arrives
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

#Metadata Generation
def file_metadata():
    metadata = {}
    for _, _, files in os.walk(Config["Files"]):
        for filename in files:
            if "chunk" in filename:
                chunks = set()
                max_chunk_number = 0
                pattern = re.compile(r'chunk(\d+)_of_(\d+)')
                match = pattern.search(filename)
                if match:
                    #Modify to return list
                    chunk_number = int(match.group(1))
                    total_chunks = int(match.group(2))
                    chunks.add(chunk_number)
                    max_chunk_number = max(max_chunk_number, chunk_number)
                metadata[filename] = {
                    "chunks": sorted(chunks),
                    "maxChunk": max_chunk_number,       #What to do
                    "totalChunks": total_chunks        # See if change
                }
    return metadata

# Example usage
def handle_client(connection, address):
    print(f"Connected to {address}")
    try:
        while True:
            data_received = connection.recv(1024)
            if not data_received:
                break
            print(f"Received from {address}: {data_received.decode()}")
    except Exception as e:
        print(f"Error with {address}: {e}")
    finally:
        print(f"Connection closed {address}")

def SendMetadata(device_socket):
        
    device_socket.sendall(file_metadata().encode)


def HandleInput(device_socket, APICall):
    
    request, name, chunks = decode_data(APICall)
    
    FetchFile(device_socket, name, chunks)

    if(request == "Get Status"):
        SendMetadata(device_socket)

    if(request == "GET"):
        send_file(device_socket, name, chunks)

def FetchFile(device_socket, filename, chunks):
    try:
        send_file(device_socket, filename, chunks)
    except Exception as e:
        print(f"Error sending file to device: {e}")
        
def send_file(device_socket, filename, chunks):
    """
    Sends file chunks for the given file and chunk indices to the device socket.
    
    Args:
        device_socket: The socket connected to the device.
        filename (str): The name of the file.
        chunks (list): List of chunk indices to transfer.
    """
    file_dir = Config["FileDir"]
    file_path = os.path.join(file_dir, filename)
    
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            for chunk_idx in chunks:
                chunk_filename = f"chunk{chunk_idx}_of_{len(chunks)}"
                chunk_path = os.path.join(file_dir, chunk_filename)
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as chunk_file:
                        chunk_data = chunk_file.read()
                        device_socket.sendall(chunk_data)
                else:
                    print(f"Chunk {chunk_idx} of file '{filename}' not found.")
    else:
        print(f"File '{filename}' not found.")


def handle_client(client_socket):
    while True:
        try:
            encoded_data = client_socket.recv()
            if not encoded_data:
                break

            decoded_message = decode_data(encoded_data)
            HandleInput(decoded_message, client_socket)

        except Exception as e:
            print("Error occurred while handling client:", e)
            break

# Function to continuously accept client connections
# Main function
def start_server():
    SERVER_HOST = get_server_ip()
    SERVER_PORT = 5000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print("Server is listening on {}:{}".format(SERVER_HOST, SERVER_PORT))

    try:
        while True:
            client_socket, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client,
                                    args=(client_socket, address))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server terminated.")

def get_server_ip():
    return socket.gethostbyname(socket.gethostname())

def main():
    start_server()

if __name__ == "__main__":
    main()
