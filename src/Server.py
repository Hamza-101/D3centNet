import json
import os
import socket
import threading
import re



# Function to read JSON data from a file
def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


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
                    "max_chunk_number": max_chunk_number,       #What to do
                    "total_chunks": total_chunks
                }
    return metadata

#Have metadata saved, then send

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
        connection.close()
        print(f"Disconnected from {address}")

def Metadata(device_socket):
        
    encoded_string = encode_data("Get Status", "", 0)

    device_socket.sendall(encoded_string.encode('utf-8'))

    # Receive the response
    response = device_socket.recv().decode()
    handle_response(response)


def HandleInput(device_socket, APICall):

    request, name, chunks = decode_data(APICall)

    if(request=="Get"):
        FetchFile(device_socket, name, chunks)

    elif(request=="FetchInfo"):
        Metadata(device_socket, name)
    
def FetchFile(device_socket, filename, chunks):
    encoded_string = encode_data("GET", filename, chunks)
    try:
        device_socket.sendall(encoded_string.encode('utf-8'))
        send_file(device_socket, filename, chunks)
    except Exception as e:
        print(f"Error sending message to device: {e}")
     

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
                        print(f"Chunk {chunk_idx} of file '{filename}' sent to device.")
                else:
                    print(f"Chunk {chunk_idx} of file '{filename}' not found.")
    else:
        print(f"File '{filename}' not found.")


def handle_client(client_socket, address):
    while True:
        try:
            encoded_data = client_socket.recv()
            if not encoded_data:
                break

            decoded_message = decode_data(encoded_data)
            HandleInput(decoded_message)

        except Exception as e:
            print("Error occurred while handling client:", e)
            break

    client_socket.close()

# Function to continuously accept client connections
# Main function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print("Server is listening on {}:{}".format(SERVER_HOST, SERVER_PORT))

    try:
        while True:
            client_socket, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server terminated.")

def get_server_ip():
    return socket.gethostbyname(socket.gethostname())

def main():
    start_server(SERVER_HOST, SERVER_PORT)

SERVER_HOST = get_server_ip()
SERVER_PORT = 5000

if __name__ == "__main__":
    main()
