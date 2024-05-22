import json
import os
import socket
import threading
import time

def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def update_status(data, ip, status):
    data[ip]['Status'] = status

def handle_client(connection, address, data):
    print(f"Connected to {address}")
    try:
        while True:
            data_received = connection.recv(1024)
            if not data_received:
                break
            print(f"Received from {address}: {data_received.decode()}")
            # Process received data here
            # Example: Echo back the received data
            connection.sendall(data_received)
    except Exception as e:
        print(f"Error with {address}: {e}")
    finally:
        print(f"Disconnected from {address}")
        update_status(data, address, 0)  # Update status to disconnected (0)

def attempt_connection(ip, data):
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # Set a timeout for the connection attempt
            sock.connect((ip, 12345))  # Assume port 12345 for connection
            update_status(data, ip, 1)  # Update status to connected (1)
            print(f"Successfully connected to {ip}")
            handle_client(sock, ip, data)
        except Exception as e:
            print(f"Failed to connect to {ip}: {e}")
            update_status(data, ip, 0)  # Update status to disconnected (0)
        time.sleep(15)  # Wait for 15 seconds before trying again

def request_file_metadata(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, 12345))  # Assume server listens on port 12345
        sock.sendall(b"GET_METADATA")
        response = sock.recv(1024)
        metadata = json.loads(response.decode())
        return metadata
    except Exception as e:
        print(f"Error requesting file metadata from {ip}: {e}")
        return {}

def store_metadata(ip, metadata):
    all_metadata = {}
    if os.path.exists("metadata.json"):
        with open("metadata.json", 'r') as file:
            all_metadata = json.load(file)
    all_metadata[ip] = metadata
    with open("metadata.json", 'w') as file:
        json.dump(all_metadata, file, indent=4)

def start_connection_attempts(data):
    for ip, status_info in data.items():
        if status_info['Status'] == 1:
            thread = threading.Thread(target=attempt_connection, args=(ip, data))
            thread.start()

def handle_user_input(command, data):
    if command == "check_status":
        active_devices = [ip for ip, info in data.items() if info['Status'] == 1]
        if active_devices:
            print(f"Active devices: {', '.join(active_devices)}")
        else:
            print("Error 404: No device connected")
    else:
        print(f"Unknown command: {command}")

def handle_cli_input(data):
    while True:
        user_input = input("Enter command: ")
        handle_user_input(user_input, data)

def save_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def main(file_path):
    data = read_json(file_path)
    
    connection_thread = threading.Thread(target=start_connection_attempts, args=(data,))
    connection_thread.start()

    cli_thread = threading.Thread(target=handle_cli_input, args=(data,))
    cli_thread.start()

    connection_thread.join()
    cli_thread.join()

if __name__ == "__main__":
    main('data.json')
