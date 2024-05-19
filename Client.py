import os
import json
import socket

Directories = {
    "Path": "./Files",
    "NetworkDevices": "network_devices.json",
    "YellowBook": "yellowbook.json",
    "HeartBeat_Port": 12345
}

def GetFile(filename):
    done = False
    devices_with_chunks = []

    relevant_devices = {}

    if not os.path.exists(Directories["YellowBook"]):
        print(f"Error: {Directories['YellowBook']} does not exist.")
        return

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

    print(f"Starting transfer for file {filename}")
    for server in sorted_devices:
        ip, chunk_indices = server[0], relevant_devices[server[0]]["chunks"]
        done = FetchFile(ip, filename, chunk_indices)

        if done:
            print(f"File {filename} fetched successfully")
            break

    if not done:
        print("Transfer still in progress and will be completed ASAP")

def FetchFile(ip, file, chunks):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, Directories["HeartBeat_Port"]))
        client_socket.sendall(file.encode())
        client_socket.sendall(json.dumps(chunks).encode())
        client_socket.sendall(b"-------")
        receive_chunks(client_socket, chunks)
        client_socket.close()
        return True
    except Exception as e:
        print(f"Error fetching file: {e}")
        return False

def receive_chunks(client_socket, chunk_indices):
    os.makedirs(Directories["Path"], exist_ok=True)

    received_chunks = set()
    while not received_chunks.issubset(chunk_indices):
        chunk_data = client_socket.recv(1024)

        if chunk_data == b"-------":
            break

        chunk_number = int(chunk_data.split(b'_')[0].decode().replace('chunk', ''))
        output_path = os.path.join(Directories["Path"], f"chunk{chunk_number}_of_{len(chunk_indices)}")

        with open(output_path, 'wb') as chunk_file:
            chunk_file.write(chunk_data)

        received_chunks.add(chunk_number)

    print(f"Received {len(received_chunks)} chunks out of {len(chunk_indices)}.")

def main():
    filename = ""
    while True:
        try:
            filename = input("Enter filename to fetch (or 'quit' to exit): ")
            if filename.lower() == "quit":
                break
            else:
                GetFile(filename)
        except KeyboardInterrupt:
            break

    print("Exiting program.")

if __name__ == "__main__":
    main()
