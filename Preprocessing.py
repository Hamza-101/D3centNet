import os
import time

# The provided function split_file_into_chunks works with any type of file. 
# Whether it's a text file, image, video, audio, or any other type, the function will split it into smaller chunks.
#
# Here's how it would work with different types of files:
#
# Text Files: Common text files like .txt, .csv, .json, etc.
# Image Files: Formats like .jpg, .png, .gif, etc.
# Video Files: Formats like .mp4, .avi, .mov, etc.
# Audio Files: Formats like .mp3, .wav, .ogg, etc.
# Binary Files: Any other type of file, including executables, archives (.zip, .tar, etc.), documents (.pdf, .docx, etc.), and so on.
#
# The function treats files as binary streams, so it's agnostic to the actual content of the file. 
# It simply reads the file in chunks and writes those chunks to separate files, regardless of the file type.

import os

def monitor_directory(directory, chunk_size, output_directory):
    for filename in os.listdir(directory):
        full_path = os.path.join(directory, filename)
        if os.path.isfile(full_path):
            split_into_chunks(full_path, chunk_size, output_directory)
            print(f"File '{filename}' chunked and stored.")

def split_into_chunks(filename, chunk_size, output_directory):
    os.makedirs(output_directory, exist_ok=True)
    output_folder = os.path.join(output_directory, os.path.splitext(os.path.basename(filename))[0])
    os.makedirs(output_folder, exist_ok=True)

    with open(filename, 'rb') as file:
        chunk_number = 0
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            output_filename = f"chunk{chunk_number}_of_{os.path.getsize(filename)//chunk_size + 1}"
            with open(os.path.join(output_folder, output_filename), 'wb') as chunk_file:
                chunk_file.write(chunk)
            print(f"Chunk {chunk_number} created for '{filename}'.")
            chunk_number += 1

# Example usage
if __name__ == "__main__":
    input_directory = "Unchunked"  # Adjust the input directory as needed
    output_directory = "Files"  
    chunk_size = 1024   

    monitor_directory(input_directory, chunk_size, output_directory)