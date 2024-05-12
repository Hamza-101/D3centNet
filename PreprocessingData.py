# The provided function split_file_into_chunks works with any type of file. 
# Whether it's a text file, image, video, audio, or any other type, the function will split it into smaller chunks.
#
# Here's how it would work with different types of files:
#

# Check all these


# Text Files: Common text files like .txt, .csv, .json, etc.
# Image Files: Formats like .jpg, .png, .gif, etc.
# Video Files: Formats like .mp4, .avi, .mov, etc.
# Audio Files: Formats like .mp3, .wav, .ogg, etc.
# Binary Files: Any other type of file, including executables, archives (.zip, .tar, etc.), documents (.pdf, .docx, etc.), and so on.
#
# The function treats files as binary streams, so it's agnostic to the actual content of the file. 
# It simply reads the file in chunks and writes those chunks to separate files, regardless of the file type.




Automate it for N files
Add documentation


import os

def split_into_chunks(filename, chunk_size, output_directory):
    # Create directory 'ChunkedFiles' at the root if it doesn't exist
    chunked_files_directory = os.path.join(os.getcwd(), "ChunkedFiles")
    os.makedirs(chunked_files_directory, exist_ok=True)

    # Extract the filename without extension for the subdirectory
    subdirectory = os.path.splitext(os.path.basename(filename))[0]
    output_subdirectory = os.path.join(chunked_files_directory, subdirectory)

    # Create the subdirectory for the file if it doesn't exist
    os.makedirs(output_subdirectory, exist_ok=True)

    # Read the file in chunks and save them to the subdirectory
    with open(filename, 'rb') as file:
        chunk_number = 0
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            output_filename = f"chunk{chunk_number}_of_{os.path.getsize(filename)//chunk_size + 1}"
            with open(os.path.join(output_subdirectory, output_filename), 'wb') as chunk_file:
                chunk_file.write(chunk)
            print(f"Chunk {chunk_number} created.")
            chunk_number += 1

def join_chunks(chunks_directory, output_directory, output_filename):
    # Get all chunk files in the specified directory
    chunk_files = sorted(os.listdir(chunks_directory), key=lambda x: int(x.split("_")[0][5:]))

    # Create the output directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)
    
    # Reconstruct the file from the chunks
    with open(os.path.join(output_directory, output_filename), 'wb') as output_file:
        for chunk_file in chunk_files:
            with open(os.path.join(chunks_directory, chunk_file), 'rb') as chunk:
                output_file.write(chunk.read())
    
    print(f"File '{output_filename}' reconstructed successfully.")

# Example usage:
Filename = "Files/Images/cat1.jpeg"
split_into_chunks(Filename, 1024, "ChunkedFiles")
join_chunks(os.path.join("ChunkedFiles", os.path.splitext(os.path.basename(Filename))[0]), "reconstructed_directory", "reconstructed_file.jpeg")
