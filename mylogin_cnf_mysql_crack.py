from Crypto.Cipher import AES
import os

# Constants
AES_BLOCK_SIZE = 16
KEY_SIZE = 20

def main(filename):
    try:
        # Open file
        with open(filename, 'rb') as file:
            # Read and skip the first 4 bytes
            file.seek(4, os.SEEK_SET)

            # The next 20 bytes are the key
            key_in_file = file.read(KEY_SIZE)
            if len(key_in_file) != KEY_SIZE:
                return -1
            
            # Perform XOR operation on the key
            key_after_xor = bytearray(AES_BLOCK_SIZE)
            for i in range(KEY_SIZE):
                key_after_xor[i % AES_BLOCK_SIZE] ^= key_in_file[i]

            # Set up the AES key for decryption
            cipher = AES.new(key_after_xor, AES.MODE_ECB)

            output_buffer = bytearray()
            # Process the file in chunks
            while True:
                chunk_size_data = file.read(4)
                if len(chunk_size_data) != 4:
                    break
                
                # Determine the chunk size
                cipher_chunk_length = int.from_bytes(chunk_size_data, byteorder='little')
                if cipher_chunk_length > 4096:
                    return -1
                
                # Read the cipher chunk
                cipher_chunk = file.read(cipher_chunk_length)
                if len(cipher_chunk) != cipher_chunk_length:
                    return -1

                # Decrypt the chunk
                decrypted_data = cipher.decrypt(cipher_chunk)
                output_buffer.extend(decrypted_data[:cipher_chunk_length])
        
        # Clean up decrypted data
        output_buffer = output_buffer.rstrip(b'\x00')  # Remove padding if present

        # Print the result
        print(output_buffer.decode('utf-8'))

    except FileNotFoundError:
        print("File not found.")
        return -1
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script.py <filename>")
    else:
        main(sys.argv[1])
