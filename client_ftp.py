import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# AES key for decryption (must match the server's key)
key = b'This is a key123'  # Ensure the key length is correct

def decrypt_data(encrypted_data, key):
    """
    Decrypts data using AES in CBC mode with padding.

    Parameters:
        encrypted_data (bytes): The IV prepended to the ciphertext.
        key (bytes): The AES decryption key.

    Returns:
        bytes: The decrypted plaintext data.
    """
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext  # Replace with actual decrypted data after completing decryption

def request_file(filename):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 9999))
    
    try:
        # Send the filename to the server
        client_socket.send(filename.encode())
        print(f"Requested file: {filename}")

        # Receive the encrypted data from the server
        encrypted_data = b''
        while True:
            part = client_socket.recv(1024)
            if not part:
                break
            encrypted_data += part

        decrypted_data = decrypt_data(encrypted_data, key)
        with open(f"received_{filename}", "wb") as file:
            file.write(decrypted_data)
        print(f"File '{filename}' received and saved.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

filename = input("Enter the filename to request: ")
request_file(filename)
