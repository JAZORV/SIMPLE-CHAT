import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES encryption parameters
KEY = b'YourSecretKey123'  # 256-bit key (32 bytes)
IV = b'InitializationVe'  # 128-bit IV (16 bytes)

HOST = '192.168.88.207'  # server IP address
PORT = 12345  # port to listen for incoming connections

def encrypt(plain_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return encrypted_bytes

def decrypt(cipher_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_bytes = cipher.decrypt(cipher_text)
    decrypted_text = unpad(decrypted_bytes, AES.block_size).decode()
    return decrypted_text

def handle_client(conn, addr):
    print('Connection established with', addr)

    while True:
        cipher_text = conn.recv(1024)
        if not cipher_text:
            print('Connection closed with', addr)
            break
        decrypted_message = decrypt(cipher_text)
        print('Message received from', addr, ':', decrypted_message)

        response = input('Write a response (or "exit" to finish): ')
        encrypted_response = encrypt(response)
        conn.sendall(encrypted_response)

        if response.lower() == 'exit':
            break

    conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print('Waiting for incoming connections...')

    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()
