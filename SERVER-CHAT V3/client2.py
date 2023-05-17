import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES encryption parameters
KEY = b'YourSecretKey123'  # 256-bit key (32 bytes)
IV = b'InitializationVe'  # 128-bit IV (16 bytes)

HOST = '192.168.88.207'  # server IP address
PORT = 12345  # port on which the server is listening

def encrypt(plain_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return encrypted_bytes

def decrypt(cipher_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_bytes = cipher.decrypt(cipher_text)
    decrypted_text = unpad(decrypted_bytes, AES.block_size).decode()
    return decrypted_text

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        message = input("Write a message ('exit' to finish): ")
        if message.lower() == 'exit':
            break
        encrypted_message = encrypt(message)
        s.sendall(encrypted_message)
        encrypted_response = s.recv(1024)
        response = decrypt(encrypted_response)

    print('Message sent:', message)
    print('Response received:', response)
