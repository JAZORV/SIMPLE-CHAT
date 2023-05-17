import socket
import threading

HOST = '127.0.0.1'  # dirección IP del servidor
PORT = 12345  # puerto para escuchar las conexiones entrantes

def handle_client(conn, addr):
    print('Conexión establecida con', addr)

    while True:
        data = conn.recv(1024)
        if not data:
            print('Conexión cerrada con', addr)
            break
        print('Mensaje recibido de', addr, ':', data.decode())
        message = input('Escribe una respuesta (o "salir" para finalizar): ')
        conn.sendall(message.encode())
        if message.lower() == 'salir':
            break

    conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print('Esperando conexiones entrantes...')

    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()
