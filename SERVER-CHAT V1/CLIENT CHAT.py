import socket

HOST = '127.0.0.1'  # dirección IP del servidor
PORT = 12345  # puerto en el que el servidor está escuchando

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        message = input("Escribe un mensaje ('salir' para finalizar): ")
        if message.lower() == 'salir':
            break
        s.sendall(message.encode())
        data = s.recv(1024)
    print('Mensaje enviado:', message)
    print('Respuesta recibida:', data.decode())
