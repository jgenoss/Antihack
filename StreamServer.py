import configparser
import os
import socket
import threading
import cv2
import numpy as np

class ScreenShareServer:
    def __init__(self, config_file="config.ini"):
        self.config_file = config_file
        self.host, self.port = self.load_config()
        self.running = False
        self.sock = None
        self.clients = {}
        self.waiting_message_shown = False

    def load_config(self):
        """ Lee la IP y el puerto desde config.ini, o crea uno por defecto. """
        config = configparser.ConfigParser()

        if not os.path.exists(self.config_file):
            # Si no existe, crear config.ini con valores por defecto
            config["server"] = {"host": "192.168.18.31", "port": "8080"}
            with open(self.config_file, "w") as configfile:
                config.write(configfile)
            print("Archivo config.ini creado con valores por defecto.")

        # Leer el archivo de configuración
        config.read(self.config_file)
        host = config["server"]["host"]
        port = int(config["server"]["port"])
        return host, port

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"Servidor iniciado en {self.host}:{self.port}")

        self.running = True
        threading.Thread(target=self.accept_clients, daemon=True).start()

        while self.running:
            self.show_clients_menu()

    def accept_clients(self):
        """ Acepta múltiples clientes y crea un hilo para cada uno. """
        while self.running:
            client_sock, addr = self.sock.accept()
            print(f"Cliente {addr} conectado.")
            self.clients[addr] = client_sock
            threading.Thread(target=self.receive_stream, args=(client_sock, addr), daemon=True).start()
            self.waiting_message_shown = False  # 📌 Restablecer para evitar "Esperando clientes..."

    def show_clients_menu(self):
        """ Permite seleccionar un cliente para ver su pantalla """
        if not self.clients:
            if not self.waiting_message_shown:
                print("Esperando clientes...")
                self.waiting_message_shown = True  # 📌 Solo mostrar una vez
            return
        
        self.waiting_message_shown = False  # 📌 Reiniciar cuando haya clientes
        
        print("\nClientes conectados:")
        for i, addr in enumerate(self.clients.keys()):
            print(f"{i + 1}. {addr}")

        choice = input("Elige un cliente para ver su pantalla (número) o 'q' para salir: ")

        if choice.lower() == 'q':
            self.running = False
            return
        
        try:
            choice = int(choice) - 1
            if 0 <= choice < len(self.clients):
                selected_client = list(self.clients.keys())[choice]
                self.view_client_screen(selected_client)
            else:
                print("Selección no válida.")
        except ValueError:
            print("Por favor, ingresa un número válido.")

    def receive_stream(self, client_sock, addr):
        """ Recibe y almacena el stream de cada cliente """
        while self.running:
            try:
                # Recibir tamaño de imagen
                data = client_sock.recv(4)
                if not data:
                    break
                
                frame_size = int.from_bytes(data, byteorder='big')
                frame_data = b''

                while len(frame_data) < frame_size:
                    packet = client_sock.recv(frame_size - len(frame_data))
                    if not packet:
                        break
                    frame_data += packet

                # Convertir imagen y almacenarla
                frame = np.frombuffer(frame_data, dtype=np.uint8)
                frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

                if frame is not None:
                    self.clients[addr] = (client_sock, frame)
            except:
                break

        print(f"Cliente {addr} desconectado.")
        del self.clients[addr]

    def view_client_screen(self, addr):
        """ Muestra la pantalla del cliente seleccionado """
        while self.running:
            if addr in self.clients and isinstance(self.clients[addr], tuple):
                _, frame = self.clients[addr]
                window = f"Pantalla de {addr}"
                cv2.namedWindow(window, cv2.WINDOW_NORMAL)
                cv2.imshow(window, frame)

                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break

        cv2.destroyAllWindows()

if __name__ == "__main__":
    server = ScreenShareServer()
    server.start()
