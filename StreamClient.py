import socket
import numpy as np
import cv2
import pyautogui
import win32com.client
import argparse

class ScreenShareClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False

    def start(self):
        try:
            self.sock.connect((self.host, self.port))
            print(f"Conectado al servidor {self.host}:{self.port}, iniciando transmisión...")

            self.running = True
            self.send_stream()

        except Exception as e:
            print(f"Error de conexión: {e}")
        finally:
            self.sock.close()

    def capture_screen(self):
        """ Captura la pantalla principal """
        screenshot = pyautogui.screenshot()
        frame = np.array(screenshot)
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        return frame

    def send_stream(self):
        """ Captura y envía la pantalla al servidor """
        while self.running:
            frame = self.capture_screen()

            # Comprimir imagen antes de enviarla
            _, img_encoded = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
            img_bytes = img_encoded.tobytes()

            # Enviar tamaño de la imagen
            self.sock.send(len(img_bytes).to_bytes(4, byteorder='big'))
            self.sock.sendall(img_bytes)

def verificar_puerto_firewall(puerto):
    """
    Verifica si un puerto específico ya está permitido en el Firewall de Windows.
    """
    try:
        fw_policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rules = fw_policy.Rules

        for rule in rules:
            if rule.Enabled and rule.LocalPorts and str(puerto) in rule.LocalPorts.split(','):
                print(f"✅ El puerto {puerto} ya está permitido en el firewall.")
                return True

        print(f"❌ El puerto {puerto} no está en el firewall.")
        return False
    except Exception as e:
        print(f"Error al verificar el puerto: {e}")
        return False


def agregar_puerto_firewall(puerto, nombre_regla="ReglaPythonFirewall", protocolo="TCP"):
    """
    Agrega una nueva regla al Firewall de Windows para permitir el puerto especificado.
    """
    try:
        if verificar_puerto_firewall(puerto):
            return False

        fw_policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rules = fw_policy.Rules
        new_rule = win32com.client.Dispatch("HNetCfg.FwRule")

        # Configurar la nueva regla
        new_rule.Name = nombre_regla
        new_rule.Description = "Regla creada automáticamente con Python"
        new_rule.Protocol = 6 if protocolo.upper() == "TCP" else 17  # 6 = TCP, 17 = UDP
        new_rule.LocalPorts = str(puerto)
        new_rule.Direction = 1  # 1 = Entrada (Inbound)
        new_rule.Action = 1  # 1 = Permitir (Allow)
        new_rule.Enabled = True

        # Agregar la regla al Firewall
        rules.Add(new_rule)
        print(f"✅ El puerto {puerto} ha sido agregado correctamente al firewall.")
        return True

    except Exception as e:
        print(f"Error al agregar el puerto: {e}")
        return False
if __name__ == "__main__":

    puerto = 9000

    puerto = int(puerto)
    if agregar_puerto_firewall(puerto):
        print("🎉 Operación completada con éxito.")
    else:
        print("⚠️ No se realizó ningún cambio o hubo un error.")

    
    parser = argparse.ArgumentParser(description="Cliente para compartir pantalla.")
    parser.add_argument("host", type=str, help="Dirección IP del servidor")
    parser.add_argument("port", type=int, help="Puerto del servidor")
    args = parser.parse_args()

    client = ScreenShareClient(args.host, args.port)
    client.start()
