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
        self.running = False
        
        # MODIFICACIÓN PARA IPv4/IPv6:
        # Detectar la familia de direcciones apropiada
        self.address_family = self.detect_address_family(host)
        self.sock = socket.socket(self.address_family, socket.SOCK_STREAM)

    def detect_address_family(self, host):
        """
        Detecta si el host es IPv4, IPv6 o un hostname y retorna la familia de direcciones apropiada.
        """
        try:
            # Intentar resolver el host para obtener información de direcciones
            addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            
            if addr_info:
                # Usar la primera dirección disponible
                family = addr_info[0][0]
                resolved_host = addr_info[0][4][0]
                
                if family == socket.AF_INET6:
                    print(f"✅ Detectado IPv6: {resolved_host}")
                    return socket.AF_INET6
                else:
                    print(f"✅ Detectado IPv4: {resolved_host}")
                    return socket.AF_INET
            
        except socket.gaierror as e:
            print(f"⚠️ Error resolviendo host '{host}': {e}")
            print("Usando IPv4 por defecto...")
        
        # Por defecto, usar IPv4
        return socket.AF_INET

    def start(self):
        try:
            # Para IPv6, necesitamos usar tupla de 4 elementos en algunos casos
            if self.address_family == socket.AF_INET6:
                # Intentar conectar con formato IPv6
                try:
                    self.sock.connect((self.host, self.port, 0, 0))
                except (OSError, ValueError):
                    # Si falla, intentar con formato simple
                    self.sock.connect((self.host, self.port))
            else:
                # IPv4 usa formato simple
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
            try:
                frame = self.capture_screen()

                # Comprimir imagen antes de enviarla
                _, img_encoded = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
                img_bytes = img_encoded.tobytes()

                # Enviar tamaño de la imagen
                self.sock.send(len(img_bytes).to_bytes(4, byteorder='big'))
                self.sock.sendall(img_bytes)
            except Exception as e:
                print(f"Error enviando frame: {e}")
                break

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
    Incluye soporte para IPv4 e IPv6.
    """
    try:
        if verificar_puerto_firewall(puerto):
            return False

        fw_policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rules = fw_policy.Rules
        
        # Crear regla para IPv4
        new_rule_v4 = win32com.client.Dispatch("HNetCfg.FwRule")
        new_rule_v4.Name = f"{nombre_regla}_IPv4"
        new_rule_v4.Description = "Regla creada automáticamente con Python para IPv4"
        new_rule_v4.Protocol = 6 if protocolo.upper() == "TCP" else 17  # 6 = TCP, 17 = UDP
        new_rule_v4.LocalPorts = str(puerto)
        new_rule_v4.Direction = 1  # 1 = Entrada (Inbound)
        new_rule_v4.Action = 1  # 1 = Permitir (Allow)
        new_rule_v4.Enabled = True
        new_rule_v4.Profiles = 7  # Todos los perfiles (Domain, Private, Public)
        rules.Add(new_rule_v4)
        
        # Crear regla para IPv6
        new_rule_v6 = win32com.client.Dispatch("HNetCfg.FwRule")
        new_rule_v6.Name = f"{nombre_regla}_IPv6"
        new_rule_v6.Description = "Regla creada automáticamente con Python para IPv6"
        new_rule_v6.Protocol = 6 if protocolo.upper() == "TCP" else 17
        new_rule_v6.LocalPorts = str(puerto)
        new_rule_v6.Direction = 1
        new_rule_v6.Action = 1
        new_rule_v6.Enabled = True
        new_rule_v6.Profiles = 7
        rules.Add(new_rule_v6)
        
        print(f"✅ El puerto {puerto} ha sido agregado correctamente al firewall (IPv4 e IPv6).")
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

    
    parser = argparse.ArgumentParser(description="Cliente para compartir pantalla (IPv4/IPv6 compatible).")
    parser.add_argument("host", type=str, help="Dirección IP del servidor (IPv4, IPv6 o hostname)")
    parser.add_argument("port", type=int, help="Puerto del servidor")
    args = parser.parse_args()

    client = ScreenShareClient(args.host, args.port)
    client.start()
