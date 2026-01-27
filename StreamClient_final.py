import socket
import numpy as np
import cv2
import mss
import argparse
import time
import json
import sys
import threading
import struct
import platform

# Tipos de mensajes del protocolo
MSG_HANDSHAKE = 0x01
MSG_FRAME = 0x02
MSG_COMMAND = 0x03

class ScreenShareClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.running = False
        
        # Parámetros de streaming (controlados por servidor)
        self.fps = 60
        self.quality = 100
        self.resolution_scale = 1.0  # 1.0 = 100%, 0.5 = 50%
        self.params_lock = threading.Lock()
        
        # Detección de familia de direcciones
        self.address_family = self.detect_address_family(host)
        
        # Instancia de mss para captura rápida
        self.sct = mss.mss()
        self.monitors = self.sct.monitors[1:]  # Todos los monitores (sin el virtual)
        
    def detect_address_family(self, host):
        """Detecta si el host es IPv4, IPv6 o un hostname"""
        try:
            addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            
            if addr_info:
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
        
        return socket.AF_INET

    def send_message(self, sock, msg_type, payload):
        """Envía un mensaje con header tipado"""
        payload_bytes = payload if isinstance(payload, bytes) else payload.encode('utf-8')
        
        # Header: [4 bytes tamaño total] [1 byte tipo] [payload]
        total_size = len(payload_bytes)
        header = struct.pack('!IB', total_size, msg_type)
        
        sock.sendall(header + payload_bytes)
    
    def recv_message(self, sock):
        """Recibe un mensaje y retorna (tipo, payload)"""
        # Leer header (5 bytes)
        header = b''
        while len(header) < 5:
            chunk = sock.recv(5 - len(header))
            if not chunk:
                return None, None
            header += chunk
        
        total_size, msg_type = struct.unpack('!IB', header)
        
        # Leer payload
        payload = b''
        while len(payload) < total_size:
            chunk = sock.recv(min(total_size - len(payload), 4096))
            if not chunk:
                return None, None
            payload += chunk
        
        return msg_type, payload

    def start(self):
        """Inicia la conexión y transmisión"""
        try:
            # Crear socket con optimizaciones
            sock = socket.socket(self.address_family, socket.SOCK_STREAM)
            
            # OPTIMIZACIÓN: TCP_NODELAY para reducir latencia
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Conectar al servidor
            if self.address_family == socket.AF_INET6:
                try:
                    sock.connect((self.host, self.port, 0, 0))
                except (OSError, ValueError):
                    sock.connect((self.host, self.port))
            else:
                sock.connect((self.host, self.port))
            
            print(f"✅ Conectado al servidor {self.host}:{self.port}")
            
            # Enviar handshake con información de monitores
            self.send_handshake(sock)
            
            self.running = True
            
            # Thread para recibir comandos del servidor
            command_thread = threading.Thread(target=self.receive_commands, args=(sock,), daemon=True)
            command_thread.start()
            
            # Iniciar transmisión (thread principal)
            self.send_stream(sock)

        except KeyboardInterrupt:
            print("\n\n⏹️ Conexión interrumpida por el usuario.")
        except Exception as e:
            print(f"❌ Error de conexión: {e}")
        finally:
            self.running = False
            try:
                sock.close()
            except:
                pass
            self.sct.close()

    def send_handshake(self, sock):
        """Envía información inicial al servidor"""
        monitors_info = []
        for i, monitor in enumerate(self.monitors, 1):
            monitors_info.append({
                "id": i,
                "width": monitor['width'],
                "height": monitor['height'],
                "left": monitor['left'],
                "top": monitor['top']
            })
        
        handshake = {
            "type": "handshake",
            "hostname": platform.node(),
            "monitors": monitors_info
        }
        
        handshake_json = json.dumps(handshake)
        self.send_message(sock, MSG_HANDSHAKE, handshake_json)
        
        print(f"📤 Handshake enviado: {len(monitors_info)} monitor(es)")
        for i, m in enumerate(monitors_info, 1):
            print(f"   Monitor {i}: {m['width']}x{m['height']}")

    def receive_commands(self, sock):
        """Thread que recibe comandos del servidor"""
        print("👂 Escuchando comandos del servidor...")
        
        while self.running:
            try:
                msg_type, payload = self.recv_message(sock)
                
                if msg_type is None:
                    break
                
                if msg_type == MSG_COMMAND:
                    command = json.loads(payload.decode('utf-8'))
                    self.handle_command(command)
                
            except Exception as e:
                if self.running:
                    print(f"❌ Error recibiendo comando: {e}")
                break
        
        print("👂 Thread de comandos finalizado")

    def handle_command(self, command):
        """Procesa comandos del servidor"""
        cmd_type = command.get('command')
        value = command.get('value')
        
        with self.params_lock:
            if cmd_type == 'set_fps':
                old_fps = self.fps
                self.fps = int(value)
                print(f"🎬 FPS actualizado: {old_fps} → {self.fps}")
                
            elif cmd_type == 'set_quality':
                old_quality = self.quality
                self.quality = int(value)
                print(f"🎨 Calidad actualizada: {old_quality}% → {self.quality}%")
                
            elif cmd_type == 'set_resolution':
                old_scale = self.resolution_scale
                self.resolution_scale = float(value)
                print(f"📐 Escala de resolución actualizada: {old_scale*100:.0f}% → {self.resolution_scale*100:.0f}%")

    def capture_screen(self, monitor_index):
        """Captura la pantalla usando mss"""
        monitor = self.monitors[monitor_index]
        img = self.sct.grab(monitor)
        
        # Convertir a numpy array
        frame = np.array(img)
        
        # mss devuelve BGRA, convertir a BGR para OpenCV
        frame = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
        
        # Aplicar escala de resolución si es necesario
        with self.params_lock:
            scale = self.resolution_scale
        
        if scale != 1.0:
            new_width = int(frame.shape[1] * scale)
            new_height = int(frame.shape[0] * scale)
            frame = cv2.resize(frame, (new_width, new_height), interpolation=cv2.INTER_LINEAR)
        
        return frame

    def send_stream(self, sock):
        """Captura y envía frames con control dinámico de FPS"""
        print(f"🎥 Iniciando transmisión...")
        print(f"   FPS inicial: {self.fps}")
        print(f"   Calidad inicial: {self.quality}%")
        print(f"   Resolución inicial: {self.resolution_scale*100:.0f}%")
        print("Presiona Ctrl+C para detener...")
        
        try:
            while self.running:
                loop_start = time.time()
                
                # Obtener parámetros actuales
                with self.params_lock:
                    current_fps = self.fps
                    current_quality = self.quality
                
                frame_time = 1.0 / current_fps if current_fps > 0 else 0.033
                
                # Enviar frame de cada monitor
                for monitor_idx in range(len(self.monitors)):
                    # Capturar pantalla
                    frame = self.capture_screen(monitor_idx)
                    
                    # Comprimir imagen
                    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), current_quality]
                    _, img_encoded = cv2.imencode('.jpg', frame, encode_params)
                    img_bytes = img_encoded.tobytes()
                    
                    # Crear payload del frame
                    frame_data = {
                        "monitor_id": monitor_idx + 1,  # 1-indexed para el servidor
                        "width": frame.shape[1],
                        "height": frame.shape[0],
                        "frame_size": len(img_bytes)
                    }
                    frame_header = json.dumps(frame_data)
                    
                    # Enviar como mensaje tipo FRAME
                    # Formato: [header JSON][frame bytes]
                    combined = frame_header.encode('utf-8') + b'\n' + img_bytes
                    self.send_message(sock, MSG_FRAME, combined)
                
                # Control de FPS
                elapsed = time.time() - loop_start
                if elapsed < frame_time:
                    time.sleep(frame_time - elapsed)
                    
        except Exception as e:
            print(f"\n❌ Error enviando frames: {e}")
        finally:
            self.running = False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cliente de Screen Sharing con control remoto (IPv4/IPv6).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python StreamClient_final.py 192.168.1.10 9000
  python StreamClient_final.py ::1 9000  # IPv6 localhost
  
Nota: FPS, calidad y resolución se controlan desde el servidor.
        """
    )
    
    parser.add_argument("host", type=str, 
                       help="Dirección IP del servidor (IPv4, IPv6 o hostname)")
    parser.add_argument("port", type=int, 
                       help="Puerto del servidor")
    
    args = parser.parse_args()
    
    # Crear y ejecutar cliente
    client = ScreenShareClient(args.host, args.port)
    client.start()
