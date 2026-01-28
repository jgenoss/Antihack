import configparser
import os
import socket
import threading
import sys
import cv2
import numpy as np
import customtkinter as ctk
from PIL import Image, ImageTk
from datetime import datetime

class ScreenShareServerGUI:
    def __init__(self):
        # Configuracion de customtkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Ventana principal
        self.root = ctk.CTk()
        self.root.title("Screen Share Server - IPv4/IPv6")
        self.root.geometry("1000x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Variables del servidor
        self.config_file = "config.ini"
        self.host, self.port, self.network_config = self.load_config()
        self.running = False
        self.sock = None
        self.clients = {}
        self.current_viewing_window = None
        self.current_viewing_client = None
        self.address_family = None
        self.dual_stack_enabled = False

        # Crear UI PRIMERO
        self.create_ui()

        # Ahora si detectar familia de direcciones (despues de crear UI)
        self.address_family, self.dual_stack_enabled = self.detect_address_family(self.host)

    def detect_address_family(self, host):
        """
        Detecta si el host es IPv4, IPv6 o debe usar dual-stack.
        Retorna: (address_family, dual_stack_enabled)
        """
        dual_stack = self.network_config.get('dual_stack', True)
        prefer_ipv6 = self.network_config.get('prefer_ipv6', True)

        # Caso 1: Direcciones especiales para dual-stack
        if host in ['::', '0.0.0.0', '']:
            if self._supports_ipv6():
                self.log_message("Modo dual-stack (IPv4 e IPv6)", "info")
                return socket.AF_INET6, True
            else:
                self.log_message("IPv6 no disponible, usando solo IPv4", "warning")
                return socket.AF_INET, False

        # Caso 2: Direccion IPv6 explicita
        if self._is_ipv6_address(host):
            self.log_message(f"IPv6 detectado: {host}", "info")
            return socket.AF_INET6, False

        # Caso 3: Direccion IPv4 explicita
        if self._is_ipv4_address(host):
            self.log_message(f"IPv4 detectado: {host}", "info")
            return socket.AF_INET, False

        # Caso 4: Hostname - resolver y determinar familia
        try:
            addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addr_info:
                # Separar direcciones IPv4 e IPv6
                ipv4_addrs = [info for info in addr_info if info[0] == socket.AF_INET]
                ipv6_addrs = [info for info in addr_info if info[0] == socket.AF_INET6]

                if ipv6_addrs and prefer_ipv6 and self._supports_ipv6():
                    self.log_message(f"Hostname resuelto a IPv6: {host}", "info")
                    return socket.AF_INET6, False
                elif ipv4_addrs:
                    self.log_message(f"Hostname resuelto a IPv4: {host}", "info")
                    return socket.AF_INET, False
                elif ipv6_addrs:
                    self.log_message(f"Solo IPv6 disponible para: {host}", "info")
                    return socket.AF_INET6, False

        except socket.gaierror as e:
            self.log_message(f"Error resolviendo host '{host}': {e}", "warning")

        # Fallback: IPv4
        self.log_message("Usando IPv4 por defecto", "warning")
        return socket.AF_INET, False

    def _supports_ipv6(self):
        """Verifica si el sistema soporta IPv6."""
        try:
            # Verificar si el modulo socket tiene soporte IPv6
            if not socket.has_ipv6:
                return False

            # Intentar crear un socket IPv6
            test_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            test_sock.close()
            return True
        except (socket.error, OSError):
            return False

    def _is_ipv6_address(self, addr):
        """Verifica si una cadena es una direccion IPv6 valida."""
        try:
            # Remover brackets si existen [::1] -> ::1
            clean_addr = addr.strip('[]')
            socket.inet_pton(socket.AF_INET6, clean_addr)
            return True
        except (socket.error, OSError):
            return False

    def _is_ipv4_address(self, addr):
        """Verifica si una cadena es una direccion IPv4 valida."""
        try:
            socket.inet_pton(socket.AF_INET, addr)
            return True
        except (socket.error, OSError):
            return False

    def get_bind_address(self):
        """Obtiene la direccion apropiada para bind() segun la familia de direcciones."""
        if self.address_family == socket.AF_INET6:
            # Para dual-stack, usar ::
            if self.dual_stack_enabled or self.host in ['0.0.0.0', '']:
                return '::'
            # Remover brackets si existen
            return self.host.strip('[]')
        else:
            # IPv4
            if self.host == '::':
                return '0.0.0.0'
            return self.host

    def load_config(self):
        """Lee la IP y el puerto desde config.ini, o crea uno por defecto."""
        config = configparser.ConfigParser()
        network_config = {
            'prefer_ipv6': True,
            'dual_stack': True,
            'connection_timeout': 10000,
            'retry_count': 5
        }

        if not os.path.exists(self.config_file):
            config["server"] = {"host": "::", "port": "9000"}
            config["network"] = {
                "prefer_ipv6": "true",
                "dual_stack": "true",
                "connection_timeout": "10000",
                "retry_count": "5"
            }
            with open(self.config_file, "w") as configfile:
                config.write(configfile)

        config.read(self.config_file)

        # Leer configuracion del servidor
        host = config.get("server", "host", fallback="::")
        port = int(config.get("server", "port", fallback="9000"))

        # Leer configuracion de red avanzada
        if config.has_section("network"):
            network_config['prefer_ipv6'] = config.getboolean("network", "prefer_ipv6", fallback=True)
            network_config['dual_stack'] = config.getboolean("network", "dual_stack", fallback=True)
            network_config['connection_timeout'] = config.getint("network", "connection_timeout", fallback=10000)
            network_config['retry_count'] = config.getint("network", "retry_count", fallback=5)

        return host, port, network_config

    def create_ui(self):
        """Crea la interfaz gráfica completa"""
        
        # Header con información del servidor
        header_frame = ctk.CTkFrame(self.root, corner_radius=10)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        title_label = ctk.CTkLabel(
            header_frame, 
            text="🖥️ Screen Share Server",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=10)
        
        # Frame para información del servidor
        info_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        info_frame.pack(pady=5, padx=20, fill="x")
        
        self.status_label = ctk.CTkLabel(
            info_frame,
            text="⚪ Estado: Detenido",
            font=ctk.CTkFont(size=14)
        )
        self.status_label.pack(side="left", padx=10)
        
        self.address_label = ctk.CTkLabel(
            info_frame,
            text=f"📡 Dirección: {self.host}:{self.port}",
            font=ctk.CTkFont(size=14)
        )
        self.address_label.pack(side="left", padx=10)
        
        self.clients_count_label = ctk.CTkLabel(
            info_frame,
            text="👥 Clientes: 0",
            font=ctk.CTkFont(size=14)
        )
        self.clients_count_label.pack(side="left", padx=10)
        
        # Botones de control
        control_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        control_frame.pack(pady=10)
        
        self.start_button = ctk.CTkButton(
            control_frame,
            text="▶️ Iniciar Servidor",
            command=self.start_server,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="green",
            hover_color="darkgreen"
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ctk.CTkButton(
            control_frame,
            text="⏹️ Detener Servidor",
            command=self.stop_server,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="red",
            hover_color="darkred",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
        # Frame principal con dos columnas
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Columna izquierda - Lista de clientes
        left_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        clients_header = ctk.CTkLabel(
            left_frame,
            text="👥 Clientes Conectados",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        clients_header.pack(pady=10)
        
        # Frame scrollable para la lista de clientes
        self.clients_scrollframe = ctk.CTkScrollableFrame(
            left_frame,
            label_text="",
            label_fg_color="transparent"
        )
        self.clients_scrollframe.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Columna derecha - Log de actividad
        right_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        log_header = ctk.CTkLabel(
            right_frame,
            text="📋 Log de Actividad",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        log_header.pack(pady=10)
        
        # Textbox para el log
        self.log_text = ctk.CTkTextbox(
            right_frame,
            wrap="word",
            font=ctk.CTkFont(size=12)
        )
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Botón para limpiar log
        clear_log_button = ctk.CTkButton(
            right_frame,
            text="🗑️ Limpiar Log",
            command=self.clear_log,
            width=120,
            height=30
        )
        clear_log_button.pack(pady=5)
        
        # Footer
        footer_frame = ctk.CTkFrame(self.root, height=30, corner_radius=0)
        footer_frame.pack(fill="x", side="bottom")
        
        footer_label = ctk.CTkLabel(
            footer_frame,
            text="IPv4/IPv6 Compatible • Screen Share Server v2.0",
            font=ctk.CTkFont(size=10)
        )
        footer_label.pack(pady=5)

    def log_message(self, message, level="info"):
        """Agrega un mensaje al log con timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Colores según el nivel
        colors = {
            "info": "#FFFFFF",
            "success": "#00FF00",
            "warning": "#FFA500",
            "error": "#FF0000"
        }
        
        color = colors.get(level, "#FFFFFF")
        formatted_message = f"[{timestamp}] {message}\n"
        
        # Insertar en el textbox
        self.log_text.insert("end", formatted_message)
        self.log_text.see("end")  # Auto-scroll
        
    def clear_log(self):
        """Limpia el log de actividad"""
        self.log_text.delete("1.0", "end")
        self.log_message("Log limpiado", "info")

    def disconnect_client(self, addr_str):
        """Desconecta un cliente específico"""
        try:
            if addr_str in self.clients:
                # Obtener el socket del cliente
                client_data = self.clients[addr_str]
                if isinstance(client_data, tuple):
                    client_sock = client_data[0]
                else:
                    client_sock = client_data
                
                # Cerrar la conexión
                client_sock.close()
                
                # Eliminar de la lista
                del self.clients[addr_str]
                
                # Log y actualizar UI
                self.log_message(f"🔌 Cliente desconectado manualmente: {addr_str}", "warning")
                self.update_clients_list()
                
        except Exception as e:
            self.log_message(f"❌ Error desconectando cliente {addr_str}: {e}", "error")

    def update_clients_list(self):
        """Actualiza la lista visual de clientes"""
        # Limpiar lista actual
        for widget in self.clients_scrollframe.winfo_children():
            widget.destroy()
        
        if not self.clients:
            no_clients_label = ctk.CTkLabel(
                self.clients_scrollframe,
                text="⏳ Esperando clientes...",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            )
            no_clients_label.pack(pady=20)
        else:
            for addr_str in self.clients.keys():
                self.create_client_card(addr_str)
        
        # Actualizar contador
        self.clients_count_label.configure(text=f"👥 Clientes: {len(self.clients)}")

    def create_client_card(self, addr_str):
        """Crea una tarjeta visual para cada cliente"""
        card_frame = ctk.CTkFrame(self.clients_scrollframe, corner_radius=8)
        card_frame.pack(fill="x", padx=5, pady=5)
        
        # Información del cliente
        info_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        # Icono y dirección
        addr_label = ctk.CTkLabel(
            info_frame,
            text=f"🖥️ {addr_str}",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w"
        )
        addr_label.pack(anchor="w")
        
        # Estado
        status_label = ctk.CTkLabel(
            info_frame,
            text="🟢 Conectado",
            font=ctk.CTkFont(size=11),
            text_color="lightgreen",
            anchor="w"
        )
        status_label.pack(anchor="w", pady=(2, 0))
        
        # Frame para botones
        buttons_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
        buttons_frame.pack(side="right", padx=10)
        
        # Botón para ver pantalla
        view_button = ctk.CTkButton(
            buttons_frame,
            text="👁️ Ver",
            command=lambda: self.view_client_screen(addr_str),
            width=100,
            height=35,
            fg_color="#1f6aa5",
            hover_color="#144870"
        )
        view_button.pack(side="left", padx=2)
        
        # Botón para desconectar
        disconnect_button = ctk.CTkButton(
            buttons_frame,
            text="🔌 Desconectar",
            command=lambda: self.disconnect_client(addr_str),
            width=120,
            height=35,
            fg_color="#c41e3a",
            hover_color="#8b0000"
        )
        disconnect_button.pack(side="left", padx=2)

    def start_server(self):
        """Inicia el servidor con soporte mejorado para IPv4/IPv6."""
        try:
            self.sock = socket.socket(self.address_family, socket.SOCK_STREAM)

            # Configuracion dual-stack para IPv6
            if self.address_family == socket.AF_INET6:
                if self.dual_stack_enabled:
                    try:
                        # IPV6_V6ONLY=0 permite aceptar conexiones IPv4 en socket IPv6
                        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                        self.log_message("Modo dual-stack habilitado (IPv4 + IPv6)", "success")
                    except (AttributeError, OSError) as e:
                        self.log_message(f"Dual-stack no disponible: {e}", "warning")
                        self.log_message("El servidor solo aceptara conexiones IPv6", "warning")
                else:
                    try:
                        # Modo solo IPv6
                        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        self.log_message("Modo solo IPv6 habilitado", "info")
                    except (AttributeError, OSError):
                        pass

            # Permitir reutilizar direccion (evita error "Address already in use")
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Obtener direccion de bind
            bind_address = self.get_bind_address()

            # Intentar bind con manejo de errores especifico
            try:
                self.sock.bind((bind_address, self.port))
            except socket.error as bind_error:
                # Si falla IPv6 dual-stack, intentar IPv4 como fallback
                if self.address_family == socket.AF_INET6 and self.dual_stack_enabled:
                    self.log_message(f"Bind IPv6 fallo: {bind_error}", "warning")
                    self.log_message("Intentando fallback a IPv4...", "info")

                    self.sock.close()
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.sock.bind(('0.0.0.0', self.port))
                    self.address_family = socket.AF_INET
                    self.dual_stack_enabled = False
                    bind_address = '0.0.0.0'
                    self.log_message("Fallback a IPv4 exitoso", "success")
                else:
                    raise

            self.sock.listen(5)
            self.running = True

            # Actualizar UI
            self.status_label.configure(text="Estado: Activo")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")

            # Mensaje de estado
            family_str = "IPv6" if self.address_family == socket.AF_INET6 else "IPv4"
            self.log_message(f"Servidor iniciado en {bind_address}:{self.port} ({family_str})", "success")

            if self.dual_stack_enabled:
                self.log_message("Escuchando conexiones IPv4 e IPv6", "success")

            # Mostrar IPs locales disponibles
            self._show_local_addresses()

            # Iniciar thread para aceptar clientes
            threading.Thread(target=self.accept_clients, daemon=True).start()

        except Exception as e:
            error_msg = str(e)
            if "Address already in use" in error_msg:
                self.log_message(f"Puerto {self.port} ya esta en uso", "error")
            elif "Permission denied" in error_msg:
                self.log_message(f"Sin permisos para puerto {self.port} (requiere root para <1024)", "error")
            else:
                self.log_message(f"Error al iniciar servidor: {e}", "error")

    def _show_local_addresses(self):
        """Muestra las direcciones IP locales donde el servidor es accesible."""
        try:
            hostname = socket.gethostname()
            # Obtener todas las direcciones
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

            ipv4_addrs = set()
            ipv6_addrs = set()

            for info in addr_info:
                family, _, _, _, sockaddr = info
                if family == socket.AF_INET:
                    ipv4_addrs.add(sockaddr[0])
                elif family == socket.AF_INET6:
                    addr = sockaddr[0]
                    # Filtrar direcciones link-local
                    if not addr.startswith('fe80'):
                        ipv6_addrs.add(addr)

            if ipv4_addrs:
                self.log_message(f"IPv4 disponibles: {', '.join(ipv4_addrs)}", "info")
            if ipv6_addrs and self.address_family == socket.AF_INET6:
                self.log_message(f"IPv6 disponibles: {', '.join(ipv6_addrs)}", "info")

        except Exception:
            pass  # No es critico si falla

    def stop_server(self):
        """Detiene el servidor"""
        self.running = False
        
        if self.sock:
            self.sock.close()
        
        # Cerrar todas las conexiones de clientes
        for addr_str, client_data in list(self.clients.items()):
            if isinstance(client_data, tuple):
                client_sock = client_data[0]
            else:
                client_sock = client_data
            try:
                client_sock.close()
            except:
                pass
        
        self.clients.clear()
        
        # Cerrar ventana de visualización si está abierta
        if self.current_viewing_window:
            cv2.destroyAllWindows()
            self.current_viewing_window = None
        
        # Actualizar UI
        self.status_label.configure(text="⚪ Estado: Detenido")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.update_clients_list()
        
        self.log_message("🛑 Servidor detenido", "warning")

    def accept_clients(self):
        """Acepta múltiples clientes y crea un hilo para cada uno"""
        while self.running:
            try:
                client_sock, addr = self.sock.accept()
                addr_str = self.format_address(addr)
                
                self.log_message(f"✅ Cliente conectado: {addr_str}", "success")
                self.clients[addr_str] = client_sock
                
                # Actualizar lista en UI
                self.root.after(0, self.update_clients_list)
                
                # Iniciar thread para recibir stream
                threading.Thread(
                    target=self.receive_stream,
                    args=(client_sock, addr_str),
                    daemon=True
                ).start()
                
            except Exception as e:
                if self.running:
                    self.log_message(f"⚠️ Error aceptando cliente: {e}", "warning")

    def format_address(self, addr):
        """
        Formatea la direccion del cliente de manera legible.
        Maneja direcciones IPv4, IPv6, y IPv4-mapped IPv6 (::ffff:x.x.x.x)
        """
        if len(addr) == 2:
            # IPv4: (ip, port)
            return f"{addr[0]}:{addr[1]}"
        elif len(addr) == 4:
            # IPv6: (ip, port, flowinfo, scope_id)
            ip = addr[0]
            port = addr[1]

            # Convertir IPv4-mapped IPv6 a formato IPv4 legible
            # ::ffff:192.168.1.1 -> 192.168.1.1
            if ip.startswith('::ffff:'):
                ipv4_addr = ip[7:]  # Remover prefijo ::ffff:
                return f"{ipv4_addr}:{port} (via IPv6)"

            return f"[{ip}]:{port}"
        else:
            return str(addr)

    def receive_stream(self, client_sock, addr_str):
        """Recibe y almacena el stream de cada cliente"""
        while self.running:
            try:
                # Recibir tamaño de imagen
                data = client_sock.recv(4)
                if not data:
                    break
                
                frame_size = int.from_bytes(data, byteorder='big')
                frame_data = b''

                while len(frame_data) < frame_size:
                    packet = client_sock.recv(min(frame_size - len(frame_data), 4096))
                    if not packet:
                        break
                    frame_data += packet

                # Convertir imagen y almacenarla
                frame = np.frombuffer(frame_data, dtype=np.uint8)
                frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

                if frame is not None:
                    self.clients[addr_str] = (client_sock, frame)
                    
            except Exception as e:
                break

        # Cliente desconectado
        self.log_message(f"❌ Cliente desconectado: {addr_str}", "error")
        if addr_str in self.clients:
            del self.clients[addr_str]
        
        # Actualizar UI
        self.root.after(0, self.update_clients_list)

    def view_client_screen(self, addr_str):
        """Muestra la pantalla del cliente seleccionado en una ventana OpenCV"""
        self.log_message(f"👁️ Viendo pantalla de: {addr_str}", "info")
        self.current_viewing_client = addr_str
        
        # Iniciar thread para mostrar el stream
        threading.Thread(
            target=self._view_stream_thread,
            args=(addr_str,),
            daemon=True
        ).start()

    def _view_stream_thread(self, addr_str):
        """Thread para mostrar el stream del cliente"""
        window_name = f"Pantalla de {addr_str}"
        
        while self.running and self.current_viewing_client == addr_str:
            if addr_str in self.clients and isinstance(self.clients[addr_str], tuple):
                _, frame = self.clients[addr_str]
                
                cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
                cv2.imshow(window_name, frame)
                
                # Presionar 'q' para cerrar
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    self.log_message(f"👁️ Cerrada visualización de: {addr_str}", "info")
                    break
            else:
                # Cliente ya no disponible
                break
        
        cv2.destroyWindow(window_name)
        self.current_viewing_client = None

    def on_closing(self):
        """Maneja el cierre de la aplicación"""
        if self.running:
            self.stop_server()
        
        cv2.destroyAllWindows()
        self.root.destroy()

    def run(self):
        """Inicia la aplicación"""
        self.log_message("🎉 Aplicación iniciada", "success")
        self.log_message(f"📝 Configuración: {self.host}:{self.port}", "info")
        self.root.mainloop()

if __name__ == "__main__":
    app = ScreenShareServerGUI()
    app.run()