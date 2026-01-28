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
        self.root.title("Screen Share Server - IPv4 + IPv6")
        self.root.geometry("1000x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Variables del servidor
        self.config_file = "config.ini"
        self.ipv4_host, self.ipv6_host, self.port, self.network_config = self.load_config()
        self.running = False

        # Sockets duales - servidor escucha en AMBOS simultaneamente
        self.sock_ipv4 = None
        self.sock_ipv6 = None

        self.clients = {}
        self.current_viewing_window = None
        self.current_viewing_client = None

        # Crear UI PRIMERO
        self.create_ui()

        # Mostrar configuracion detectada
        self._show_config_info()

    def _show_config_info(self):
        """Muestra informacion de la configuracion detectada."""
        self.log_message("Modo servidor: Listeners duales (IPv4 + IPv6)", "info")

        if self.ipv4_host:
            self.log_message(f"  IPv4: {self.ipv4_host}:{self.port}", "info")
        else:
            self.log_message("  IPv4: Deshabilitado", "warning")

        if self.ipv6_host:
            ipv6_supported = "OK" if self._supports_ipv6() else "NO SOPORTADO"
            self.log_message(f"  IPv6: [{self.ipv6_host}]:{self.port} ({ipv6_supported})", "info")
        else:
            self.log_message("  IPv6: Deshabilitado", "warning")

    def _supports_ipv6(self):
        """Verifica si el sistema soporta IPv6."""
        try:
            if not socket.has_ipv6:
                return False
            test_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            test_sock.close()
            return True
        except (socket.error, OSError):
            return False

    def _is_ipv6_address(self, addr):
        """Verifica si una cadena es una direccion IPv6 valida."""
        if not addr:
            return False
        try:
            clean_addr = addr.strip('[]')
            socket.inet_pton(socket.AF_INET6, clean_addr)
            return True
        except (socket.error, OSError):
            return False

    def _is_ipv4_address(self, addr):
        """Verifica si una cadena es una direccion IPv4 valida."""
        if not addr:
            return False
        try:
            socket.inet_pton(socket.AF_INET, addr)
            return True
        except (socket.error, OSError):
            return False

    def load_config(self):
        """Lee la configuracion desde config.ini."""
        config = configparser.ConfigParser()
        network_config = {
            'priority': 'ipv4',
            'fallback': True,
            'connection_timeout': 10000,
            'retry_count': 5
        }

        if not os.path.exists(self.config_file):
            config["server"] = {
                "ipv4_host": "0.0.0.0",
                "ipv6_host": "::",
                "port": "9000"
            }
            config["network"] = {
                "priority": "ipv4",
                "fallback": "true",
                "connection_timeout": "10000",
                "retry_count": "5"
            }
            with open(self.config_file, "w") as configfile:
                config.write(configfile)

        config.read(self.config_file)

        # Leer configuracion del servidor
        ipv4_host = config.get("server", "ipv4_host", fallback="")
        ipv6_host = config.get("server", "ipv6_host", fallback="")

        # Compatibilidad con formato antiguo (host unico)
        if not ipv4_host and not ipv6_host:
            legacy_host = config.get("server", "host", fallback="0.0.0.0")
            if legacy_host == '::' or (legacy_host and ':' in legacy_host and not legacy_host.startswith('0')):
                ipv6_host = legacy_host
            else:
                ipv4_host = legacy_host

        port = int(config.get("server", "port", fallback="9000"))

        # Leer configuracion de red avanzada
        if config.has_section("network"):
            network_config['priority'] = config.get("network", "priority", fallback="ipv4").lower()
            network_config['fallback'] = config.getboolean("network", "fallback", fallback=True)
            network_config['connection_timeout'] = config.getint("network", "connection_timeout", fallback=10000)
            network_config['retry_count'] = config.getint("network", "retry_count", fallback=5)

        return ipv4_host, ipv6_host, port, network_config

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
        """Inicia el servidor con listeners duales para IPv4 e IPv6."""
        started_any = False

        # Iniciar listener IPv4
        if self.ipv4_host:
            try:
                self.sock_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock_ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock_ipv4.bind((self.ipv4_host, self.port))
                self.sock_ipv4.listen(5)

                self.log_message(f"Listener IPv4 activo: {self.ipv4_host}:{self.port}", "success")
                started_any = True

                # Thread para aceptar clientes IPv4
                threading.Thread(target=self._accept_clients_ipv4, daemon=True).start()

            except Exception as e:
                error_msg = str(e)
                if "Address already in use" in error_msg:
                    self.log_message(f"IPv4: Puerto {self.port} ya en uso", "error")
                else:
                    self.log_message(f"IPv4: Error - {e}", "error")
                self.sock_ipv4 = None

        # Iniciar listener IPv6
        if self.ipv6_host and self._supports_ipv6():
            try:
                self.sock_ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                self.sock_ipv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # IPV6_V6ONLY=1 para que solo acepte IPv6 (IPv4 tiene su propio socket)
                try:
                    self.sock_ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except (AttributeError, OSError):
                    pass

                ipv6_bind = self.ipv6_host.strip('[]')
                self.sock_ipv6.bind((ipv6_bind, self.port))
                self.sock_ipv6.listen(5)

                self.log_message(f"Listener IPv6 activo: [{ipv6_bind}]:{self.port}", "success")
                started_any = True

                # Thread para aceptar clientes IPv6
                threading.Thread(target=self._accept_clients_ipv6, daemon=True).start()

            except Exception as e:
                error_msg = str(e)
                if "Address already in use" in error_msg:
                    self.log_message(f"IPv6: Puerto {self.port} ya en uso", "error")
                else:
                    self.log_message(f"IPv6: Error - {e}", "error")
                self.sock_ipv6 = None
        elif self.ipv6_host and not self._supports_ipv6():
            self.log_message("IPv6: No soportado en este sistema", "warning")

        if started_any:
            self.running = True

            # Actualizar UI
            self.status_label.configure(text="Estado: Activo")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")

            # Mostrar resumen
            active_protocols = []
            if self.sock_ipv4:
                active_protocols.append("IPv4")
            if self.sock_ipv6:
                active_protocols.append("IPv6")

            self.log_message(f"Servidor activo - Protocolos: {' + '.join(active_protocols)}", "success")
            self._show_local_addresses()
        else:
            self.log_message("No se pudo iniciar ningun listener", "error")

    def _accept_clients_ipv4(self):
        """Acepta clientes en el socket IPv4."""
        while self.running and self.sock_ipv4:
            try:
                client_sock, addr = self.sock_ipv4.accept()
                self._handle_new_client(client_sock, addr, "IPv4")
            except Exception as e:
                if self.running:
                    self.log_message(f"Error aceptando cliente IPv4: {e}", "warning")

    def _accept_clients_ipv6(self):
        """Acepta clientes en el socket IPv6."""
        while self.running and self.sock_ipv6:
            try:
                client_sock, addr = self.sock_ipv6.accept()
                self._handle_new_client(client_sock, addr, "IPv6")
            except Exception as e:
                if self.running:
                    self.log_message(f"Error aceptando cliente IPv6: {e}", "warning")

    def _handle_new_client(self, client_sock, addr, protocol):
        """Maneja una nueva conexion de cliente."""
        addr_str = self.format_address(addr)

        self.log_message(f"Cliente conectado ({protocol}): {addr_str}", "success")
        self.clients[addr_str] = client_sock

        # Actualizar lista en UI
        self.root.after(0, self.update_clients_list)

        # Iniciar thread para recibir stream
        threading.Thread(
            target=self.receive_stream,
            args=(client_sock, addr_str),
            daemon=True
        ).start()

    def _show_local_addresses(self):
        """Muestra las direcciones IP locales donde el servidor es accesible."""
        try:
            hostname = socket.gethostname()
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

            ipv4_addrs = set()
            ipv6_addrs = set()

            for info in addr_info:
                family, _, _, _, sockaddr = info
                if family == socket.AF_INET:
                    ipv4_addrs.add(sockaddr[0])
                elif family == socket.AF_INET6:
                    addr = sockaddr[0]
                    if not addr.startswith('fe80'):
                        ipv6_addrs.add(addr)

            if ipv4_addrs and self.sock_ipv4:
                self.log_message(f"  IPv4: {', '.join(ipv4_addrs)}", "info")
            if ipv6_addrs and self.sock_ipv6:
                self.log_message(f"  IPv6: {', '.join(ipv6_addrs)}", "info")

        except Exception:
            pass

    def stop_server(self):
        """Detiene el servidor (ambos listeners)."""
        self.running = False

        # Cerrar socket IPv4
        if self.sock_ipv4:
            try:
                self.sock_ipv4.close()
                self.log_message("Listener IPv4 detenido", "info")
            except:
                pass
            self.sock_ipv4 = None

        # Cerrar socket IPv6
        if self.sock_ipv6:
            try:
                self.sock_ipv6.close()
                self.log_message("Listener IPv6 detenido", "info")
            except:
                pass
            self.sock_ipv6 = None

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

        # Cerrar ventana de visualizacion si esta abierta
        if self.current_viewing_window:
            cv2.destroyAllWindows()
            self.current_viewing_window = None

        # Actualizar UI
        self.status_label.configure(text="Estado: Detenido")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.update_clients_list()

        self.log_message("Servidor detenido", "warning")

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