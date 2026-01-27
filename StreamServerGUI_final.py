import configparser
import os
import socket
import threading
import cv2
import numpy as np
import customtkinter as ctk
from PIL import Image, ImageTk
from datetime import datetime
import json
import struct

# Tipos de mensajes del protocolo
MSG_HANDSHAKE = 0x01
MSG_FRAME = 0x02
MSG_COMMAND = 0x03

class ClientControlPanel(ctk.CTkFrame):
    """Panel de control para un cliente específico"""
    def __init__(self, master, client_id, on_change_callback, on_disconnect_callback):
        super().__init__(master, corner_radius=10, fg_color="#2b2b2b")
        
        self.client_id = client_id
        self.on_change = on_change_callback
        self.on_disconnect = on_disconnect_callback
        
        # Valores actuales
        self.fps_value = 60
        self.quality_value = 100
        self.resolution_value = 1.0
        
        self.create_ui()
    
    def create_ui(self):
        """Crea los controles del panel"""
        
        # Título
        title = ctk.CTkLabel(
            self,
            text=f"⚙️ Controles - {self.client_id}",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        title.pack(pady=5, padx=10, anchor="w")
        
        # Separador
        separator = ctk.CTkFrame(self, height=2, fg_color="#444444")
        separator.pack(fill="x", padx=10, pady=5)
        
        # FPS Control
        fps_frame = ctk.CTkFrame(self, fg_color="transparent")
        fps_frame.pack(fill="x", padx=10, pady=5)
        
        self.fps_label = ctk.CTkLabel(
            fps_frame,
            text=f"🎬 FPS: {self.fps_value}",
            font=ctk.CTkFont(size=11)
        )
        self.fps_label.pack(side="left")
        
        self.fps_slider = ctk.CTkSlider(
            fps_frame,
            from_=10,
            to=60,
            number_of_steps=50,
            command=self.on_fps_change,
            width=150
        )
        self.fps_slider.set(self.fps_value)
        self.fps_slider.pack(side="right", padx=5)
        
        # Quality Control
        quality_frame = ctk.CTkFrame(self, fg_color="transparent")
        quality_frame.pack(fill="x", padx=10, pady=5)
        
        self.quality_label = ctk.CTkLabel(
            quality_frame,
            text=f"🎨 Calidad: {self.quality_value}%",
            font=ctk.CTkFont(size=11)
        )
        self.quality_label.pack(side="left")
        
        self.quality_slider = ctk.CTkSlider(
            quality_frame,
            from_=10,
            to=100,
            number_of_steps=90,
            command=self.on_quality_change,
            width=150
        )
        self.quality_slider.set(self.quality_value)
        self.quality_slider.pack(side="right", padx=5)
        
        # Resolution Control
        resolution_frame = ctk.CTkFrame(self, fg_color="transparent")
        resolution_frame.pack(fill="x", padx=10, pady=5)
        
        self.resolution_label = ctk.CTkLabel(
            resolution_frame,
            text=f"📐 Resolución: {int(self.resolution_value*100)}%",
            font=ctk.CTkFont(size=11)
        )
        self.resolution_label.pack(side="left")
        
        self.resolution_slider = ctk.CTkSlider(
            resolution_frame,
            from_=0.25,
            to=1.0,
            number_of_steps=15,
            command=self.on_resolution_change,
            width=150
        )
        self.resolution_slider.set(self.resolution_value)
        self.resolution_slider.pack(side="right", padx=5)
        
        # Botón disconnect
        disconnect_btn = ctk.CTkButton(
            self,
            text="🔌 Desconectar",
            command=lambda: self.on_disconnect(self.client_id),
            width=120,
            height=28,
            fg_color="#c41e3a",
            hover_color="#8b0000",
            font=ctk.CTkFont(size=10)
        )
        disconnect_btn.pack(pady=5)
    
    def on_fps_change(self, value):
        """Callback cuando cambia el FPS"""
        self.fps_value = int(value)
        self.fps_label.configure(text=f"🎬 FPS: {self.fps_value}")
        self.on_change(self.client_id, 'set_fps', self.fps_value)
    
    def on_quality_change(self, value):
        """Callback cuando cambia la calidad"""
        self.quality_value = int(value)
        self.quality_label.configure(text=f"🎨 Calidad: {self.quality_value}%")
        self.on_change(self.client_id, 'set_quality', self.quality_value)
    
    def on_resolution_change(self, value):
        """Callback cuando cambia la resolución"""
        self.resolution_value = round(value, 2)
        self.resolution_label.configure(text=f"📐 Resolución: {int(self.resolution_value*100)}%")
        self.on_change(self.client_id, 'set_resolution', self.resolution_value)


class ScreenShareServerGUI:
    def __init__(self):
        # Configuración de customtkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Ventana principal
        self.root = ctk.CTk()
        self.root.title("🖥️ Screen Share Server - Dynamic Control")
        self.root.geometry("1600x900")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables del servidor
        self.config_file = "config.ini"
        self.host, self.port = self.load_config()
        self.running = False
        self.sock = None
        self.clients = {}  # {client_id: {sock, hostname, monitors: {monitor_id: frame}, control_panel}}
        self.address_family = None
        
        # Variables para vista expandida
        self.expanded_view = None
        self.expanded_client_id = None
        self.expanded_monitor_id = None
        
        # Crear UI
        self.create_ui()
        
        # Detectar familia de direcciones
        self.address_family = self.detect_address_family(self.host)
        
    def detect_address_family(self, host):
        """Detecta si el host es IPv4, IPv6 o debe usar dual-stack"""
        try:
            addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            
            if addr_info:
                family = addr_info[0][0]
                
                if host in ['0.0.0.0', '']:
                    self.log_message("🌐 Modo dual-stack (IPv4 e IPv6)", "info")
                    return socket.AF_INET6
                
                if family == socket.AF_INET6:
                    self.log_message(f"✅ IPv6 detectado: {host}", "info")
                    return socket.AF_INET6
                else:
                    self.log_message(f"✅ IPv4 detectado: {host}", "info")
                    return socket.AF_INET
                    
        except socket.gaierror as e:
            self.log_message(f"⚠️ Error resolviendo host: {e}", "warning")
        
        return socket.AF_INET

    def get_bind_address(self):
        """Obtiene la dirección apropiada para bind()"""
        if self.address_family == socket.AF_INET6:
            if self.host in ['0.0.0.0', '']:
                return '::'
            return self.host
        else:
            return self.host

    def load_config(self):
        """Lee la IP y el puerto desde config.ini"""
        config = configparser.ConfigParser()

        if not os.path.exists(self.config_file):
            config["server"] = {"host": "0.0.0.0", "port": "9000"}
            with open(self.config_file, "w") as configfile:
                config.write(configfile)

        config.read(self.config_file)
        host = config["server"]["host"]
        port = int(config["server"]["port"])
        return host, port

    def send_message(self, sock, msg_type, payload):
        """Envía un mensaje con header tipado"""
        try:
            payload_bytes = payload if isinstance(payload, bytes) else payload.encode('utf-8')
            
            # Header: [4 bytes tamaño total] [1 byte tipo] [payload]
            total_size = len(payload_bytes)
            header = struct.pack('!IB', total_size, msg_type)
            
            sock.sendall(header + payload_bytes)
            return True
        except Exception as e:
            self.log_message(f"Error enviando mensaje: {e}", "error")
            return False
    
    def recv_message(self, sock):
        """Recibe un mensaje y retorna (tipo, payload)"""
        try:
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
                chunk = sock.recv(min(total_size - len(payload), 8192))
                if not chunk:
                    return None, None
                payload += chunk
            
            return msg_type, payload
        except Exception:
            return None, None

    def create_ui(self):
        """Crea la interfaz gráfica con grid view y controles"""
        
        # Header
        header_frame = ctk.CTkFrame(self.root, corner_radius=10)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        title_label = ctk.CTkLabel(
            header_frame, 
            text="🖥️ Screen Share Server - Dynamic Control",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=10)
        
        # Info del servidor
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
            text="👥 Clientes: 0 | 📺 Pantallas: 0",
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
        
        # Frame principal dividido en 3 columnas
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Columna 1: Controles de clientes (izquierda)
        controls_frame = ctk.CTkFrame(main_frame, corner_radius=10, width=300)
        controls_frame.pack(side="left", fill="y", padx=(0, 5))
        controls_frame.pack_propagate(False)
        
        controls_header = ctk.CTkLabel(
            controls_frame,
            text="⚙️ Controles de Clientes",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        controls_header.pack(pady=10)
        
        # Scrollable frame para controles
        self.controls_scrollframe = ctk.CTkScrollableFrame(
            controls_frame,
            label_text="",
            label_fg_color="transparent"
        )
        self.controls_scrollframe.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Columna 2: Grid de pantallas (centro)
        center_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        center_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        grid_header = ctk.CTkLabel(
            center_frame,
            text="📺 Vista de Pantallas",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        grid_header.pack(pady=10)
        
        # Scrollable frame para el grid
        self.grid_scrollframe = ctk.CTkScrollableFrame(
            center_frame,
            label_text="",
            label_fg_color="transparent"
        )
        self.grid_scrollframe.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Columna 3: Log de actividad (derecha)
        right_frame = ctk.CTkFrame(main_frame, corner_radius=10, width=350)
        right_frame.pack(side="right", fill="y", padx=(5, 0))
        right_frame.pack_propagate(False)
        
        log_header = ctk.CTkLabel(
            right_frame,
            text="📋 Log de Actividad",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        log_header.pack(pady=10)
        
        self.log_text = ctk.CTkTextbox(
            right_frame,
            wrap="word",
            font=ctk.CTkFont(size=11)
        )
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
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
            text="IPv4/IPv6 • Multi-Monitor • Dynamic Control • TCP_NODELAY",
            font=ctk.CTkFont(size=10)
        )
        footer_label.pack(pady=5)

    def log_message(self, message, level="info"):
        """Agrega mensaje al log con timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        colors = {
            "info": "#FFFFFF",
            "success": "#00FF00",
            "warning": "#FFA500",
            "error": "#FF0000"
        }
        
        color = colors.get(level, "#FFFFFF")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.log_text.insert("end", formatted_message, level)
        self.log_text.tag_config(level, foreground=color)
        self.log_text.see("end")

    def clear_log(self):
        """Limpia el log de actividad"""
        self.log_text.delete("1.0", "end")
        self.log_message("Log limpiado", "info")

    def update_controls_panel(self):
        """Actualiza el panel de controles"""
        # Limpiar panel actual
        for widget in self.controls_scrollframe.winfo_children():
            widget.destroy()
        
        if not self.clients:
            no_clients_label = ctk.CTkLabel(
                self.controls_scrollframe,
                text="Sin clientes\nconectados",
                font=ctk.CTkFont(size=12),
                text_color="gray"
            )
            no_clients_label.pack(pady=20)
            return
        
        # Crear panel de control para cada cliente
        for client_id, client_data in self.clients.items():
            if 'control_panel' not in client_data or client_data['control_panel'] is None:
                control_panel = ClientControlPanel(
                    self.controls_scrollframe,
                    client_id,
                    self.send_control_command,
                    self.disconnect_client
                )
                control_panel.pack(fill="x", pady=5, padx=5)
                client_data['control_panel'] = control_panel

    def send_control_command(self, client_id, command, value):
        """Envía un comando de control a un cliente específico"""
        if client_id not in self.clients:
            return
        
        client_sock = self.clients[client_id]['sock']
        
        command_data = {
            'command': command,
            'value': value
        }
        
        command_json = json.dumps(command_data)
        
        if self.send_message(client_sock, MSG_COMMAND, command_json):
            self.log_message(f"📤 Comando enviado a {client_id}: {command}={value}", "info")
        else:
            self.log_message(f"❌ Error enviando comando a {client_id}", "error")

    def update_grid_view(self):
        """Actualiza el grid de pantallas"""
        # Limpiar grid actual
        for widget in self.grid_scrollframe.winfo_children():
            widget.destroy()
        
        # Contar clientes y pantallas
        total_screens = sum(
            len(client_data.get('monitors', {})) 
            for client_data in self.clients.values()
        )
        
        self.clients_count_label.configure(
            text=f"👥 Clientes: {len(self.clients)} | 📺 Pantallas: {total_screens}"
        )
        
        if not self.clients:
            no_clients_label = ctk.CTkLabel(
                self.grid_scrollframe,
                text="Sin clientes conectados\nEsperando conexiones...",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            )
            no_clients_label.pack(pady=50)
            return
        
        # Crear grid
        row = 0
        col = 0
        max_cols = 2  # 2 columnas
        
        for client_id, client_data in self.clients.items():
            hostname = client_data.get('hostname', 'Unknown')
            monitors = client_data.get('monitors', {})
            
            for monitor_id, frame in monitors.items():
                if frame is None:
                    continue
                
                # Crear card para cada pantalla
                card = ctk.CTkFrame(self.grid_scrollframe, corner_radius=10)
                card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
                
                # Título de la card
                title_text = f"{hostname}\nMonitor {monitor_id}"
                title_label = ctk.CTkLabel(
                    card,
                    text=title_text,
                    font=ctk.CTkFont(size=12, weight="bold")
                )
                title_label.pack(pady=5)
                
                # Miniatura de la pantalla
                thumbnail = self.create_thumbnail(frame, width=400, height=225)
                
                if thumbnail:
                    img_label = ctk.CTkLabel(card, text="", image=thumbnail)
                    img_label.image = thumbnail
                    img_label.pack(padx=5, pady=5)
                    
                    # Hacer clickeable para expandir
                    img_label.bind("<Button-1>", 
                        lambda e, cid=client_id, mid=monitor_id: self.expand_view(cid, mid))
                    img_label.configure(cursor="hand2")
                
                # Actualizar posición en grid
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
        
        # Configurar grid weights
        for i in range(max_cols):
            self.grid_scrollframe.grid_columnconfigure(i, weight=1)

    def create_thumbnail(self, frame, width=400, height=225):
        """Crea una miniatura del frame para el grid"""
        try:
            # Redimensionar frame
            thumbnail = cv2.resize(frame, (width, height))
            
            # Convertir BGR a RGB
            thumbnail_rgb = cv2.cvtColor(thumbnail, cv2.COLOR_BGR2RGB)
            
            # Convertir a PIL Image
            pil_image = Image.fromarray(thumbnail_rgb)
            
            # Convertir a CTkImage
            ctk_image = ctk.CTkImage(
                light_image=pil_image,
                dark_image=pil_image,
                size=(width, height)
            )
            
            return ctk_image
        except Exception as e:
            return None

    def expand_view(self, client_id, monitor_id):
        """Expande una pantalla a vista completa"""
        self.log_message(f"👁️ Expandiendo vista: {client_id} - Monitor {monitor_id}", "info")
        
        self.expanded_client_id = client_id
        self.expanded_monitor_id = monitor_id
        
        # Crear ventana expandida si no existe
        if self.expanded_view is None or not self.expanded_view.winfo_exists():
            self.expanded_view = ctk.CTkToplevel(self.root)
            self.expanded_view.title(f"Vista Completa - {client_id} - Monitor {monitor_id}")
            self.expanded_view.geometry("1280x720")
            
            # Label para mostrar la imagen
            self.expanded_image_label = ctk.CTkLabel(self.expanded_view, text="")
            self.expanded_image_label.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Botón para cerrar
            close_btn = ctk.CTkButton(
                self.expanded_view,
                text="❌ Cerrar Vista",
                command=self.close_expanded_view,
                width=150,
                height=40
            )
            close_btn.pack(pady=10)
            
            # Iniciar actualización
            self.update_expanded_view()
    
    def update_expanded_view(self):
        """Actualiza la vista expandida continuamente"""
        if self.expanded_view and self.expanded_view.winfo_exists():
            if self.expanded_client_id in self.clients:
                client_data = self.clients[self.expanded_client_id]
                monitors = client_data.get('monitors', {})
                
                if self.expanded_monitor_id in monitors:
                    frame = monitors[self.expanded_monitor_id]
                    
                    if frame is not None:
                        # Crear imagen para vista expandida
                        expanded_img = self.create_thumbnail(frame, width=1200, height=675)
                        
                        if expanded_img:
                            self.expanded_image_label.configure(image=expanded_img)
                            self.expanded_image_label.image = expanded_img
            
            # Programar siguiente actualización
            self.root.after(33, self.update_expanded_view)  # ~30 FPS
    
    def close_expanded_view(self):
        """Cierra la vista expandida"""
        if self.expanded_view:
            self.expanded_view.destroy()
            self.expanded_view = None
        self.expanded_client_id = None
        self.expanded_monitor_id = None

    def disconnect_client(self, client_id):
        """Desconecta un cliente específico"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['sock'].close()
            except:
                pass
            
            del self.clients[client_id]
            self.log_message(f"❌ Cliente desconectado: {client_id}", "warning")
            self.root.after(0, self.update_controls_panel)
            self.root.after(0, self.update_grid_view)

    def start_server(self):
        """Inicia el servidor"""
        try:
            self.sock = socket.socket(self.address_family, socket.SOCK_STREAM)
            
            # OPTIMIZACIÓN: TCP_NODELAY para reducir latencia
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Configuración dual-stack
            if self.address_family == socket.AF_INET6:
                try:
                    self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    self.log_message("🔧 Modo dual-stack habilitado", "success")
                except (AttributeError, OSError) as e:
                    self.log_message(f"⚠️ No se pudo habilitar dual-stack: {e}", "warning")
            
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            bind_address = self.get_bind_address()
            self.sock.bind((bind_address, self.port))
            self.sock.listen(10)
            
            self.running = True
            
            # Actualizar UI
            self.status_label.configure(text="🟢 Estado: Activo")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            
            self.log_message(f"🚀 Servidor iniciado en {bind_address}:{self.port}", "success")
            if self.address_family == socket.AF_INET6 and bind_address == '::':
                self.log_message("📡 Escuchando conexiones IPv4 e IPv6", "success")
            
            # Thread para aceptar clientes
            threading.Thread(target=self.accept_clients, daemon=True).start()
            
            # Iniciar actualización del grid
            self.update_grid_periodically()
            
        except Exception as e:
            self.log_message(f"❌ Error al iniciar servidor: {e}", "error")

    def stop_server(self):
        """Detiene el servidor"""
        self.running = False
        
        if self.sock:
            self.sock.close()
        
        # Cerrar todas las conexiones
        for client_id, client_data in list(self.clients.items()):
            try:
                client_data['sock'].close()
            except:
                pass
        
        self.clients.clear()
        
        # Cerrar vista expandida
        self.close_expanded_view()
        
        # Actualizar UI
        self.status_label.configure(text="⚪ Estado: Detenido")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.update_controls_panel()
        self.update_grid_view()
        
        self.log_message("🛑 Servidor detenido", "warning")

    def accept_clients(self):
        """Acepta múltiples clientes"""
        while self.running:
            try:
                client_sock, addr = self.sock.accept()
                
                # OPTIMIZACIÓN: TCP_NODELAY en el socket del cliente
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
                addr_str = self.format_address(addr)
                
                self.log_message(f"🔌 Nueva conexión desde: {addr_str}", "info")
                
                # Thread para manejar handshake y recepción
                threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr_str),
                    daemon=True
                ).start()
                
            except Exception as e:
                if self.running:
                    self.log_message(f"⚠️ Error aceptando cliente: {e}", "warning")

    def format_address(self, addr):
        """Formatea la dirección del cliente"""
        if len(addr) == 2:
            return f"{addr[0]}:{addr[1]}"
        elif len(addr) == 4:
            return f"[{addr[0]}]:{addr[1]}"
        else:
            return str(addr)

    def handle_client(self, client_sock, addr_str):
        """Maneja un cliente: recibe handshake y streams"""
        try:
            # Recibir handshake
            msg_type, payload = self.recv_message(client_sock)
            
            if msg_type != MSG_HANDSHAKE:
                self.log_message(f"❌ Handshake inválido de {addr_str}", "error")
                client_sock.close()
                return
            
            handshake = json.loads(payload.decode('utf-8'))
            
            hostname = handshake.get('hostname', 'Unknown')
            monitors_info = handshake.get('monitors', [])
            
            # Crear ID único para el cliente
            client_id = f"{hostname}@{addr_str}"
            
            # Registrar cliente
            self.clients[client_id] = {
                'sock': client_sock,
                'hostname': hostname,
                'addr': addr_str,
                'monitors': {},
                'control_panel': None
            }
            
            self.log_message(f"✅ Cliente registrado: {client_id} ({len(monitors_info)} monitor(es))", "success")
            
            # Actualizar UI
            self.root.after(0, self.update_controls_panel)
            
            # Recibir streams
            self.receive_stream(client_sock, client_id)
            
        except Exception as e:
            self.log_message(f"❌ Error en handshake: {e}", "error")
            try:
                client_sock.close()
            except:
                pass

    def receive_stream(self, client_sock, client_id):
        """Recibe y almacena frames del cliente"""
        while self.running and client_id in self.clients:
            try:
                msg_type, payload = self.recv_message(client_sock)
                
                if msg_type is None:
                    break
                
                if msg_type == MSG_FRAME:
                    # Parsear header y frame
                    parts = payload.split(b'\n', 1)
                    if len(parts) != 2:
                        continue
                    
                    header_json, frame_bytes = parts
                    header = json.loads(header_json.decode('utf-8'))
                    
                    monitor_id = header['monitor_id']
                    
                    # Decodificar imagen
                    frame = np.frombuffer(frame_bytes, dtype=np.uint8)
                    frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)
                    
                    if frame is not None:
                        # Almacenar frame
                        self.clients[client_id]['monitors'][monitor_id] = frame
                    
            except Exception as e:
                break
        
        # Cliente desconectado
        self.log_message(f"❌ Cliente desconectado: {client_id}", "error")
        if client_id in self.clients:
            del self.clients[client_id]
        
        self.root.after(0, self.update_controls_panel)
        self.root.after(0, self.update_grid_view)

    def update_grid_periodically(self):
        """Actualiza el grid periódicamente"""
        if self.running:
            self.update_grid_view()
            self.root.after(1000, self.update_grid_periodically)  # Cada 1 segundo

    def on_closing(self):
        """Maneja el cierre de la aplicación"""
        if self.running:
            self.stop_server()
        
        self.close_expanded_view()
        self.root.destroy()

    def run(self):
        """Inicia la aplicación"""
        self.log_message("🎉 Aplicación iniciada", "success")
        self.log_message(f"📝 Configuración: {self.host}:{self.port}", "info")
        self.root.mainloop()

if __name__ == "__main__":
    app = ScreenShareServerGUI()
    app.run()
