import tkinter as tk
from tkinter import ttk
import pyperclip  # Para copiar al portapapeles

def convert_text_to_formats(input_text):
    # Convertir a hexadecimal con espacios entre bytes
    hex_format = ' '.join([f"{ord(c):02x}" for c in input_text])
    
    # Crear una cadena de 'x' con la misma longitud que el texto original
    x_string = 'x' * len(input_text)
    
    # Formatear la salida como se solicitó
    result = f'{{ "{input_text}", "{hex_format}", "{x_string}", 0 }}'
    
    return result

def convert_and_display():
    input_text = entry_text.get()
    if input_text:
        result = convert_text_to_formats(input_text)
        result_text.config(state="normal")
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
        result_text.config(state="disabled")
        status_label.config(text="Conversión exitosa")
    else:
        status_label.config(text="Por favor, ingresa un texto")

def copy_to_clipboard():
    result = result_text.get(1.0, tk.END).strip()
    if result:
        pyperclip.copy(result)
        status_label.config(text="Copiado al portapapeles")
    else:
        status_label.config(text="No hay resultado para copiar")

def clear_fields():
    entry_text.delete(0, tk.END)
    result_text.config(state="normal")
    result_text.delete(1.0, tk.END)
    result_text.config(state="disabled")
    status_label.config(text="Campos limpiados")

# Crear la ventana principal
root = tk.Tk()
root.title("Conversor de Texto a Formatos")
root.geometry("600x350")
root.resizable(True, True)

# Configurar estilos
style = ttk.Style()
style.configure("TLabel", font=("Arial", 11))
style.configure("TButton", font=("Arial", 10))
style.configure("TEntry", font=("Consolas", 11))

# Marco principal
main_frame = ttk.Frame(root, padding="20")
main_frame.pack(fill=tk.BOTH, expand=True)

# Etiqueta y entrada para el texto
input_label = ttk.Label(main_frame, text="Ingresa el texto a convertir:")
input_label.pack(anchor="w", pady=(0, 5))

entry_text = ttk.Entry(main_frame, width=50, font=("Consolas", 11))
entry_text.pack(fill=tk.X, pady=(0, 15))
entry_text.focus()

# Botón de conversión
convert_button = ttk.Button(main_frame, text="Convertir", command=convert_and_display)
convert_button.pack(pady=(0, 15))

# Etiqueta y campo de resultado
result_label = ttk.Label(main_frame, text="Resultado:")
result_label.pack(anchor="w", pady=(0, 5))

result_text = tk.Text(main_frame, height=6, width=50, font=("Consolas", 10), wrap="word")
result_text.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
result_text.config(state="disabled")

# Marco para botones de acción
button_frame = ttk.Frame(main_frame)
button_frame.pack(fill=tk.X, pady=(0, 10))

# Botones de copiar y limpiar
copy_button = ttk.Button(button_frame, text="Copiar resultado", command=copy_to_clipboard)
copy_button.pack(side=tk.LEFT, padx=(0, 10))

clear_button = ttk.Button(button_frame, text="Limpiar campos", command=clear_fields)
clear_button.pack(side=tk.LEFT)

# Etiqueta de estado
status_label = ttk.Label(main_frame, text="", font=("Arial", 10, "italic"))
status_label.pack(anchor="w")

# Asociar la tecla Enter con el botón de conversión
root.bind("<Return>", lambda event: convert_and_display())

# Iniciar el bucle principal
root.mainloop()