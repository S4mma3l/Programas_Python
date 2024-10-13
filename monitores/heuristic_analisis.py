import time
import smtplib
import os
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from email.mime.text import MIMEText

load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))           # Contraseña o token de aplicación            # Contraseña o token de aplicación

# Clase para manejar eventos de creación o modificación de archivos
class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        """Maneja el evento de creación de archivos."""
        print(f"File created: {event.src_path}")
        send_alert("File Created", f"File created: {event.src_path}")
    
    def on_modified(self, event):
        """Maneja el evento de modificación de archivos."""
        print(f"File modified: {event.src_path}")
        send_alert("File Modified", f"File modified: {event.src_path}")

# Función para monitorear archivos en un directorio
def monitor_files(path="C:\\"):
    """Inicia el monitoreo de un directorio específico."""
    print(f"Monitoring directory: {path}")
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)  # Monitoreo recursivo
    observer.start()

    try:
        while True:
            time.sleep(1)  # Mantiene el monitoreo
    except KeyboardInterrupt:
        observer.stop()  # Detiene el monitoreo al recibir Ctrl+C
        print("Monitoring stopped.")
    observer.join()

# Función para enviar alertas por correo electrónico
def send_alert(subject, body):
    """Envía un correo electrónico con el asunto y el cuerpo especificados."""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    with smtplib.SMTP(SMTP_SERVER, 587) as server:
        server.starttls()  # Inicia TLS para seguridad
        server.login(SMTP_USER, SMTP_PASS)  # Inicia sesión en el servidor SMTP
        server.sendmail(msg['From'], [msg['To']], msg.as_string())  # Envía el correo

    print(f"Alert sent: {subject}")

# Ejecución del monitoreo
if __name__ == "__main__":
    monitor_files()  # Llama a la función de monitoreo