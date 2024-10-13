import time
import smtplib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
import schedule
import threading

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))  # Puerto para TLS

# Archivo para almacenar resultados
report_file = "analysis_report.txt"

# Clase para manejar eventos de creación o modificación de archivos
class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.src_path != os.path.abspath(report_file):  # Ignorar el archivo de reporte
            log_event("File created", event.src_path)
    
    def on_modified(self, event):
        if event.src_path != os.path.abspath(report_file):  # Ignorar el archivo de reporte
            log_event("File modified", event.src_path)

def log_event(action, path):
    with open(report_file, "a") as f:
        f.write(f"{action}: {path}\n")
    print(f"{action}: {path}")

# Función para enviar alertas por correo electrónico
def send_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()  # Iniciar la conexión TLS
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

    print(f"Alert sent: {subject}")

# Función para enviar un informe de análisis
def send_analysis_report():
    if os.path.exists(report_file):
        with open(report_file, "rb") as f:
            msg = MIMEText(f.read(), "plain")
            msg['Subject'] = "Scheduled Analysis Report"
            msg['From'] = SMTP_USER
            msg['To'] = ALERT_EMAIL
            msg.add_header('Content-Disposition', 'attachment', filename=report_file)

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()  # Iniciar la conexión TLS
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(msg['From'], [msg['To']], msg.as_string())

        print(f"Analysis report sent: {report_file}")

        # Limpiar el archivo después de enviarlo
        open(report_file, "w").close()

# Función para monitorear archivos en un directorio
def monitor_files(path="C:\\"):
    print(f"Monitoring directory: {path}")
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()

# Función para programar el envío del informe cada 10 minutos
def schedule_analysis_report():
    schedule.every(10).minutes.do(send_analysis_report)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

# Ejecución del monitoreo y programación del informe
if __name__ == "__main__":
    # Limpiar el archivo antes de comenzar
    open(report_file, "w").close()
    
    threading.Thread(target=schedule_analysis_report).start()  # Hilo para programar el informe
    monitor_files()
