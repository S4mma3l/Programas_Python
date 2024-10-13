import psutil
import smtplib
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
import time

load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))  # Puerto SMTP

# Definir PIDs anómalos (Ejemplo: puedes agregar más PIDs o criterios)
ANOMALOUS_PIDS = [1234, 5678]  # Reemplaza estos números con los PIDs que consideras anómalos

def check_processes():
    print("Verificando procesos...")
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']

            # Comprobar si el proceso es anómalo
            if pid in ANOMALOUS_PIDS:
                print(f"Proceso anómalo detectado: {name} (PID: {pid})")
                send_alert("Anomalous process detected", f"Detected anomalous process: {name} with PID: {pid}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def send_alert(subject, body):
    print(f"Preparando para enviar alerta: {subject}")
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Iniciar TLS
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print(f"Alerta enviada: {subject}")
    except Exception as e:
        print(f"Error al enviar alerta: {e}")

if __name__ == "__main__":
    while True:
        check_processes()
        time.sleep(60)  # Esperar 60 segundos antes de verificar nuevamente
