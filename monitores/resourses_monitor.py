import psutil
import smtplib
import time
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText


load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))           # Contraseña o token de aplicación

# Monitoreo de recursos del sistema
def monitor_resources():
    print("Iniciando monitoreo de recursos del sistema...")
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent

        print(f"Uso de CPU: {cpu_usage}%")
        print(f"Uso de memoria: {memory_usage}%")

        if cpu_usage > 80:
            print("Uso alto de CPU detectado. Enviando alerta...")
            send_alert("High CPU usage detected", f"CPU usage is at {cpu_usage}%")
        
        if memory_usage > 80:
            print("Uso alto de memoria detectado. Enviando alerta...")
            send_alert("High memory usage detected", f"Memory usage is at {memory_usage}%")

        time.sleep(5)  # Espera 5 segundos antes del próximo monitoreo

# Enviar alertas por correo
def send_alert(subject, body):
    print(f"Preparando para enviar alerta: {subject}")
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            print("Conectando al servidor SMTP...")
            server.login(SMTP_USER, SMTP_PASS)
            print("Conexión exitosa al servidor SMTP.")
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print(f"Alerta enviada: {subject}")
    except Exception as e:
        print(f"Error al enviar alerta: {e}")

# Ejecución del monitoreo
if __name__ == "__main__":
    monitor_resources()