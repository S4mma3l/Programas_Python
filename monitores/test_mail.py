import smtplib
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText


load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))           # Contraseña o token de aplicación    # Contraseña o token de aplicación

def send_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()  # Inicia TLS
            server.login(SMTP_USER, SMTP_PASS)  # Inicia sesión
            server.sendmail(msg['From'], [msg['To']], msg.as_string())  # Envía el correo
        print(f"Alert sent: {subject}")
    except smtplib.SMTPAuthenticationError:
        print("Error de autenticación. Verifica tu usuario y contraseña.")

# Ejemplo de uso
send_alert("Prueba", "Este es un mensaje de prueba.")
