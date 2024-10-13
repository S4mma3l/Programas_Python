import requests
import smtplib
import os
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))  # Puerto para TLS

def check_phishing(url):
    print(f"Verificando la URL: {url}")
    try:
        # Cambiar el User-Agent para simular un navegador
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        # Agregar un timeout de 10 segundos para evitar esperas largas
        response = requests.get(url, headers=headers, timeout=10)
        print(f"Respuesta del servidor: {response.status_code}")

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Comprobar si la URL contiene términos sospechosos
            if "login" in response.url or "reset-password" in response.url:
                print(f"Intento de phishing detectado en: {url}")
                send_alert("Phishing attempt detected", f"Phishing link detected: {url}")
            else:
                print(f"URL {url} parece segura.")
        else:
            print(f"No se pudo acceder a la página. Estado del servidor: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"Error al verificar la URL {url}: {e}")

def send_alert(subject, body):
    print(f"Preparando para enviar alerta: {subject}")
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Iniciar TLS
            print("Conectando al servidor SMTP...")
            server.login(SMTP_USER, SMTP_PASS)
            print("Conexión exitosa al servidor SMTP.")
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print(f"Alerta enviada: {subject}")
    except smtplib.SMTPAuthenticationError:
        print("Error: Fallo en la autenticación. Verifica tu usuario y contraseña.")
    except smtplib.SMTPException as e:
        print(f"Error al enviar alerta: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Ejemplo de uso
if __name__ == "__main__":
    test_url = input("Ingresa la dirección de la cual sospechas: ")  # Cambia esto por la URL que desees verificar
    check_phishing(test_url)