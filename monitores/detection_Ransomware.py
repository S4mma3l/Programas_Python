import yara
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))  # Puerto para TLS

# Cargar las reglas YARA
def load_yara_rules():
    print("Loading YARA rules from file...")
    try:
        rules = yara.compile(filepath='ransomware_rules.yar')
        print("YARA rules successfully loaded.")
        return rules
    except Exception as e:
        print(f"Error loading YARA rules: {e}")
        return None  # Asegúrate de retornar None si hay un error

# Escanear archivos en busca de malware usando YARA
def scan_files_for_malware(directory="C:\\"):
    print(f"Starting malware scan in directory: {directory}")
    rules = load_yara_rules()
    if rules is None:
        print("YARA rules could not be loaded. Aborting scan.")
        return

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                print(f"Scanning file: {filepath}")
                matches = rules.match(filepath)
                if matches:
                    print(f"Ransomware detected in {filepath}. Sending alert...")
                    send_alert("Ransomware detected", f"Ransomware detected in {filepath}")
                else:
                    print(f"No ransomware detected in {filepath}")
            except UnicodeEncodeError as e:
                print(f"Encoding error for {filepath}: {e}")
            except Exception as e:
                print(f"Error scanning {filepath}: {e}")

# Enviar alertas por correo
def send_alert(subject, body):
    print(f"Preparing to send alert: {subject}")
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            print("Connecting to SMTP server...")
            server.login(SMTP_USER, SMTP_PASS)
            print("Logged in to SMTP server.")
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print(f"Alert sent: {subject}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

# Ejemplo de ejecución del escaneo
if __name__ == "__main__":
    scan_files_for_malware(input("Indique la ruta: "))  # Asegúrate de que la ruta es válida
 # Cambia el directorio según sea necesario