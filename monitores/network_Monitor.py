import smtplib
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP

load_dotenv()

# Configuración de correo electrónico
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Tu correo personalizado
SMTP_SERVER = os.getenv("SMTP_SERVER")   # Servidor SMTP de Gmail
SMTP_USER = os.getenv("SMTP_USER")       # Tu correo de Gmail
SMTP_PASS = os.getenv("SMTP_PASS")       # Contraseña de tu cuenta de Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT"))           # Contraseña o token de aplicación          # Contraseña o token de aplicación

# Función para enviar alertas por correo
def send_alert(subject, body):
    print(f"Preparing to send alert: {subject}")
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            print("Connecting to SMTP server...")
            server.login(SMTP_USER, SMTP_PASS)
            print("Logged in to SMTP server.")
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print(f"Alert sent: {subject}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

# Función de monitoreo de red
def monitor_network(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Packet from {ip_src} to {ip_dst}")
        
        # Detecta pushing o conexiones sospechosas
        if packet.haslayer(TCP):
            if packet[TCP].dport == 443 and "suspicious-site.com" in packet[IP].dst:
                print("Suspicious pushing detected. Preparing alert...")
                send_alert("Pushing attempt detected", f"Possible pushing attempt from {ip_src} to {ip_dst}")
            else:
                print(f"Normal TCP traffic from {ip_src} to {ip_dst}")

# Inicia el monitoreo de la red
def start_network_monitoring():
    print("Starting network monitoring...")
    sniff(prn=monitor_network, store=0)

# Llama a la función para iniciar el monitoreo
if __name__ == "__main__":
    start_network_monitoring()
