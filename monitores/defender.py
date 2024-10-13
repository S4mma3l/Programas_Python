import psutil
import yara
import os
import requests
from bs4 import BeautifulSoup
from scapy.all import sniff, IP, TCP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import smtplib
from email.mime.text import MIMEText
import time
import threading

# Configuraciones globales
ALERT_EMAIL = "s4mma3l@pentestercr.com"  # Tu correo personalizado
SMTP_SERVER = "smtp.mail.me.com"         # Servidor SMTP de iCloud
SMTP_USER = "s4mma3l@pentestercr.com"    # Tu correo de iCloud
SMTP_PASS = "SAMmael101986."      # Contraseña o token de aplicación de iCloud

# 1. Monitoreo de recursos del sistema
def monitor_resources():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent

    print(f"CPU usage: {cpu_usage}%")
    print(f"Memory usage: {memory_usage}%")

    if cpu_usage > 80:
        send_alert("High CPU usage detected", f"CPU usage is at {cpu_usage}%")
    if memory_usage > 80:
        send_alert("High memory usage detected", f"Memory usage is at {memory_usage}%")

# 2. Detección de ransomware y malware con YARA
def load_yara_rules():
    return yara.compile(filepath='ransomware_rules.yar')

def scan_files_for_malware(directory="C:\\"):
    rules = load_yara_rules()
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                matches = rules.match(filepath)
                if matches:
                    send_alert("Ransomware detected", f"Ransomware detected in {filepath}")
            except Exception as e:
                print(f"Error scanning {filepath}: {e}")

# 3. Monitoreo de tráfico de red para pushing
def monitor_network(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Packet from {ip_src} to {ip_dst}")
        
        # Detecta pushing o conexiones sospechosas
        if packet.haslayer(TCP):
            if packet[TCP].dport == 443 and "suspicious-site.com" in packet[IP].dst:
                send_alert("Pushing attempt detected", f"Possible pushing attempt from {ip_src}")

def start_network_monitoring():
    sniff(prn=monitor_network, store=0)

# 4. Protección contra phishing (análisis de URL)
def check_phishing(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        if "login" in response.url or "reset-password" in response.url:
            send_alert("Phishing attempt detected", f"Phishing link detected: {url}")
        else:
            print(f"URL {url} appears safe")
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL {url}: {e}")

# 5. Monitoreo en tiempo real del sistema de archivos
class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"File created: {event.src_path}")
        send_alert("File Created", f"File created: {event.src_path}")
    
    def on_modified(self, event):
        print(f"File modified: {event.src_path}")
        send_alert("File Modified", f"File modified: {event.src_path}")

def monitor_files(path="C:\\"):
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# 6. Análisis heurístico y comportamental
def analyze_process_behavior():
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'connections']):
        try:
            cpu_usage = proc.info['cpu_percent']
            connections = proc.connections()

            if cpu_usage > 50:
                send_alert("Suspicious CPU usage", f"High CPU usage by {proc.info['name']}")
            
            if any(conn.raddr and conn.raddr[0] == "suspicious-server.com" for conn in connections):
                send_alert("Suspicious connection", f"Process {proc.info['name']} is connecting to a suspicious server")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

# 7. Respuesta automática ante incidentes
def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"Terminated process {pid}")
        send_alert("Process terminated", f"Terminated process {pid}")
    except Exception as e:
        print(f"Error terminating process {pid}: {e}")

# 8. Envío de alertas por correo electrónico
def send_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    with smtplib.SMTP(SMTP_SERVER, 587) as server:
        server.starttls()  # Iniciar el cifrado TLS
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

    print(f"Alert sent: {subject}")

# 9. Ejecución periódica (uso de hilos)
def run_all_tasks():
    print("Starting system monitoring...")
    
    # Ejecutar las tareas en hilos separados
    threading.Thread(target=monitor_resources).start()
    threading.Thread(target=scan_files_for_malware).start()
    threading.Thread(target=start_network_monitoring).start()
    threading.Thread(target=analyze_process_behavior).start()
    threading.Thread(target=monitor_files).start()

if __name__ == "__main__":
    run_all_tasks()