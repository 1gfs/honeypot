import socketserver
import logging
import threading
import time
from typing import List

SETTINGS = {
    "logging": {
        "log_file": "honeypot.log",
        "log_level": logging.INFO,
    },
    "alerting": {
        "enabled": True,
        "alert_message": "ALERT! Suspicious activity detected from {ip} on {service} service."
    },
    "services": [
        {"ip": "0.0.0.0", "port": 22, "name": "SSH"},
        {"ip": "0.0.0.0", "port": 80, "name": "HTTP"},
        {"ip": "0.0.0.0", "port": 21, "name": "FTP"},
        {"ip": "0.0.0.0", "port": 23, "name": "Telnet"},
        {"ip": "0.0.0.0", "port": 25, "name": "SMTP"},
        {"ip": "0.0.0.0", "port": 3389, "name": "RDP"},
        {"ip": "0.0.0.0", "port": 3306, "name": "MySQL"}
    ]
}

logging.basicConfig(
    filename=SETTINGS["logging"]["log_file"],
    level=SETTINGS["logging"]["log_level"],
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def alert_admin(ip: str, service: str, data: str) -> None:
    if SETTINGS["alerting"]["enabled"]:
        alert_message = SETTINGS["alerting"]["alert_message"].format(ip=ip, service=service)
        logging.warning(alert_message)

class HoneypotRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        service_name = self.server.service_name
        client_ip = self.client_address[0]
        logging.info(f"Connection attempt on {service_name} from {client_ip}")
        try:
            data = self.request.recv(1024).decode('utf-8', errors='ignore').strip()
            logging.info(f"Received data from {client_ip} on {service_name}: {data}")
            self.request.sendall(f"{service_name} access denied.\n".encode('utf-8'))
            alert_admin(client_ip, service_name, data)
        except Exception as exc:
            logging.error(f"Error handling client {client_ip} on {service_name}: {exc}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class Honeypot:
    def __init__(self) -> None:
        self.servers: List[ThreadedTCPServer] = []
        self.threads: List[threading.Thread] = []

    def load_services(self) -> None:
        for service in SETTINGS["services"]:
            try:
                server = ThreadedTCPServer(
                    (service["ip"], service["port"]), HoneypotRequestHandler
                )
                server.service_name = service["name"]
                self.servers.append(server)
                logging.info(f"{service['name']} service loaded on {service['ip']}:{service['port']}")
            except Exception as e:
                logging.error(f"Failed to load {service['name']} on {service['ip']}:{service['port']} - {e}")

    def start_services(self) -> None:
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            logging.info(f"{server.service_name} service started on {server.server_address[0]}:{server.server_address[1]}")
            self.threads.append(thread)

    def stop_services(self) -> None:
        logging.info("Shutting down honeypot services...")
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()
        logging.info("All honeypot services have been shut down.")

    def run(self) -> None:
        self.load_services()
        self.start_services()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_services()

if __name__ == "__main__":
    honeypot = Honeypot()
    honeypot.run()