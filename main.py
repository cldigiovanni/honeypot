#!/usr/bin/env python3
import argparse
import datetime
import logging
import os
import socket
import sys
import threading
import paramiko
import re
import hashlib
import requests
import urllib.parse
from pathlib import Path

# logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("ssh_honeypot.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# create directories for malware samples
SAMPLES_DIR = Path("samples")
SAMPLES_DIR.mkdir(exist_ok=True)

# metadata storage
METADATA_FILE = "malware_metadata.log"

# generate server key if it doesn"t exist
host_key_path = "honeypot_key"
if not os.path.exists(host_key_path):
    logging.info("Generating new host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(host_key_path)
    logging.info(f"Host key generated and saved to {host_key_path}")
else:
    logging.info(f"Using existing host key from {host_key_path}")

host_key = paramiko.RSAKey(filename=host_key_path)

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.commands = []

    def check_channel_request(self, kind, chanid):
        logging.info(f"Client {self.client_ip} requested channel: {kind}")
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logging.info(f"Login attempt - IP: {self.client_ip}, Username: {username}, Password: {password}")
        # always succeed authentication
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        logging.info(f"Publickey auth attempt - IP: {self.client_ip}, Username: {username}, Key: {key.get_fingerprint().hex()}")
        # always succeed authentication
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8")
        logging.info(f"Exec request from {self.client_ip}: {cmd}")
        self.commands.append(cmd)
        self.event.set()
        return True

def download_malware(url, client_ip, command):
    """safely download potential malware sample from URL."""
    try:
        # basic URL validation
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            logging.warning(f"Invalid URL format: {url}")
            return None
        
        # download with a timeout and user agent
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, stream=True)
        
        if response.status_code != 200:
            logging.warning(f"Failed to download from {url}, status code: {response.status_code}")
            return None
            
        # create a unique filename based on hash
        content = response.content
        file_hash = hashlib.sha256(content).hexdigest()
        file_path = SAMPLES_DIR / file_hash
        
        # save the malware sample
        with open(file_path, "wb") as f:
            f.write(content)
            
        # record metadata
        timestamp = datetime.datetime.now().isoformat()
        file_size = len(content)
        metadata = f"{timestamp},{client_ip},{url},{file_hash},{file_size},{command}\n"
        
        with open(METADATA_FILE, "a") as f:
            f.write(metadata)
            
        logging.info(f"Downloaded malware sample from {url}, saved as {file_hash} ({file_size} bytes)")
        return file_hash
        
    except Exception as e:
        logging.error(f"Error downloading from {url}: {str(e)}")
        return None

def extract_urls(command):
    """extract URLs from command string."""
    # basic URL regex
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(url_pattern, command)

def handle_connection(client, addr):
    client_ip = addr[0]
    logging.info(f"Connection from {client_ip}:{addr[1]}")
    
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        transport.local_version = "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2"  # fake version
        
        server = SSHHoneypot(client_ip)
        
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            logging.warning(f"SSH negotiation failed from {client_ip}")
            return
        
        # wait for auth
        channel = transport.accept(20)
        if channel is None:
            logging.warning(f"No channel from {client_ip}")
            return
            
        server.event.wait(10)
        
        # send fake banner
        channel.send("Welcome to Ubuntu 20.04.5 LTS\r\n")
        channel.send("Last login: Mon Mar 17 12:34:56 2025 from 192.168.1.2\r\n")
        
        buffer = ""
        try:
            while transport.is_active():
                channel.send("$ ")
                data = channel.recv(1024)
                if not data:
                    break
                    
                command = data.decode("utf-8").strip()
                logging.info(f"Command from {client_ip}: {command}")
                
                # check for download commands
                if command.startswith(("wget", "curl")) or "http://" in command or "https://" in command:
                    # log potential malware download attempt
                    logging.warning(f"Potential malware download from {client_ip}: {command}")
                    
                    # extract URLs from command
                    urls = extract_urls(command)
                    for url in urls:
                        # attempt to download the malware sample
                        file_hash = download_malware(url, client_ip, command)
                        if file_hash:
                            channel.send(f"Downloaded file saved as {file_hash[:8]}...\r\n")
                        else:
                            channel.send(f"Failed to download from {url}\r\n")
                
                # simulate command responses
                elif command.startswith("ls"):
                    channel.send("user.txt\r\nbackup.tar.gz\r\nconfig.yaml\r\n")
                elif command.startswith("cat"):
                    channel.send("Permission denied\r\n")
                elif command.startswith("whoami"):
                    channel.send("user\r\n")
                elif command == "exit":
                    channel.send("logout\r\n")
                    break
                else:
                    channel.send(f"Command not found: {command}\r\n")
        except Exception as e:
            logging.error(f"Error handling command: {str(e)}")
            
    except Exception as e:
        logging.error(f"Error handling connection: {str(e)}")
    finally:
        try:
            client.close()
        except:
            pass

def start_server(port=2222, bind="0.0.0.0"):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
        sock.listen(100)
        logging.info(f"SSH honeypot listening on {bind}:{port}")
        
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr)).start()
            
    except Exception as e:
        logging.error(f"Error starting server: {str(e)}")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run an SSH honeypot server with malware collection")
    parser.add_argument("--port", "-p", help="The port to bind the ssh server to", default=2222, type=int)
    parser.add_argument("--bind", "-b", help="The address to bind the ssh server to", default="0.0.0.0", type=str)
    args = parser.parse_args()
    
    start_server(args.port, args.bind)
