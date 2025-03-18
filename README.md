# SSH Honeypot with Malware Collection

A Python-based SSH honeypot designed to log unauthorized access attempts and collect malware samples deployed by attackers. This tool helps security researchers study attack patterns, collect credentials used in brute force attempts, and gather malware samples for analysis.

- **Low-interaction SSH honeypot** that simulates a real SSH server
- **Credential harvesting** to collect usernames and passwords from brute force attempts
- **Command logging** to analyze attacker behavior and tactics
- **Malware sample collection** to gather binaries, scripts, and other malicious payloads
- **Comprehensive logging** with timestamps, IP addresses, and session details
- **Realistic environment simulation** to keep attackers engaged
- **Thread-based connection handling** for multiple simultaneous connections

## Requirements

- Python 3.6+
- Paramiko
- Requests

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ssh-honeypot.git
   cd ssh-honeypot
   ```

2. Install dependencies:
   ```bash
   pip install paramiko requests
   ```

3. Run the honeypot:
   ```bash
   python3 ssh_honeypot.py
   ```

## Configuration

The honeypot has several configurable options that can be adjusted via command-line arguments:

```bash
python3 ssh_honeypot.py --port 2222 --bind 0.0.0.0
```

Available options:
- `--port, -p`: The port to run the SSH honeypot on (default: 2222)
- `--bind, -b`: The IP address to bind to (default: 0.0.0.0)

## How It Works

This honeypot operates by:

1. Presenting an SSH server on port 2222 (by default)
2. Accepting all authentication attempts while logging credentials
3. Providing a simulated shell environment to the attacker
4. Recording all commands entered by attackers
5. Detecting attempts to download malware and saving samples
6. Maintaining detailed logs of all activity

## Malware Collection

When an attacker attempts to download malware (using wget, curl, or direct URLs), the honeypot:

1. Extracts URLs from the command
2. Downloads the file with proper error handling and timeouts
3. Calculates a SHA-256 hash of the file
4. Stores the file in the `samples/` directory using the hash as filename
5. Records metadata including timestamp, attacker IP, URL, and the command used

Malware metadata is stored in `malware_metadata.log` with the following format:
```
timestamp,attacker_ip,download_url,file_hash,file_size,command
```

## Log Files

The honeypot maintains logs in:
- `ssh_honeypot.log`: Main log file with all connection and command information
- `malware_metadata.log`: Detailed information about downloaded malware samples

## Security Considerations

⚠️ **IMPORTANT**: This honeypot is designed for research purposes. Please consider the following security measures:

1. **Never run as root**. Use a dedicated user with minimal privileges.
2. **Run in isolation**. Consider using Docker or a dedicated VM.
3. **Network segmentation**. Place the honeypot in a separate network segment.
4. **Firewall rules**. Only expose the honeypot port (2222, or whatever you set) and restrict other traffic.
5. **Handle collected malware with care**. All samples should be considered dangerous.
6. **Regularly back up logs** to a secure location.
7. **Monitor the honeypot** for unusual system behavior.

## Responsible Deployment

When deploying this honeypot:
- Ensure you have proper authorization to run it on your network
- Do not use it to entrap or deceive specific individuals
- Do not use collected credentials or malware for malicious purposes

## Example Docker Deployment

For safer deployment, you can use Docker:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY ssh_honeypot.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/samples

# Run as non-root user
RUN useradd -m honeypotuser
USER honeypotuser

CMD ["python", "ssh_honeypot.py"]
```

Build and run:
```bash
docker build -t ssh-honeypot .
docker run -p 2222:2222 ssh-honeypot
```

## Analyzing Collected Data

The collected data can be analyzed to:
- Identify common usernames and passwords used in attacks
- Study attacker behavior patterns
- Analyze malware deployment techniques
- Track attack sources and timing patterns

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. Use at your own risk.

---

*Always ensure you have authorization to run security tools on your networks and systems.*