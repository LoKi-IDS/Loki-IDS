import json
import logging
import os
from datetime import datetime

class LokiLogger:
    """
    Handles logging of IDS alerts to both console and a structured JSONL file.
    """
    def __init__(self, log_dir="logs", filename="loki_alerts.jsonl"):
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(current_dir))
        self.log_dir = os.path.join(project_root, log_dir)
        
        self.filename = filename
        self.filepath = os.path.join(self.log_dir, self.filename)
        
        # Ensure log directory exists
        if not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir)
            except Exception as e:
                logger.console_logger.critical(f"[!] couldn't create the log directory: {e}")
                self.log_dir = current_dir # I will just work on the current director.

        # Setup Python's built-in logging for console output
        self.console_logger = logging.getLogger("LokiIDS")
        self.console_logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers if re-initialized
        if not self.console_logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.console_logger.addHandler(ch)

    def log_alert(self, alert_type, src_ip, dst_ip, src_port, dst_port, message, details=None):
        """
        Logs an alert to the console and appends a JSON record to the log file.
        
        Args:
            alert_type (str): "SIGNATURE", "BEHAVIOR", or "BLACKLIST".
            src_ip (str): The attacker's IP address.
            message (str): A human-readable description (e.g., "Port Scan Detected").
            details (dict, optional): Extra data (e.g., ports scanned, payload snippet).
        """
        timestamp = datetime.utcnow().isoformat()
        
        # 1. Console Output (Human Readable)
        self.console_logger.warning(f"[{alert_type}] {src_ip}:{src_port}->{dst_ip}:{dst_port} - {message}")
        
        # 2. File Output (Machine Readable - JSON Lines)
        record = {
            "timestamp": timestamp,
            "type": alert_type,
            "src_ip": src_ip,
            "message": message,
            "details": details or {}
        }
        
        try:
            with open(self.filepath, 'a') as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            self.console_logger.error(f"Failed to write to log file: {e}")

# Create a singleton instance for easy import
logger = LokiLogger()
