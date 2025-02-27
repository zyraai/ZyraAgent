import psutil
import socket
import time
from datetime import datetime
import requests
import logging
import platform
from typing import Dict, List, Optional
import os
import ctypes
import sys
import threading
import queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import uuid
import win32evtlog
import winreg
import win32com.client
import subprocess
import hashlib
from scapy.all import sniff, DNS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='system_monitor.log'
)
logger = logging.getLogger(__name__)

# API endpoint configuration
API_BASE_URL = "http://localhost:8000/api/v1"  # Update this to your server's URL if different

class AnomalyDetector:
    def __init__(self):
        self.login_attempts = {}
        self.threshold = 5
        self.time_window = 300

    def check_login_anomaly(self, event: Dict) -> Optional[Dict]:
        if event.get("type") != "failure":
            return None
        user = event.get("user", "Unknown")
        timestamp = datetime.now().timestamp()
        if user not in self.login_attempts:
            self.login_attempts[user] = []
        self.login_attempts[user] = [t for t in self.login_attempts[user] if timestamp - t < self.time_window]
        self.login_attempts[user].append(timestamp)
        if len(self.login_attempts[user]) >= self.threshold:
            return {
                "type": "login_anomaly",
                "user": user,
                "attempts": len(self.login_attempts[user]),
                "details": "Multiple failed login attempts detected",
                "timestamp": datetime.now().isoformat()
            }
        return None

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, data_queue, device_id, hostname):
        self.data_queue = data_queue
        self.device_id = device_id
        self.hostname = hostname

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        data = {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "type": "file_event",
            "event": "created",
            "path": file_path,
            "timestamp": datetime.now().isoformat()
        }
        self.data_queue.put(data)

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        data = {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "type": "file_event",
            "event": "modified",
            "path": file_path,
            "timestamp": datetime.now().isoformat()
        }
        self.data_queue.put(data)

    def on_deleted(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        data = {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "type": "file_deletion",
            "path": file_path,
            "details": "File deleted",
            "timestamp": datetime.now().isoformat()
        }
        if 'log' in file_path.lower() or file_path.endswith('.log'):
            data["details"] = "Log file deleted - potential security concern"
            data["severity"] = "high"
        self.data_queue.put(data)

class SystemMonitor:
    def __init__(self, require_admin: bool = False, monitor_path: str = ".", config_files: List[str] = None):
        self.os_type = platform.system()
        self.is_admin = self._check_admin()
        self.require_admin = require_admin
        self.running = False
        self.data_queue = queue.Queue()
        self.anomaly_detector = AnomalyDetector()
        self.monitor_path = monitor_path
        self.hostname = socket.gethostname()
        self.device_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, self.hostname))
        self.system_name = platform.node()
        self.last_registry_state = {}
        self.config_files = config_files or (
            [r"C:\Windows\System32\drivers\etc\hosts"] if self.os_type == "Windows" 
            else ["/etc/passwd", "/etc/hosts"]
        )
        self.config_hashes = {path: self._get_file_hash(path) for path in self.config_files if os.path.exists(path)}
        self.last_boot_time = psutil.boot_time()
        self.agent_file = os.path.abspath(__file__)
        self.agent_hash = self._get_file_hash(self.agent_file)
        self.agent_pid = os.getpid()
        
        if require_admin and not self.is_admin:
            logger.warning("Admin privileges required - attempting to elevate")
            if self._request_admin():
                return
            else:
                raise PermissionError("This script requires administrative privileges and elevation failed")

    def _check_admin(self) -> bool:
        if self.os_type == "Windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    def _request_admin(self) -> bool:
        if self.is_admin:
            return True
        if self.os_type == "Windows":
            try:
                result = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{os.path.abspath(__file__)}" {" ".join(sys.argv[1:])}', None, 1
                )
                if result > 32:
                    sys.exit(0)
                return False
            except Exception as e:
                logger.error(f"Failed to elevate privileges: {e}")
                return False
        return False

    def _get_file_hash(self, file_path: str) -> str:
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def _send_data_to_server(self, data):
        try:
            response = requests.post(f"{API_BASE_URL}/data", json=data)
            if response.status_code == 200:
                logger.info(f"Sent {data['type']} data to server for device {self.device_id}")
            else:
                logger.error(f"Failed to send data: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error sending data to server: {e}")

    def get_system_info(self):
        while self.running:
            try:
                ip_address = socket.gethostbyname(self.hostname)
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                data = {
                    "device_id": self.device_id,
                    "hostname": self.hostname,
                    "type": "system",
                    "data": {
                        "system_name": self.system_name,
                        "ip_address": ip_address,
                        "cpu_usage": cpu_usage,
                        "memory_usage": memory.percent,
                        "os": self.os_type,
                        "is_admin": self.is_admin
                    },
                    "timestamp": datetime.now().isoformat()
                }
                self.data_queue.put(data)
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error collecting system info: {e}")
                time.sleep(1)

    def get_network_stats(self):
        while self.running:
            try:
                net_io = psutil.net_io_counters()
                data = {
                    "device_id": self.device_id,
                    "hostname": self.hostname,
                    "type": "network",
                    "data": {
                        "system_name": self.system_name,
                        "bytes_sent": net_io.bytes_sent,
                        "bytes_received": net_io.bytes_recv,
                        "packets_sent": net_io.packets_sent,
                        "packets_received": net_io.packets_recv
                    },
                    "timestamp": datetime.now().isoformat()
                }
                self.data_queue.put(data)
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error collecting network stats: {e}")
                time.sleep(1)

    def capture_dns_queries(self):
        if not self.is_admin:
            logger.warning("DNS capture requires admin privileges - skipping")
            return
        def process_packet(packet):
            try:
                if self.running and packet.haslayer(DNS) and packet[DNS].qr == 0:
                    query = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    data = {
                        "device_id": self.device_id,
                        "hostname": self.hostname,
                        "type": "dns_query",
                        "data": {
                            "system_name": self.system_name,
                            "domain": query
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                    self.data_queue.put(data)
            except Exception as e:
                logger.error(f"Error processing DNS packet: {e}")
        try:
            logger.info("Starting DNS capture...")
            sniff(filter="udp port 53", prn=process_packet, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.error(f"DNS capture error: {e}")

    def get_login_events(self):
        if self.os_type != "Windows" or not self.is_admin:
            logger.warning("Login events require Windows and admin privileges - skipping")
            return
        try:
            server = "localhost"
            log_type = "Security"
            hand = win32evtlog.OpenEventLog(server, log_type)
            while self.running:
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    timestamp = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                    event_data = {"timestamp": timestamp, "user": "Unknown"}
                    if event_id == 4624:
                        event_data["type"] = "success"
                        if len(event.StringInserts) > 5:
                            event_data["user"] = event.StringInserts[5]
                    elif event_id == 4625:
                        event_data["type"] = "failure"
                        if len(event.StringInserts) > 5:
                            event_data["user"] = event.StringInserts[5]
                    if "type" in event_data:
                        data = {
                            "device_id": self.device_id,
                            "hostname": self.hostname,
                            "type": "login_event",
                            "data": {
                                "system_name": self.system_name,
                                **event_data
                            },
                            "timestamp": datetime.now().isoformat()
                        }
                        self.data_queue.put(data)
                        anomaly = self.anomaly_detector.check_login_anomaly(event_data)
                        if anomaly:
                            anomaly["device_id"] = self.device_id
                            anomaly["hostname"] = self.hostname,
                            anomaly["data"] = {"system_name": self.system_name, **anomaly}
                            del anomaly["timestamp"]  # Avoid nesting timestamp
                            anomaly["timestamp"] = datetime.now().isoformat()
                            self.data_queue.put(anomaly)
                time.sleep(1)
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logger.error(f"Error collecting login events: {e}")

    def monitor_file_events(self):
        event_handler = FileEventHandler(self.data_queue, self.device_id, self.hostname)
        observer = Observer()
        observer.schedule(event_handler, self.monitor_path, recursive=True)
        observer.start()
        try:
            while self.running:
                time.sleep(1)
        except Exception as e:
            logger.error(f"File monitoring error: {e}")
        finally:
            observer.stop()
            observer.join()

    def monitor_users(self):
        while self.running:
            try:
                users = psutil.users()
                user_data = [{
                    "username": user.name,
                    "terminal": user.terminal or "N/A",
                    "host": user.host or "N/A",
                    "started": datetime.fromtimestamp(user.started).isoformat()
                } for user in users]
                data = {
                    "device_id": self.device_id,
                    "hostname": self.hostname,
                    "type": "user_activity",
                    "data": {
                        "system_name": self.system_name,
                        "users": user_data
                    },
                    "timestamp": datetime.now().isoformat()
                }
                self.data_queue.put(data)
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error monitoring users: {e}")
                time.sleep(5)

    def monitor_registry(self):
        if self.os_type != "Windows" or not self.is_admin:
            logger.warning("Registry monitoring requires Windows and admin privileges - skipping")
            return
        critical_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
        ]
        while self.running:
            try:
                for hive, subkey in critical_keys:
                    key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                    num_values = winreg.QueryInfoKey(key)[1]
                    current_state = {}
                    for i in range(num_values):
                        name, value, _ = winreg.EnumValue(key, i)
                        current_state[name] = value
                    if subkey in self.last_registry_state:
                        old_state = self.last_registry_state[subkey]
                        changes = {k: v for k, v in current_state.items() if k not in old_state or old_state[k] != v}
                        if changes:
                            data = {
                                "device_id": self.device_id,
                                "hostname": self.hostname,
                                "type": "registry_change",
                                "data": {
                                    "system_name": self.system_name,
                                    "key": subkey,
                                    "changes": changes,
                                    "details": "Registry key modified"
                                },
                                "timestamp": datetime.now().isoformat()
                            }
                            self.data_queue.put(data)
                    self.last_registry_state[subkey] = current_state
                    winreg.CloseKey(key)
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error monitoring registry: {e}")
                time.sleep(5)

    def monitor_firewall(self):
        if self.os_type != "Windows" or not self.is_admin:
            logger.warning("Firewall monitoring requires Windows and admin privileges - skipping")
            return
        try:
            server = "localhost"
            log_type = "Security"
            hand = win32evtlog.OpenEventLog(server, log_type)
            while self.running:
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    if event_id in (2004, 2005):
                        timestamp = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                        data = {
                            "device_id": self.device_id,
                            "hostname": self.hostname,
                            "type": "firewall_change",
                            "data": {
                                "system_name": self.system_name,
                                "event_id": event_id,
                                "timestamp": timestamp,
                                "details": "Firewall rule " + ("added" if event_id == 2004 else "modified"),
                                "strings": event.StringInserts if event.StringInserts else []
                            },
                            "timestamp": datetime.now().isoformat()
                        }
                        self.data_queue.put(data)
                time.sleep(1)
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logger.error(f"Error monitoring firewall: {e}")

    def monitor_remote_commands(self):
        if self.os_type != "Windows" or not self.is_admin:
            logger.warning("Remote command detection requires Windows and admin privileges - skipping")
            return
        try:
            server = "localhost"
            log_type = "Security"
            hand = win32evtlog.OpenEventLog(server, log_type)
            while self.running:
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    if event_id == 4688:
                        timestamp = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                        command_line = event.StringInserts[8] if len(event.StringInserts) > 8 else "N/A"
                        if any(cmd in command_line.lower() for cmd in ["powershell", "wmic", "cmd"]):
                            data = {
                                "device_id": self.device_id,
                                "hostname": self.hostname,
                                "type": "remote_command",
                                "data": {
                                    "system_name": self.system_name,
                                    "event_id": event_id,
                                    "timestamp": timestamp,
                                    "command_line": command_line,
                                    "details": "Potential remote command execution detected"
                                },
                                "timestamp": datetime.now().isoformat()
                            }
                            self.data_queue.put(data)
                time.sleep(1)
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logger.error(f"Error monitoring remote commands: {e}")

    def monitor_services(self):
        while self.running:
            try:
                if self.os_type == "Windows" and self.is_admin:
                    server = "localhost"
                    log_type = "System"
                    hand = win32evtlog.OpenEventLog(server, log_type)
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    for event in events:
                        if event.EventID == 7036:  # Service start/stop
                            timestamp = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                            service_name = event.StringInserts[0] if event.StringInserts else "Unknown"
                            state = event.StringInserts[1] if len(event.StringInserts) > 1 else "Unknown"
                            data = {
                                "device_id": self.device_id,
                                "hostname": self.hostname,
                                "type": "service_event",
                                "data": {
                                    "system_name": self.system_name,
                                    "service_name": service_name,
                                    "state": state,
                                    "timestamp": timestamp
                                },
                                "timestamp": datetime.now().isoformat()
                            }
                            self.data_queue.put(data)
                            if state.lower() == "stopped" and "antivirus" in service_name.lower():
                                alert = {
                                    "device_id": self.device_id,
                                    "hostname": self.hostname,
                                    "type": "service_alert",
                                    "data": {
                                        "system_name": self.system_name,
                                        "details": f"Critical service stopped: {service_name}",
                                        "severity": "high"
                                    },
                                    "timestamp": datetime.now().isoformat()
                                }
                                self.data_queue.put(alert)
                    win32evtlog.CloseEventLog(hand)
                elif self.os_type == "Linux":
                    result = subprocess.run(['systemctl', '--type=service', '--all'], capture_output=True, text=True)
                    services = [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
                    for service in services:
                        status = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True).stdout.strip()
                        data = {
                            "device_id": self.device_id,
                            "hostname": self.hostname,
                            "type": "service_event",
                            "data": {
                                "system_name": self.system_name,
                                "service_name": service,
                                "state": status
                            },
                            "timestamp": datetime.now().isoformat()
                        }
                        self.data_queue.put(data)
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error monitoring services: {e}")
                time.sleep(5)

    def monitor_config_files(self):
        event_handler = FileEventHandler(self.data_queue, self.device_id, self.hostname)
        observer = Observer()
        for config_file in self.config_files:
            if os.path.exists(config_file):
                observer.schedule(event_handler, os.path.dirname(config_file), recursive=False)
        observer.start()
        while self.running:
            try:
                for config_file in self.config_files:
                    if os.path.exists(config_file):
                        current_hash = self._get_file_hash(config_file)
                        if config_file in self.config_hashes and self.config_hashes[config_file] != current_hash:
                            data = {
                                "device_id": self.device_id,
                                "hostname": self.hostname,
                                "type": "config_change",
                                "data": {
                                    "system_name": self.system_name,
                                    "path": config_file,
                                    "details": "Critical configuration file modified",
                                    "severity": "high"
                                },
                                "timestamp": datetime.now().isoformat()
                            }
                            self.data_queue.put(data)
                            self.config_hashes[config_file] = current_hash
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error monitoring config files: {e}")
                time.sleep(5)
        observer.stop()
        observer.join()

    def protect_agent(self):
        while self.running:
            try:
                current_hash = self._get_file_hash(self.agent_file)
                if current_hash != self.agent_hash:
                    data = {
                        "device_id": self.device_id,
                        "hostname": self.hostname,
                        "type": "agent_alert",
                        "data": {
                            "system_name": self.system_name,
                            "details": "Agent file modified",
                            "severity": "critical"
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                    self.data_queue.put(data)
                    os.system(f"python {self.agent_file} &")
                    sys.exit(1)
                
                if not psutil.pid_exists(self.agent_pid):
                    data = {
                        "device_id": self.device_id,
                        "hostname": self.hostname,
                        "type": "agent_alert",
                        "data": {
                            "system_name": self.system_name,
                            "details": "Agent process terminated",
                            "severity": "critical"
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                    self.data_queue.put(data)
                    os.system(f"python {self.agent_file} &")
                    sys.exit(1)
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error protecting agent: {e}")
                time.sleep(5)

    def remote_control(self):
        while self.running:
            try:
                response = requests.get(f"{API_BASE_URL}/{self.device_id}/commands")
                if response.status_code == 200:
                    commands = response.json()
                    for cmd_doc in commands:
                        if not cmd_doc.get("processed", False):
                            cmd = cmd_doc["command"]
                            if cmd == "kill_process" and "pid" in cmd_doc:
                                pid = cmd_doc["pid"]
                                try:
                                    process = psutil.Process(pid)
                                    process.terminate()
                                    result = f"Terminated process {pid}"
                                except Exception as e:
                                    result = f"Failed to terminate {pid}: {e}"
                            elif cmd == "collect_file" and "path" in cmd_doc:
                                path = cmd_doc["path"]
                                try:
                                    with open(path, "rb") as f:
                                        file_content = f.read()
                                    result = f"Collected {len(file_content)} bytes from {path}"
                                except Exception as e:
                                    result = f"Failed to collect {path}: {e}"
                            else:
                                result = f"Unknown command: {cmd}"
                            
                            data = {
                                "device_id": self.device_id,
                                "hostname": self.hostname,
                                "type": "remote_response",
                                "data": {
                                    "system_name": self.system_name,
                                    "command": cmd,
                                    "result": result
                                },
                                "timestamp": datetime.now().isoformat()
                            }
                            self.data_queue.put(data)
                            # Mark command as processed
                            requests.put(f"{API_BASE_URL}/commands/{cmd_doc['command_id']}", json={"processed": True})
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in remote control: {e}")
                time.sleep(5)

    def monitor_uptime(self):
        while self.running:
            try:
                current_boot_time = psutil.boot_time()
                uptime = time.time() - current_boot_time
                if current_boot_time != self.last_boot_time:
                    data = {
                        "device_id": self.device_id,
                        "hostname": self.hostname,
                        "type": "reboot_event",
                        "data": {
                            "system_name": self.system_name,
                            "details": "System rebooted",
                            "previous_boot": datetime.fromtimestamp(self.last_boot_time).isoformat(),
                            "current_boot": datetime.fromtimestamp(current_boot_time).isoformat()
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                    self.data_queue.put(data)
                    self.last_boot_time = current_boot_time
                data = {
                    "device_id": self.device_id,
                    "hostname": self.hostname,
                    "type": "uptime",
                    "data": {
                        "system_name": self.system_name,
                        "uptime_seconds": uptime
                    },
                    "timestamp": datetime.now().isoformat()
                }
                self.data_queue.put(data)
                time.sleep(10)
            except Exception as e:
                logger.error(f"Error monitoring uptime: {e}")
                time.sleep(10)

    def update_agent_status(self):
        while self.running:
            try:
                data = {
                    "device_id": self.device_id,
                    "hostname": self.hostname,
                    "type": "agent_status",
                    "data": {
                        "system_name": self.system_name,
                        "status": "online"
                    },
                    "timestamp": datetime.now().isoformat()
                }
                self.data_queue.put(data)
                time.sleep(30)  # Update every 30 seconds
            except Exception as e:
                logger.error(f"Error updating agent status: {e}")
                time.sleep(30)

    def store_data(self):
        while self.running:
            try:
                while not self.data_queue.empty():
                    data = self.data_queue.get()
                    self._send_data_to_server(data)
                    self.data_queue.task_done()
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in data storage thread: {e}")
                time.sleep(1)

    def start(self):
        if self.running:
            return
        self.running = True
        logger.info(f"Starting real-time system monitor for device {self.device_id}")
        logger.info(f"Hostname: {self.hostname}, System Name: {self.system_name}")
        logger.info(f"Running with admin privileges: {self.is_admin}")
        logger.info(f"Monitoring file events in: {self.monitor_path}")
        logger.info(f"Monitoring config files: {self.config_files}")

        threads = [
            threading.Thread(target=self.get_system_info, daemon=True),
            threading.Thread(target=self.get_network_stats, daemon=True),
            threading.Thread(target=self.capture_dns_queries, daemon=True),
            threading.Thread(target=self.get_login_events, daemon=True),
            threading.Thread(target=self.monitor_file_events, daemon=True),
            threading.Thread(target=self.monitor_users, daemon=True),
            threading.Thread(target=self.monitor_registry, daemon=True),
            threading.Thread(target=self.monitor_firewall, daemon=True),
            threading.Thread(target=self.monitor_remote_commands, daemon=True),
            threading.Thread(target=self.monitor_services, daemon=True),
            threading.Thread(target=self.monitor_config_files, daemon=True),
            threading.Thread(target=self.protect_agent, daemon=True),
            threading.Thread(target=self.remote_control, daemon=True),
            threading.Thread(target=self.monitor_uptime, daemon=True),
            threading.Thread(target=self.update_agent_status, daemon=True),
            threading.Thread(target=self.store_data, daemon=True)
        ]

        for thread in threads:
            thread.start()

    def stop(self):
        self.running = False
        # Send offline status
        try:
            data = {
                "device_id": self.device_id,
                "hostname": self.hostname,
                "type": "agent_status",
                "data": {
                    "system_name": self.system_name,
                    "status": "offline"
                },
                "timestamp": datetime.now().isoformat()
            }
            self._send_data_to_server(data)
        except Exception as e:
            logger.error(f"Error sending offline status: {e}")
        logger.info("Shutting down monitor...")

if __name__ == "__main__":
    monitor = SystemMonitor(
        require_admin=True,
        monitor_path="C:\\Users\\Adnan\\Desktop\\Zyra",
        config_files=[r"C:\Windows\System32\drivers\etc\hosts"]
    )
    try:
        monitor.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()