#!/usr/bin/env python3
import os
import socket
import time
import platform
import logging
import threading
import datetime
import signal
import sys
import subprocess
import re
from pathlib import Path
import queue

# Try importing optional modules with fallbacks
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("psutil not installed. Limited process monitoring available.")

try:
    import colorama
    from colorama import Fore, Style, Back
    colorama.init()
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    print("colorama not installed. Using plain text output.")
    # Create dummy color constants
    class DummyFore:
        def __getattr__(self, name):
            return ""
    Fore = DummyFore()
    Style = DummyFore()
    Back = DummyFore()

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    print("tabulate not installed. Using simple table format.")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("watchdog not installed. File monitoring disabled.")

# ========== GLOBAL VARIABLES ==========
CURRENT_OS = platform.system()
IS_ADMIN = False
open_ports_state = set()
suspicious_processes = set()
file_events = []
event_queue = queue.Queue()
MAX_FILE_EVENTS = 15
system_stats = {
    "cpu_percent": 0,
    "memory_percent": 0,
    "network_connections": 0,
    "uptime": "Unknown"
}
monitoring_active = True

# ========== LOGGING SETUP ==========
log_dir = "security_logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"security_monitor_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
    ]
)
logger = logging.getLogger("SecurityMonitor")

# ========== PLATFORM-SPECIFIC FUNCTIONS ==========
def check_admin_privileges():
    """Check if script is running with admin/root privileges"""
    global IS_ADMIN
    
    if CURRENT_OS == "Windows":
        try:
            import ctypes
            IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            IS_ADMIN = False
    else:  # Unix-based systems (Linux, macOS)
        IS_ADMIN = os.geteuid() == 0
    
    if not IS_ADMIN:
        logger.warning("Not running with administrator/root privileges. Some features may be limited.")
    return IS_ADMIN

def get_system_uptime():
    """Get system uptime in a platform-independent way"""
    if PSUTIL_AVAILABLE:
        try:
            uptime_seconds = time.time() - psutil.boot_time()
            days, remainder = divmod(uptime_seconds, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            if days > 0:
                return f"{int(days)}d {int(hours)}h {int(minutes)}m"
            elif hours > 0:
                return f"{int(hours)}h {int(minutes)}m"
            else:
                return f"{int(minutes)}m {int(seconds)}s"
        except:
            pass
    
    # Fallback methods if psutil fails
    if CURRENT_OS == "Windows":
        try:
            output = subprocess.check_output("net statistics server", shell=True).decode()
            for line in output.split("\n"):
                if "Statistics since" in line:
                    return line.replace("Statistics since", "").strip()
        except:
            pass
    elif CURRENT_OS == "Linux":
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                days, remainder = divmod(uptime_seconds, 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                if days > 0:
                    return f"{int(days)}d {int(hours)}h {int(minutes)}m"
                elif hours > 0:
                    return f"{int(hours)}h {int(minutes)}m"
                else:
                    return f"{int(minutes)}m {int(seconds)}s"
        except:
            pass
    elif CURRENT_OS == "Darwin":  # macOS
        try:
            output = subprocess.check_output("uptime", shell=True).decode()
            return output.split('up ')[1].split(',')[0].strip()
        except:
            pass
    
    return "Unknown"

# ========== FILE MONITORING ==========
class FileAccessHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            event_queue.put(("MODIFIED", event.src_path))

    def on_created(self, event):
        if not event.is_directory:
            event_queue.put(("CREATED", event.src_path))

    def on_deleted(self, event):
        if not event.is_directory:
            event_queue.put(("DELETED", event.src_path))

def event_processor():
    """Process file events from the queue to avoid overwhelming the system"""
    global file_events
    while monitoring_active:
        try:
            while not event_queue.empty():
                event_type, path = event_queue.get(block=False)
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                file_events.append((timestamp, event_type, path))
                logger.warning(f"[{event_type}] {path}")
                
                # Keep the list at a reasonable size
                if len(file_events) > MAX_FILE_EVENTS:
                    file_events.pop(0)
                    
            time.sleep(0.5)
        except queue.Empty:
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error processing events: {str(e)}")
            time.sleep(1)

def get_paths_to_monitor():
    """Get paths to monitor based on the current OS"""
    paths = []
    user_home = str(Path.home())
    
    # OS-specific browser and critical paths
    if CURRENT_OS == "Windows":
        browser_paths = [
            os.path.expandvars(r'%LocalAppData%\Google\Chrome\User Data\Default'),
            os.path.expandvars(r'%AppData%\Mozilla\Firefox\Profiles'),
            os.path.expandvars(r'%LocalAppData%\Microsoft\Edge\User Data\Default'),
            os.path.expandvars(r'%LocalAppData%\BraveSoftware\Brave-Browser\User Data\Default')
        ]
        
        critical_paths = []
        if IS_ADMIN:
            critical_paths = [
                os.path.expandvars(r'%WINDIR%\System32\drivers'),
                os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
            ]
        
        # Add desktop, downloads, and documents
        user_paths = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Documents")
        ]
        
        paths = browser_paths + critical_paths + user_paths
        
    elif CURRENT_OS == "Darwin":  # macOS
        browser_paths = [
            os.path.join(user_home, "Library/Application Support/Google/Chrome/Default"),
            os.path.join(user_home, "Library/Application Support/Firefox/Profiles"),
            os.path.join(user_home, "Library/Safari")
        ]
        
        critical_paths = []
        if IS_ADMIN:
            critical_paths = [
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
                os.path.join(user_home, "Library/LaunchAgents")
            ]
        
        # Add desktop, downloads, and documents
        user_paths = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Documents")
        ]
        
        paths = browser_paths + critical_paths + user_paths
        
    elif CURRENT_OS == "Linux":
        browser_paths = [
            os.path.join(user_home, ".config/google-chrome/Default"),
            os.path.join(user_home, ".mozilla/firefox")
        ]
        
        critical_paths = []
        if IS_ADMIN:
            critical_paths = [
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.hourly",
                "/etc/cron.weekly",
                "/etc/cron.monthly"
            ]
        
        # Add desktop, downloads, and documents
        user_paths = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Documents")
        ]
        
        paths = browser_paths + critical_paths + user_paths
    
    # Filter out non-existent paths
    return [path for path in paths if os.path.exists(path)]

def start_file_monitor():
    """Start the file monitoring system if watchdog is available"""
    if not WATCHDOG_AVAILABLE:
        logger.warning("File monitoring disabled - watchdog module not available.")
        return None
    
    paths = get_paths_to_monitor()
    if not paths:
        logger.warning("No valid paths to monitor found.")
        return None
    
    observer = Observer()
    handler = FileAccessHandler()
    
    # Start processor thread for handling events
    processor_thread = threading.Thread(target=event_processor, daemon=True)
    processor_thread.start()
    
    paths_monitored = 0
    for path in paths:
        try:
            observer.schedule(handler, path=path, recursive=True)
            logger.info(f"Monitoring file path: {path}")
            paths_monitored += 1
        except Exception as e:
            logger.error(f"Failed to monitor {path}: {str(e)}")
    
    if paths_monitored > 0:
        observer.start()
        return observer
    else:
        logger.warning("Could not monitor any paths.")
        return None

# ========== PORT MONITORING ==========
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5800: "VNC",
    5900: "VNC",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    # Potentially suspicious ports
    4444: "Metasploit",
    5555: "Android Debug",
    6666: "IRC/Backdoor",
    6667: "IRC/Backdoor",
    8888: "Alt HTTP",
    9999: "Common backdoor"
}

def check_open_ports():
    """Platform-independent port checking"""
    open_ports = set()
    
    if CURRENT_OS == "Windows":
        try:
            # Use netstat on Windows
            output = subprocess.check_output("netstat -an", shell=True).decode()
            for line in output.split('\n'):
                if "LISTENING" in line:
                    parts = line.split()
                    for part in parts:
                        if ":" in part:
                            try:
                                port = int(part.split(":")[-1])
                                if port in common_ports:
                                    open_ports.add(port)
                            except ValueError:
                                pass
        except Exception as e:
            logger.error(f"Error checking Windows ports: {str(e)}")
    
    elif CURRENT_OS == "Darwin":  # macOS
        try:
            # Use lsof on macOS
            if IS_ADMIN:
                output = subprocess.check_output("lsof -i -P -n", shell=True).decode()
            else:
                output = subprocess.check_output("lsof -i -P -n 2>/dev/null", shell=True).decode()
                
            for line in output.split('\n'):
                if "(LISTEN)" in line:
                    match = re.search(r':(\d+) $$LISTEN$$', line)
                    if match:
                        try:
                            port = int(match.group(1))
                            if port in common_ports:
                                open_ports.add(port)
                        except ValueError:
                            pass
        except Exception as e:
            logger.error(f"Error checking macOS ports: {str(e)}")
    
    elif CURRENT_OS == "Linux":
        try:
            # Use ss on Linux (modern replacement for netstat)
            if IS_ADMIN:
                output = subprocess.check_output("ss -tulwn", shell=True).decode()
            else:
                output = subprocess.check_output("ss -tulwn 2>/dev/null", shell=True).decode()
                
            for line in output.split('\n'):
                if "LISTEN" in line:
                    match = re.search(r':(\d+)\s', line)
                    if match:
                        try:
                            port = int(match.group(1))
                            if port in common_ports:
                                open_ports.add(port)
                        except ValueError:
                            pass
        except Exception as e:
            logger.error(f"Error checking Linux ports: {str(e)}")
    
    # Fallback: Try basic socket connect method for each port
    # This is less reliable but works cross-platform
    if not open_ports:
        for port in common_ports.keys():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    open_ports.add(port)
            except:
                pass
    
    return open_ports

def port_monitor():
    """Monitor for open ports"""
    global open_ports_state
    while monitoring_active:
        try:
            current_open_ports = check_open_ports()
            
            # Check for newly opened ports
            for port in current_open_ports:
                if port not in open_ports_state:
                    port_description = common_ports.get(port, "Unknown")
                    logger.warning(f"[PORT OPEN] {port} - {port_description}")
                    open_ports_state.add(port)
            
            # Check for closed ports
            for port in list(open_ports_state):
                if port not in current_open_ports:
                    logger.info(f"[PORT CLOSED] {port}")
                    open_ports_state.remove(port)
        except Exception as e:
            logger.error(f"Error in port monitoring: {str(e)}")
        
        time.sleep(5)

# ========== PROCESS MONITORING ==========
suspicious_process_names = [
    # Hacking tools
    "mimikatz", "psexec", "netcat", "nc", "nmap", "wireshark", "tcpdump", "john", 
    "hashcat", "hydra", "ettercap", "aircrack", "metasploit", "msfconsole",
    # Potentially suspicious system tools when used suspiciously
    "powershell", "cmd.exe", "bash", "sh", "telnet", "ftp", "ssh", "regedit",
    # Crypto miners
    "miner", "xmrig", "cgminer", "ethminer", "bfgminer",
    # Remote access
    "teamviewer", "anydesk", "vnc", "rdp", "ammyy",
    # Scripting
    "wscript", "cscript",
    # Common backdoor names
    "backdoor", "rootkit"
]

def is_suspicious_process(process_name):
    """Check if a process name matches known suspicious patterns"""
    if not process_name:
        return False
        
    process_name = process_name.lower()
    return any(susp.lower() in process_name for susp in suspicious_process_names)

def get_running_processes():
    """Get a list of running processes in a platform-independent way"""
    processes = []
    
    # Try using psutil first (most reliable cross-platform)
    if PSUTIL_AVAILABLE:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    process_info = proc.info
                    process_name = process_info.get('name', "")
                    if process_name:
                        pid = process_info.get('pid', 0)
                        username = process_info.get('username', "Unknown")
                        processes.append({
                            'pid': pid,
                            'name': process_name,
                            'username': username
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            return processes
        except Exception as e:
            logger.error(f"Error using psutil for process monitoring: {str(e)}")
    
    # Platform-specific fallbacks
    if CURRENT_OS == "Windows":
        try:
            output = subprocess.check_output("tasklist /FO CSV /NH", shell=True).decode()
            for line in output.split('\n'):
                if not line.strip():
                    continue
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    name = parts[0]
                    try:
                        pid = int(parts[1])
                        processes.append({
                            'pid': pid,
                            'name': name,
                            'username': "Unknown"
                        })
                    except ValueError:
                        pass
        except Exception as e:
            logger.error(f"Error using tasklist for process monitoring: {str(e)}")

    elif CURRENT_OS in ["Linux", "Darwin"]:
        try:
            cmd = "ps aux" if CURRENT_OS == "Linux" else "ps -e -o user,pid,comm"
            output = subprocess.check_output(cmd, shell=True).decode()
            lines = output.split('\n')
            
            # Skip header on first line
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    # Format is different between Linux and macOS
                    if CURRENT_OS == "Linux":
                        username = parts[0]
                        try:
                            pid = int(parts[1])
                            # Process name could be multiple parts, join the rest
                            name = ' '.join(parts[10:]) if len(parts) > 10 else parts[-1]
                            processes.append({
                                'pid': pid,
                                'name': name,
                                'username': username
                            })
                        except (ValueError, IndexError):
                            pass
                    else:  # macOS
                        username = parts[0]
                        try:
                            pid = int(parts[1])
                            name = ' '.join(parts[2:])
                            processes.append({
                                'pid': pid,
                                'name': name,
                                'username': username
                            })
                        except (ValueError, IndexError):
                            pass
        except Exception as e:
            logger.error(f"Error using ps for process monitoring: {str(e)}")
    
    return processes

def process_monitor():
    """Monitor for suspicious processes"""
    global suspicious_processes, system_stats
    while monitoring_active:
        try:
            current_suspicious = set()
            
            # Update system stats if psutil is available
            if PSUTIL_AVAILABLE:
                try:
                    system_stats["cpu_percent"] = psutil.cpu_percent(interval=0.5)
                    system_stats["memory_percent"] = psutil.virtual_memory().percent
                    system_stats["network_connections"] = len(psutil.net_connections())
                    system_stats["uptime"] = get_system_uptime()
                except Exception as e:
                    logger.error(f"Error updating system stats: {str(e)}")
            
            # Check for suspicious processes
            processes = get_running_processes()
            for process in processes:
                process_name = process.get('name', '')
                if is_suspicious_process(process_name):
                    pid = process.get('pid', 0)
                    username = process.get('username', 'Unknown')
                    proc_key = f"{pid}:{process_name}"
                    current_suspicious.add(proc_key)
                    
                    if proc_key not in suspicious_processes:
                        logger.warning(f"[SUSPICIOUS PROCESS] PID: {pid}, Name: {process_name}, User: {username}")
                        suspicious_processes.add(proc_key)
            
            # Check for terminated suspicious processes
            for proc_key in list(suspicious_processes):
                if proc_key not in current_suspicious:
                    logger.info(f"[PROCESS ENDED] {proc_key}")
                    suspicious_processes.remove(proc_key)
        
        except Exception as e:
            logger.error(f"Error in process monitoring: {str(e)}")
            
        time.sleep(3)

# ========== UI FUNCTIONS ==========
def clear_screen():
    """Clear the terminal screen in a platform-independent way"""
    os.system('cls' if CURRENT_OS == 'Windows' else 'clear')

def print_header():
    """Print the dashboard header with current time"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if COLOR_AVAILABLE:
        print(f"{Back.BLUE}{Fore.WHITE} SECURITY MONITOR {Style.RESET_ALL} {now} ({CURRENT_OS})")
    else:
        print(f"SECURITY MONITOR - {now} ({CURRENT_OS})")
    print("="*80)
    
    # Print privilege level
    if IS_ADMIN:
        print(f"{Fore.GREEN}Running with administrator privileges{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Running with limited privileges. Some features may not work.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Restart with sudo (Linux/macOS) or as Administrator (Windows) for full functionality.{Style.RESET_ALL}")
    print()

def print_system_status():
    """Print current system status"""
    if COLOR_AVAILABLE:
        cpu_color = Fore.GREEN if system_stats["cpu_percent"] < 70 else Fore.YELLOW if system_stats["cpu_percent"] < 90 else Fore.RED
        mem_color = Fore.GREEN if system_stats["memory_percent"] < 70 else Fore.YELLOW if system_stats["memory_percent"] < 90 else Fore.RED
        
        print(f"{Fore.CYAN}SYSTEM STATUS:{Style.RESET_ALL}")
        print(f"  CPU Usage: {cpu_color}{system_stats['cpu_percent']}%{Style.RESET_ALL}")
        print(f"  Memory Usage: {mem_color}{system_stats['memory_percent']}%{Style.RESET_ALL}")
        print(f"  Network Connections: {system_stats['network_connections']}")
        print(f"  System Uptime: {system_stats['uptime']}")
    else:
        print("SYSTEM STATUS:")
        print(f"  CPU Usage: {system_stats['cpu_percent']}%")
        print(f"  Memory Usage: {system_stats['memory_percent']}%")
        print(f"  Network Connections: {system_stats['network_connections']}")
        print(f"  System Uptime: {system_stats['uptime']}")
    print()

def print_port_status():
    """Print information about open ports"""
    if COLOR_AVAILABLE:
        print(f"{Fore.CYAN}OPEN PORTS:{Style.RESET_ALL}")
    else:
        print("OPEN PORTS:")
        
    if not open_ports_state:
        if COLOR_AVAILABLE:
            print(f"  {Fore.GREEN}No open ports detected{Style.RESET_ALL}")
        else:
            print("  No open ports detected")
    else:
        if TABULATE_AVAILABLE:
            port_table = []
            for port in sorted(open_ports_state):
                is_suspicious = port in [4444, 1337, 6666, 6667, 8888, 9999, 5555]
                status = f"{Fore.YELLOW}WARNING{Style.RESET_ALL}" if is_suspicious else "Normal"
                if not COLOR_AVAILABLE:
                    status = "WARNING" if is_suspicious else "Normal"
                port_table.append([port, common_ports.get(port, "Unknown"), status])
            print(tabulate(port_table, headers=["Port", "Service", "Status"]))
        else:
            # Simple table format without tabulate
            print("  Port | Service | Status")
            print("  ----- | ------- | ------")
            for port in sorted(open_ports_state):
                is_suspicious = port in [4444, 1337, 6666, 6667, 8888, 9999, 5555]
                status = f"{Fore.YELLOW}WARNING{Style.RESET_ALL}" if is_suspicious else "Normal"
                if not COLOR_AVAILABLE:
                    status = "WARNING" if is_suspicious else "Normal"
                print(f"  {port} | {common_ports.get(port, 'Unknown')} | {status}")
    print()

def print_process_status():
    """Print information about suspicious processes"""
    if COLOR_AVAILABLE:
        print(f"{Fore.CYAN}SUSPICIOUS PROCESSES:{Style.RESET_ALL}")
    else:
        print("SUSPICIOUS PROCESSES:")
        
    if not suspicious_processes:
        if COLOR_AVAILABLE:
            print(f"  {Fore.GREEN}No suspicious processes detected{Style.RESET_ALL}")
        else:
            print("  No suspicious processes detected")
    else:
        if TABULATE_AVAILABLE:
            proc_table = []
            for proc in suspicious_processes:
                pid, name = proc.split(":", 1)
                status = f"{Fore.RED}SUSPICIOUS{Style.RESET_ALL}" if COLOR_AVAILABLE else "SUSPICIOUS"
                proc_table.append([pid, name, status])
            print(tabulate(proc_table, headers=["PID", "Name", "Status"]))
        else:
            # Simple table format without tabulate
            print("  PID | Name | Status")
            print("  ----- | ------- | ------")
            for proc in suspicious_processes:
                pid, name = proc.split(":", 1)
                status = f"{Fore.RED}SUSPICIOUS{Style.RESET_ALL}" if COLOR_AVAILABLE else "SUSPICIOUS"
                print(f"  {pid} | {name} | {status}")
    print()

def print_file_events():
    """Print information about recent file events"""
    if COLOR_AVAILABLE:
        print(f"{Fore.CYAN}RECENT FILE EVENTS:{Style.RESET_ALL}")
    else:
        print("RECENT FILE EVENTS:")
        
    if not file_events:
        if COLOR_AVAILABLE:
            print(f"  {Fore.GREEN}No file events detected{Style.RESET_ALL}")
        else:
            print("  No file events detected")
    else:
        if TABULATE_AVAILABLE:
            file_table = []
            # Show last 5 events (or fewer if less than 5 exist)
            display_events = file_events[-min(5, len(file_events)):]
            for timestamp, event_type, path in display_events:
                event_status = f"{Fore.YELLOW}{event_type}{Style.RESET_ALL}" if COLOR_AVAILABLE else event_type
                file_table.append([
                    timestamp, 
                    event_status,
                    os.path.basename(path),
                    os.path.dirname(path)
                ])
            print(tabulate(file_table, headers=["Time", "Event", "File", "Path"]))
        else:
            # Simple table format without tabulate
            print("  Time | Event | File | Path")
            print("  ----- | ------- | ------ | ------")
            display_events = file_events[-min(5, len(file_events)):]
            for timestamp, event_type, path in display_events:
                event_status = f"{Fore.YELLOW}{event_type}{Style.RESET_ALL}" if COLOR_AVAILABLE else event_type
                print(f"  {timestamp} | {event_status} | {os.path.basename(path)} | {os.path.dirname(path)}")
    print()

def display_dashboard():
    """Display the security dashboard UI"""
    while monitoring_active:
        try:
            clear_screen()
            print_header()
            print_system_status()
            print_port_status()
            print_process_status()
            print_file_events()
            
            # Show helpful message at bottom
            print(f"{Fore.WHITE}Press Ctrl+C to exit | Logging to: {log_file}{Style.RESET_ALL}")
            
            # Update dashboard every 2 seconds
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error updating dashboard: {str(e)}")
            time.sleep(5)  # Longer delay on error

# ========== MAIN FUNCTIONS ==========
def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global monitoring_active
    print(f"\n{Fore.YELLOW}Shutting down security monitor...{Style.RESET_ALL}" if COLOR_AVAILABLE else "\nShutting down security monitor...")
    monitoring_active = False
    time.sleep(1)
    print(f"{Fore.GREEN}Security monitoring stopped.{Style.RESET_ALL}" if COLOR_AVAILABLE else "Security monitoring stopped.")
    print(f"Log file saved to: {log_file}")
    sys.exit(0)

def run():
    """Main function to run the security monitor"""
    global monitoring_active
    
    # Check for admin/root privileges
    check_admin_privileges()
    
    logger.info(f"Starting Security Monitor on {CURRENT_OS}")
    logger.info(f"Admin privileges: {IS_ADMIN}")
    
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start file monitor if available
    file_observer = start_file_monitor()
    
    # Start monitoring threads
    threads = []
    
    # Port monitoring thread
    port_thread = threading.Thread(target=port_monitor, daemon=True)
    port_thread.start()
    threads.append(port_thread)
    
    # Process monitoring thread
    process_thread = threading.Thread(target=process_monitor, daemon=True)
    process_thread.start()
    threads.append(process_thread)
    
    # UI thread
    ui_thread = threading.Thread(target=display_dashboard, daemon=True)
    ui_thread.start()
    threads.append(ui_thread)
    
    logger.info("Security monitoring active. Press Ctrl+C to exit.")
    
    try:
        # Keep the main thread alive
        while monitoring_active:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
    finally:
        monitoring_active = False
        if file_observer:
            file_observer.stop()
            file_observer.join()
        
        # Wait for threads to finish
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=1)

if __name__ == "__main__":
    # Show startup banner
    print("\n" + "="*60)
    print(" CROSS-PLATFORM SECURITY MONITOR ")
    print("="*60 + "\n")
    
    if COLOR_AVAILABLE:
        print(f"{Fore.YELLOW}Starting security monitoring...{Style.RESET_ALL}")
    else:
        print("Starting security monitoring...")
        
    # Check for required modules
    missing_modules = []
    if not PSUTIL_AVAILABLE:
        missing_modules.append("psutil")
    if not WATCHDOG_AVAILABLE:
        missing_modules.append("watchdog")
    if not COLOR_AVAILABLE:
        missing_modules.append("colorama")
    if not TABULATE_AVAILABLE:
        missing_modules.append("tabulate")
    
    if missing_modules:
        print("\nSome optional modules are missing. For full functionality, install:")
        print(f"pip install {' '.join(missing_modules)}")
        print("Continuing with limited functionality...\n")
        time.sleep(2)
    
    # Run the security monitor
    run()
