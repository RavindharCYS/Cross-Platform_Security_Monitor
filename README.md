# Cross-Platform Security Monitor

![Security Monitor Banner](https://img.shields.io/badge/Security-Monitor-red?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.6+-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

A comprehensive, real-time security monitoring tool for Windows, macOS, and Linux systems. This tool provides continuous surveillance of key system components to detect potential security threats and suspicious activities.

## 🔍 Features

### File System Monitoring
- Detects file creation, modification, and deletion in sensitive locations
- Monitors browser data directories, system folders, and user documents
- Provides real-time alerts for suspicious file activities

### Network Port Monitoring
- Scans for open ports and identifies running services
- Flags potentially malicious ports commonly used by malware
- Detects unauthorized network services in real-time

### Process Monitoring
- Identifies suspicious processes like hacking tools and potential malware
- Monitors administrative tools that could be used maliciously
- Alerts when suspicious processes start or terminate

### System Resource Analysis
- Tracks CPU and memory usage for potential resource abuse
- Monitors network connection count
- Displays system uptime information

### Cross-Platform Support
- Works on Windows, macOS, and Linux
- Uses platform-specific optimizations when available
- Gracefully degrades functionality based on available permissions

## 📋 Requirements

### Minimum Requirements
- Python 3.6 or higher

### Recommended Dependencies
```bash
pip install psutil watchdog colorama tabulate
```

The tool will adapt to missing packages by using limited functionality:
- **Without psutil**: Limited process and system monitoring
- **Without watchdog**: File system monitoring disabled
- **Without colorama**: Plain text output instead of colorized
- **Without tabulate**: Simple table formatting

## ⚙️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RavindharCYS/Cross-Platform_Security_Monitor.git
   cd Cross-Platform_Security_Monitor
   ```

2. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

### Windows
```bash
# Run with administrator privileges for full functionality
python security_monitor.py
```

### macOS
```bash
# Run with administrator privileges for full functionality
sudo python3 security_monitor.py

# Or with basic functionality
python3 security_monitor.py
```

### Linux
```bash
# Run with administrator privileges for full functionality
sudo python3 security_monitor.py

# Or with basic functionality
python3 security_monitor.py
```

## 📊 Dashboard Interface

The tool provides a real-time dashboard with the following sections:

- **System Status**: CPU, memory usage, network connections, and uptime
- **Open Ports**: List of open network ports with service identification
- **Suspicious Processes**: Processes that match known suspicious patterns
- **Recent File Events**: Latest file system activities in monitored locations

![Dashboard Example](https://github.com/RavindharCYS/Cross-Platform_Security_Monitor/blob/main/Screenshot%201.png)

## 📝 Log Files

The security monitor saves detailed logs to the `security_logs` directory. Each monitoring session creates a timestamped log file containing all security events detected during runtime.

## 🛡️ Administrator/Root Privileges

While the tool can run with regular user permissions, administrator/root privileges are recommended for:

- Monitoring system-critical directories
- Detecting all open network ports
- Accessing information about all running processes

The tool will automatically detect available privileges and adjust functionality accordingly.

## ⚠️ Limitations

- File monitoring performance may degrade when watching many directories
- Some system processes may not be visible without administrator privileges
- On macOS, System Integrity Protection (SIP) may restrict access to certain system areas
- Heavy CPU usage may occur on systems with limited resources

## 🔒 Privacy & Security

This tool:
- ✅ Operates entirely locally on your system
- ✅ Does not send or receive any data over the network
- ✅ Does not modify any system files
- ✅ Can be stopped at any time with `Ctrl+C`

## 📜 Disclaimer

⚠️ **Important**: This security monitoring tool is provided for educational and defensive security purposes only. It should be used only on systems you own or have permission to monitor. The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📸 Screenshots

### Windows Interface
![Windows Interface](https://via.placeholder.com/800x600/0078d4/ffffff?text=Windows+Interface)

### macOS Interface
![macOS Interface](https://via.placeholder.com/800x600/000000/ffffff?text=macOS+Interface)

### Linux Interface
![Linux Interface](https://via.placeholder.com/800x600/ff6900/ffffff?text=Linux+Interface)

---

<div align="center">
  <strong>🔐 Keep your systems secure with continuous monitoring! 🔐</strong>
</div>
