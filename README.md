
# 🛡️ Rebel Security Scanner v4.0

**An advanced web vulnerability scanner for educational and professional use**  
🚀 Fully supports Arabic and English, combining power and usability for beginners and experts.

---

## ⚙️ Key Features

- 🔍 Supports scanning for multiple vulnerabilities:
  - `LFI`, `XSS`, `SQLi`, `SSRF`, `RCE`, `IDOR`, `Command Injection`
  - `File Upload`, `Redirect`, `CSP`, `DOM XSS`, `CORS`, `Path Traversal`
  - `Security Headers` scanning and `Subdomain` discovery
- 🧠 Intelligent analysis of JavaScript files to detect hidden endpoints
- 🌐 Proxy, cookies, and custom headers support
- 🎯 Real-time notifications via Discord or Telegram webhooks
- 📊 Report generation in multiple formats: JSON, CSV, HTML
- ☁️ Cloud upload support for reports (Google Cloud)
- ⏱️ Scheduled scans supported (`daily`, `weekly`, `monthly`)
- 🖥️ Integration with external tools:
  - `nmap`, `wpscan`, `nikto`

---

## 🧰 Requirements

- Python 3.8+
- OS: Linux or Windows
- External tools to install manually if used:
  - `nmap`, `wpscan`, `nikto`

---

## 📦 Installation

```bash
git clone https://github.com/Abdelrahmaneala/scan_web_valn.git
cd scan_web_valn
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Linux/macOS

pip install -r requirements.txt
```

---

## 🚀 Usage Examples

### Full scan:
```bash
python scan_web_valn.py --target http://example.com --scan all
```

### Specific scan types:
```bash
python scan_web_valn.py --target http://example.com --scan xss,sqli
```

### Aggressive mode:
```bash
python scan_web_valn.py --target http://example.com --aggressive
```

### Save results to file:
```bash
python scan_web_valn.py --target http://example.com --output result --format html
```

### Use a proxy:
```bash
python scan_web_valn.py --target http://example.com --proxy http://127.0.0.1:8080
```

---

## 🧪 Additional Options

| Option | Description |
|--------|-------------|
| `--cookie` | Pass session cookies |
| `--auth` | Authentication (user:pass) |
| `--bearer` | Bearer token |
| `--payloads` | Custom payloads JSON file |
| `--timeout` | Request timeout (default: 15s) |
| `--threads` | Number of threads (default: 10) |
| `--webhook` | Discord webhook URL |
| `--telegram` | Telegram alert (`token:chatid`) |
| `--nmap` | Run Nmap scan |
| `--wpscan` | Run WPScan |
| `--nikto` | Run Nikto |
| `--gcloud-bucket` | Upload report to Google Cloud |

---


## 📜 Legal Disclaimer

This tool is for **educational purposes only**.  
**Unauthorized use against real systems is solely the user's responsibility.**

---

## 🧠 Author

👨‍💻 [@Abdelrahmaneala](https://github.com/Abdelrahmaneala)  
📧 For inquiries or feedback, feel free to open an issue or contact via GitHub.

---
