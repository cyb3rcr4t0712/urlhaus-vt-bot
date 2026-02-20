# 🚨 URLhaus → VirusTotal Bot

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20GCP-orange?logo=google-cloud)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Uptime](https://img.shields.io/badge/Uptime-24%2F7-brightgreen)
![Comments](https://img.shields.io/badge/Comments-490%2Fday-red)

An automated cybersecurity bot that monitors the [URLhaus](https://urlhaus.abuse.ch/) malicious URL feed and posts enriched threat-intelligence comments on [VirusTotal](https://www.virustotal.com/) 24/7, without human intervention.

---

## 🔍 What it does

- Polls URLhaus authenticated feed every 60 seconds for newly added malicious URLs
- Prioritises **high-severity threats** (Mirai, Mozi, Emotet, Ransomware, RATs, etc.)
- Posts structured threat-intel comments on VirusTotal for each URL
- Sends **Telegram notifications** on startup, progress, daily limit, and crashes
- Responds to **Telegram commands** (`/status`, `/stats`, `/logs`, `/queue`, `/sysinfo`, `/help`) in real time
- Runs as a `systemd` service and auto-restarts on failure or reboot
- Handles VT rate limits (429) gracefully with max-retry logic
- Graceful shutdown - saves full state before exit

---

## 📸 Sample VirusTotal Comment

```
🚨 Malware URL detected via URLhaus

🔗 URL: hxxp://110[.]37[.]44[.]250:44845/i
📍 Status: online
⚠️  Threat: malware_download
🏷️  Tags: #mirai #mozi #elf #arm
👤 Reporter: zbetcheckin
🔎 URLhaus: https://urlhaus.abuse.ch/url/123456/
```

---

## ⚙️ Architecture

```
URLhaus Feed (every 60s)
        │
        ▼
  Priority Queue
  (HIGH: Mirai, Mozi, Emotet, RATs, Ransomware...)
        │
        ▼
  VirusTotal Comment API
  (max 490 comments/day, 1 per 20s)
        │
        ▼
  Telegram Notifications
  (/status /stats /logs /queue /sysinfo /help)
```

---

## 🚀 Deployment

### Requirements
- Python 3.8+
- `requests` library
- `psutil` library (optional, for `/sysinfo` command)
- VirusTotal API key (free tier works)
- URLhaus Auth-Key (free from [abuse.ch](https://auth.abuse.ch/))
- (Optional) Telegram bot token + chat ID

### 1. Clone the repo
```bash
git clone https://github.com/cyb3rcr4t0712/urlhaus-vt-bot.git
cd urlhaus-vt-bot
```

### 2. Set up Python environment
```bash
python3 -m venv botenv
source botenv/bin/activate
pip install requests psutil
```

### 3. Configure environment variables
```bash
cp .env.example .env
nano .env  # fill in your keys
```

### 4. Run manually
```bash
source botenv/bin/activate
VT_API_KEY=your_key URLHAUS_AUTH_KEY=your_key python urlhaus_vt_bot.py
```

### 5. Deploy as systemd service (recommended)
```bash
cp urlhaus-vt-bot.service.example /etc/systemd/system/urlhaus-vt-bot.service
nano /etc/systemd/system/urlhaus-vt-bot.service  # fill in keys + paths
sudo systemctl daemon-reload
sudo systemctl enable urlhaus-vt-bot
sudo systemctl start urlhaus-vt-bot
```

---

## 📱 Telegram Commands

| Command      | Description                                      |
|--------------|--------------------------------------------------|
| `/status`    | Uptime, daily progress bar, queue sizes          |
| `/stats`     | Full stats + all-time total comments             |
| `/today`     | Today's progress + ETA to daily limit            |
| `/seen`      | Total unique URLs processed                      |
| `/logs`      | Last 20 log lines                                |
| `/errors`    | Recent errors and warnings                       |
| `/queue`     | Current HIGH/NORMAL queue sizes                  |
| `/clearqueue`| Wipe the queue                                   |
| `/sysinfo`   | CPU, RAM, Disk usage (requires psutil)           |
| `/restart`   | Restart the bot remotely                         |
| `/stop`      | Stop the bot remotely                            |
| `/help`      | List all commands                                |

---

## 🗂️ File Structure

```
urlhaus-vt-bot/
├── urlhaus_vt_bot.py               # Main bot
├── urlhaus-vt-bot.service.example  # systemd service template
├── .env.example                    # Environment variable template
├── .gitignore
├── SECURITY.md
└── README.md
```

---

## ⚠️ Disclaimer

This tool is built for **defensive security research only**. It processes malicious URLs from public threat intelligence feeds and posts informational comments on VirusTotal to help the security community.

- Do **not** visit, download from, or interact with any URLs processed by this bot
- Do **not** use this tool to distribute, host, or execute malware
- The author is not responsible for misuse of this software

---

## 🤝 Contributing

PRs welcome. If you use this tool and want to contribute threat-intel coverage improvements, open an issue.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👤 Author

Built with ❤️ for the threat-intel community.