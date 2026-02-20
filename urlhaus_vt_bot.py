#!/usr/bin/env python3
"""
urlhaus_vt_bot.py
-----------------
Monitors URLhaus authenticated feed for newly added malicious URLs and
automatically posts informative comments on VirusTotal for each new URL.

Runs 24/7 without human intervention.

Environment Variables Required:
  VT_API_KEY          - VirusTotal API key
  URLHAUS_AUTH_KEY    - URLhaus Auth-Key from auth.abuse.ch
  TELEGRAM_BOT_TOKEN  - (optional) Telegram bot token
  TELEGRAM_CHAT_ID    - (optional) Telegram chat ID

Telegram Commands:
  /status     - Bot status + daily progress bar
  /stats      - Full summary (uptime, seen, queue, count)
  /today      - Daily comment progress + ETA
  /seen       - Total URLs processed
  /logs       - Last 20 log lines
  /errors     - Recent errors and warnings
  /queue      - Queue sizes
  /clearqueue - Wipe the queue
  /sysinfo    - CPU, RAM, Disk usage
  /restart    - Restart the bot remotely
  /stop       - Stop the bot remotely
  /help       - All commands

Python: 3.8+
Dependencies: requests, psutil (optional)
"""

import base64
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests

try:
    import psutil
except ImportError:
    psutil = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
URLHAUS_FEED_URL        = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
VT_COMMENT_URL          = "https://www.virustotal.com/api/v3/urls/{url_id}/comments"
POLL_INTERVAL_SECONDS   = 60
REQUEST_TIMEOUT_SECONDS = 15
VT_SLEEP_BETWEEN_POSTS  = 20
VT_DAILY_LIMIT          = 490
VT_RATE_LIMIT_SLEEP     = 60
VT_MAX_RETRIES          = 5
SEEN_URLS_FILE          = "seen_urls.json"
QUEUE_FILE              = "queue.json"
LOG_FILE                = "automation.log"
MAX_HIGH_QUEUE          = 2000

HIGH_PRIORITY_TAGS = {
    "mozi", "mirai", "emotet", "cobalt-strike", "asyncrat", "njrat",
    "quasar", "remcos", "backdoor", "ransomware", "stealer", "sshdkit",
    "hajime", "clearfake", "socgholish",
}

# ---------------------------------------------------------------------------
# Shared bot state
# ---------------------------------------------------------------------------
_bot_state: Dict = {
    "daily_count":  0,
    "queue_high":   0,
    "queue_normal": 0,
    "started_at":   "",
    "last_success": "none yet",
    "seen_total":   0,
    "errors_today": 0,
    "total_posted": 0,
}

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "").strip()


def send_telegram(message: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10,
        )
    except Exception as exc:
        log(f"WARNING: Telegram send failed: {exc}")


def _get_last_logs(n: int = 20, filter_str: Optional[str] = None) -> str:
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        if filter_str:
            lines = [l for l in lines if filter_str.lower() in l.lower()]
        last = lines[-n:] if len(lines) >= n else lines
        return "".join(last).strip() or "No matching lines found."
    except Exception:
        return "Could not read log file."


def _uptime_str() -> str:
    started = _bot_state.get("started_at", "")
    if not started:
        return "unknown"
    try:
        start = datetime.strptime(started, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        diff  = datetime.now(timezone.utc) - start
        h, m  = divmod(int(diff.total_seconds()) // 60, 60)
        d, h  = divmod(h, 24)
        parts = []
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        parts.append(f"{m}m")
        return " ".join(parts)
    except Exception:
        return started


def _handle_telegram_commands(shutdown) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    offset = 0
    while not shutdown.shutdown_requested:
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                params={"offset": offset, "timeout": 30},
                timeout=35,
            )
            updates = r.json().get("result", [])
            for update in updates:
                offset  = update["update_id"] + 1
                msg     = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id", ""))
                text    = msg.get("text", "").strip().lower()

                if chat_id != TELEGRAM_CHAT_ID:
                    continue

                s = _bot_state

                if text == "/status":
                    pct = int((s["daily_count"] / VT_DAILY_LIMIT) * 100)
                    bar = "\u2588" * (pct // 10) + "\u2591" * (10 - pct // 10)
                    send_telegram(
                        f"<b>\U0001f916 Bot Status</b>\n"
                        f"Uptime: {_uptime_str()}\n"
                        f"Started: {s['started_at']}\n\n"
                        f"<b>Today's Progress:</b>\n"
                        f"{bar} {pct}%\n"
                        f"Comments: {s['daily_count']}/{VT_DAILY_LIMIT}\n\n"
                        f"<b>Queue:</b>\n"
                        f"HIGH: {s['queue_high']}\n"
                        f"NORMAL: {s['queue_normal']}\n\n"
                        f"Last success:\n<code>{s['last_success']}</code>"
                    )

                elif text == "/stats":
                    send_telegram(
                        f"<b>\U0001f4ca Full Stats</b>\n\n"
                        f"\u23f1 Uptime: {_uptime_str()}\n"
                        f"\U0001f517 Seen URLs total: {s['seen_total']:,}\n"
                        f"\U0001f4ac Comments today: {s['daily_count']}/{VT_DAILY_LIMIT}\n"
                        f"\U0001f4ac Comments all-time: {s['total_posted']:,}\n"
                        f"\u274c Errors today: {s['errors_today']}\n"
                        f"\U0001f4e5 Queue HIGH: {s['queue_high']}\n"
                        f"\U0001f4e5 Queue NORMAL: {s['queue_normal']}\n"
                        f"\U0001f550 Started: {s['started_at']}"
                    )

                elif text == "/today":
                    remaining = VT_DAILY_LIMIT - s["daily_count"]
                    eta_mins  = remaining * (VT_SLEEP_BETWEEN_POSTS / 60)
                    send_telegram(
                        f"<b>\U0001f4c5 Today's Progress</b>\n\n"
                        f"\u2705 Posted: {s['daily_count']}/{VT_DAILY_LIMIT}\n"
                        f"\u23f3 Remaining: {remaining}\n"
                        f"\u23f1 ETA to finish: ~{int(eta_mins)} min\n"
                        f"\U0001f4e5 In queue: {s['queue_high']} URLs"
                    )

                elif text == "/seen":
                    send_telegram(
                        f"<b>\U0001f50d URLs Seen</b>\n\n"
                        f"Total unique URLs processed: <b>{s['seen_total']:,}</b>\n"
                        f"(stored in seen_urls.json)"
                    )

                elif text == "/logs":
                    last_logs = _get_last_logs(20)
                    send_telegram(
                        f"<b>\U0001f4cb Last 20 log lines:</b>\n"
                        f"<pre>{last_logs[-3500:]}</pre>"
                    )

                elif text == "/errors":
                    err_logs  = _get_last_logs(20, filter_str="error")
                    warn_logs = _get_last_logs(20, filter_str="warning")
                    combined  = (err_logs + "\n" + warn_logs).strip()
                    send_telegram(
                        f"<b>\u26a0\ufe0f Recent Errors/Warnings:</b>\n"
                        f"<pre>{combined[-3500:]}</pre>"
                    )

                elif text == "/queue":
                    send_telegram(
                        f"<b>\U0001f4e5 Queue Sizes</b>\n\n"
                        f"HIGH priority: {s['queue_high']}\n"
                        f"NORMAL priority: {s['queue_normal']}"
                    )

                elif text == "/clearqueue":
                    try:
                        empty = {"high": [], "normal": []}
                        with open(QUEUE_FILE, "w", encoding="utf-8") as fh:
                            json.dump(empty, fh)
                        _bot_state["queue_high"]   = 0
                        _bot_state["queue_normal"] = 0
                        send_telegram("\u2705 Queue cleared! Bot will refill on next poll.")
                        log("INFO: Queue cleared via Telegram command.")
                    except Exception as exc:
                        send_telegram(f"\u274c Failed to clear queue: {exc}")

                elif text == "/sysinfo":
                    if psutil:
                        cpu  = psutil.cpu_percent(interval=1)
                        ram  = psutil.virtual_memory()
                        disk = psutil.disk_usage("/")
                        send_telegram(
                            f"<b>\U0001f5a5 System Info</b>\n\n"
                            f"CPU: {cpu}%\n"
                            f"RAM: {ram.used // (1024**2)}MB / {ram.total // (1024**2)}MB ({ram.percent}%)\n"
                            f"Disk: {disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB ({disk.percent}%)"
                        )
                    else:
                        send_telegram(
                            "\u26a0\ufe0f psutil not installed.\n"
                            "Run on VM: <code>source /home/demo/botenv/bin/activate && pip install psutil</code>"
                        )

                elif text == "/restart":
                    send_telegram("\U0001f504 Restarting bot... you'll get a startup message shortly.")
                    log("INFO: Restart requested via Telegram.")
                    try:
                        subprocess.Popen(["sudo", "systemctl", "restart", "urlhaus-vt-bot"])
                    except Exception as exc:
                        send_telegram(f"\u274c Restart failed: {exc}")

                elif text == "/stop":
                    send_telegram("\u23f9 Stopping bot via Telegram command...")
                    log("INFO: Stop requested via Telegram.")
                    shutdown.shutdown_requested = True

                elif text == "/help":
                    send_telegram(
                        "<b>\U0001f916 Available Commands</b>\n\n"
                        "/status     - Status + daily progress bar\n"
                        "/stats      - Full stats summary\n"
                        "/today      - Today's progress + ETA\n"
                        "/seen       - Total URLs processed\n"
                        "/logs       - Last 20 log lines\n"
                        "/errors     - Recent errors and warnings\n"
                        "/queue      - Queue sizes\n"
                        "/clearqueue - Wipe the queue\n"
                        "/sysinfo    - CPU, RAM, Disk usage\n"
                        "/restart    - Restart the bot remotely\n"
                        "/stop       - Stop the bot remotely\n"
                        "/help       - This message"
                    )

        except Exception as exc:
            log(f"WARNING: Telegram polling error: {exc}")
            time.sleep(5)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log(message: str) -> None:
    now_utc   = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%H:%M:%S")
    full_line = f"[{timestamp} UTC] {message}"
    print(full_line, flush=True)
    if "ERROR" in message or "WARNING" in message:
        _bot_state["errors_today"] = _bot_state.get("errors_today", 0) + 1
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(full_line + "\n")
    except OSError as exc:
        print(f"[LOG FILE ERROR] {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Persistent State
# ---------------------------------------------------------------------------
def load_seen_urls() -> List[str]:
    if not os.path.exists(SEEN_URLS_FILE):
        return []
    try:
        with open(SEEN_URLS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as exc:
        log(f"WARNING: Could not load {SEEN_URLS_FILE}: {exc} - starting fresh.")
        return []


def save_seen_urls(seen_urls: List[str]) -> None:
    tmp = SEEN_URLS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(seen_urls, fh, indent=2)
        os.replace(tmp, SEEN_URLS_FILE)
    except OSError as exc:
        log(f"ERROR: Could not save {SEEN_URLS_FILE}: {exc}")


def load_queue() -> Dict[str, List[dict]]:
    empty: Dict[str, List[dict]] = {"high": [], "normal": []}
    if not os.path.exists(QUEUE_FILE):
        return empty
    try:
        with open(QUEUE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("high"), list):
            return data
        return empty
    except (json.JSONDecodeError, OSError) as exc:
        log(f"WARNING: Could not load {QUEUE_FILE}: {exc} - starting fresh.")
        return empty


def save_queue(queue: Dict[str, List[dict]]) -> None:
    tmp = QUEUE_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(queue, fh, indent=2)
        os.replace(tmp, QUEUE_FILE)
    except OSError as exc:
        log(f"ERROR: Could not save {QUEUE_FILE}: {exc}")


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------
def fetch_urlhaus_feed(auth_key: str) -> Optional[List[dict]]:
    try:
        r = requests.get(
            URLHAUS_FEED_URL,
            headers={"Auth-Key": auth_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        return r.json().get("urls", [])
    except requests.exceptions.Timeout:
        log("ERROR: URLhaus fetch timed out.")
        return None
    except requests.exceptions.HTTPError as exc:
        log(f"ERROR: URLhaus HTTP error: {exc.response.status_code}")
        return None
    except requests.exceptions.RequestException as exc:
        log(f"ERROR: URLhaus network error: {exc}")
        return None


def poll_urlhaus(auth_key: str, seen_urls: List[str],
                 queue: Dict[str, List[dict]]) -> Tuple[int, int]:
    entries = fetch_urlhaus_feed(auth_key)
    if entries is None:
        return 0, 0

    total, new_count = len(entries), 0
    seen_set = set(seen_urls)

    for e in entries:
        url = e.get("url", "").strip()
        if not url or not url.startswith("http") or url in seen_set:
            continue

        tags   = e.get("tags") or []
        status = e.get("url_status", "unknown")

        if status.lower() != "online":
            continue

        entry_tags_lower = {t.lower() for t in tags}
        if not (entry_tags_lower & HIGH_PRIORITY_TAGS):
            continue

        if len(queue["high"]) >= MAX_HIGH_QUEUE:
            continue

        entry = {
            "url":               url,
            "url_status":        status,
            "threat":            e.get("threat", "unknown"),
            "tags":              tags,
            "urlhaus_reference": e.get("urlhaus_reference", ""),
            "reporter":          e.get("reporter", "unknown"),
        }
        queue["high"].append(entry)
        seen_set.add(url)
        seen_urls.append(url)
        new_count += 1
        log(f"QUEUED [HIGH]: {url} | threat={entry['threat']} | tags={tags}")

    return total, new_count


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------
def build_vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def build_comment_text(entry: dict) -> str:
    defanged = entry["url"].replace("http", "hxxp").replace(".", "[.]")
    tags_str = " ".join(f"#{t}" for t in entry["tags"]) if entry["tags"] else "none"
    return (
        f"\U0001f6a8 Malware URL detected via URLhaus\n\n"
        f"\U0001f517 URL: {defanged}\n"
        f"\U0001f4cd Status: {entry['url_status']}\n"
        f"\u26a0\ufe0f  Threat: {entry['threat']}\n"
        f"\U0001f3f7\ufe0f  Tags: {tags_str}\n"
        f"\U0001f464 Reporter: {entry['reporter']}\n"
        f"\U0001f50e URLhaus: {entry['urlhaus_reference']}"
    )


def post_vt_comment(url: str, comment_text: str, vt_api_key: str) -> Tuple[bool, bool]:
    url_id = build_vt_url_id(url)
    try:
        r = requests.post(
            VT_COMMENT_URL.format(url_id=url_id),
            headers={"x-apikey": vt_api_key, "content-type": "application/json"},
            json={"data": {"type": "comment", "attributes": {"text": comment_text}}},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.Timeout:
        log(f"ERROR: VT timed out for: {url}")
        return False, False
    except requests.exceptions.RequestException as exc:
        log(f"ERROR: VT network error for {url}: {exc}")
        return False, False

    if r.status_code == 200:   return True, False
    elif r.status_code == 429: return False, True
    else:
        log(f"ERROR: VT HTTP {r.status_code} for: {url}")
        return False, False


def is_new_utc_day(last_reset_day: int) -> bool:
    return datetime.now(timezone.utc).timetuple().tm_yday != last_reset_day


def interruptible_sleep(seconds: float, shutdown) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end and not shutdown.shutdown_requested:
        time.sleep(0.5)


def process_queue(queue: Dict[str, List[dict]], vt_api_key: str,
                  daily_count: int, last_reset_day: int,
                  shutdown) -> Tuple[int, int]:
    for priority in ("high", "normal"):
        while queue[priority] and not shutdown.shutdown_requested:
            if is_new_utc_day(last_reset_day):
                last_reset_day             = datetime.now(timezone.utc).timetuple().tm_yday
                daily_count                = 0
                _bot_state["daily_count"]  = 0
                _bot_state["errors_today"] = 0
                log("INFO: Daily counter reset (new UTC day).")

            if daily_count >= VT_DAILY_LIMIT:
                msg = f"\U0001f6d1 Daily limit ({VT_DAILY_LIMIT}) reached. Resuming tomorrow UTC."
                log(f"INFO: {msg}")
                send_telegram(msg)
                return daily_count, last_reset_day

            entry        = queue[priority].pop(0)
            save_queue(queue)
            url          = entry["url"]
            comment_text = build_comment_text(entry)
            success, rate_limited = post_vt_comment(url, comment_text, vt_api_key)

            if success:
                daily_count                += 1
                _bot_state["total_posted"] += 1
                _bot_state["daily_count"]   = daily_count
                _bot_state["queue_high"]    = len(queue["high"])
                _bot_state["queue_normal"]  = len(queue["normal"])
                _bot_state["last_success"]  = f"{url[:60]}... ({daily_count}/{VT_DAILY_LIMIT})"
                log(f"SUCCESS: Comment posted for {url} (daily count: {daily_count}/{VT_DAILY_LIMIT})")
                if daily_count % 25 == 0:
                    send_telegram(
                        f"\U0001f4ca <b>Progress:</b> {daily_count}/{VT_DAILY_LIMIT} today\n"
                        f"Queue HIGH: {len(queue['high'])}"
                    )
                interruptible_sleep(VT_SLEEP_BETWEEN_POSTS, shutdown)

            elif rate_limited:
                entry["_retries"] = entry.get("_retries", 0) + 1
                if entry["_retries"] > VT_MAX_RETRIES:
                    log(f"SKIP: Dropping {url} after {VT_MAX_RETRIES} rate-limit retries.")
                else:
                    log(f"RATE LIMITED (429): Re-queuing {url} (retry {entry['_retries']}/{VT_MAX_RETRIES}). Sleeping {VT_RATE_LIMIT_SLEEP}s.")
                    queue[priority].insert(0, entry)
                    save_queue(queue)
                    interruptible_sleep(VT_RATE_LIMIT_SLEEP, shutdown)
            else:
                log(f"SKIP: Dropping {url} after non-retryable VT error.")

    return daily_count, last_reset_day


# ---------------------------------------------------------------------------
# Graceful Shutdown
# ---------------------------------------------------------------------------
class GracefulShutdown:
    def __init__(self) -> None:
        self.shutdown_requested = False
        signal.signal(signal.SIGINT,  self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum: int, frame) -> None:
        name = "SIGINT (Ctrl+C)" if signum == signal.SIGINT else "SIGTERM"
        log(f"INFO: {name} received - requesting graceful shutdown.")
        self.shutdown_requested = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    log("=" * 60)
    log("URLhaus to VirusTotal Bot Starting")
    log("=" * 60)

    vt_api_key       = os.environ.get("VT_API_KEY", "").strip()
    urlhaus_auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()

    if not vt_api_key:
        log("FATAL: VT_API_KEY not set. Exiting.")
        sys.exit(1)
    if not urlhaus_auth_key:
        log("FATAL: URLHAUS_AUTH_KEY not set. Exiting.")
        sys.exit(1)

    log("INFO: Credentials loaded.")
    telegram_enabled = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    if telegram_enabled:
        log("INFO: Telegram notifications + commands enabled.")

    seen_urls = load_seen_urls()
    queue     = load_queue()
    log(f"INFO: Loaded {len(seen_urls)} seen URLs.")
    log(f"INFO: Queue - HIGH: {len(queue['high'])}, NORMAL: {len(queue['normal'])}.")

    daily_count    = 0
    last_reset_day = datetime.now(timezone.utc).timetuple().tm_yday
    started_at     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    shutdown       = GracefulShutdown()

    _bot_state["started_at"]   = started_at
    _bot_state["seen_total"]   = len(seen_urls)
    _bot_state["queue_high"]   = len(queue["high"])
    _bot_state["queue_normal"] = len(queue["normal"])

    if telegram_enabled:
        t = threading.Thread(
            target=_handle_telegram_commands,
            args=(shutdown,),
            daemon=True,
        )
        t.start()
        send_telegram(
            f"\u2705 <b>URLhaus-VT Bot started</b>\n"
            f"Time: {started_at}\n"
            f"Seen URLs: {len(seen_urls):,}\n"
            f"Queue HIGH: {len(queue['high'])}\n\n"
            f"Commands: /status /stats /today /seen\n"
            f"/logs /errors /queue /sysinfo /restart /stop /help"
        )

    log(f"INFO: Entering main loop (poll every {POLL_INTERVAL_SECONDS}s).")

    try:
        while not shutdown.shutdown_requested:
            cycle_start = time.monotonic()

            log("INFO: Polling URLhaus feed...")
            total, new_count = poll_urlhaus(urlhaus_auth_key, seen_urls, queue)
            log(f"INFO: Poll complete - fetched {total}, {new_count} new.")
            log(f"INFO: Queue - HIGH: {len(queue['high'])}, NORMAL: {len(queue['normal'])}.")

            _bot_state["seen_total"]   = len(seen_urls)
            _bot_state["queue_high"]   = len(queue["high"])
            _bot_state["queue_normal"] = len(queue["normal"])

            save_seen_urls(seen_urls)
            save_queue(queue)

            if is_new_utc_day(last_reset_day):
                last_reset_day             = datetime.now(timezone.utc).timetuple().tm_yday
                daily_count                = 0
                _bot_state["daily_count"]  = 0
                _bot_state["errors_today"] = 0
                log("INFO: Daily counter reset (new UTC day).")

            if daily_count < VT_DAILY_LIMIT and (queue["high"] or queue["normal"]):
                log("INFO: Processing queue...")
                daily_count, last_reset_day = process_queue(
                    queue, vt_api_key, daily_count, last_reset_day, shutdown
                )
            elif daily_count >= VT_DAILY_LIMIT:
                log("INFO: Daily limit reached. Skipping.")

            elapsed = time.monotonic() - cycle_start
            sleep_t = max(0.0, POLL_INTERVAL_SECONDS - elapsed)
            if not shutdown.shutdown_requested:
                log(f"INFO: Cycle done in {elapsed:.1f}s. Sleeping {sleep_t:.1f}s.")
                interruptible_sleep(sleep_t, shutdown)

    except Exception as exc:
        send_telegram(f"\U0001f6a8 <b>Bot crashed!</b>\n<code>{exc}</code>")
        raise

    log("INFO: Shutdown - saving state...")
    save_seen_urls(seen_urls)
    save_queue(queue)
    send_telegram(
        f"\u23f9 <b>Bot stopped cleanly.</b>\n"
        f"Comments today: {daily_count}/{VT_DAILY_LIMIT}\n"
        f"Total all-time: {_bot_state['total_posted']:,}"
    )
    log("INFO: URLhaus to VirusTotal Bot stopped. Goodbye.")


if __name__ == "__main__":
    main()
