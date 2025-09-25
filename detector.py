"""
detector.py
Main entry point for Keylogger Detector (Windows).
Scans processes, autostart entries, scheduled tasks and optionally inspects suspicious EXE files.
Educational use only.
"""

import os
import time
import logging
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
import psutil
import yaml

from inspector import Inspector
from notifier import notify_console

colorama_init(autoreset=True)

# -----------------------------
# Setup logs folder
# -----------------------------
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logfile = os.path.join(LOG_DIR, f"detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configure logging
logging.basicConfig(
    filename=logfile,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("").addHandler(console)

# -----------------------------
# Load configuration
# -----------------------------
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

SUSPICIOUS_LIST_PATH = os.path.join(os.path.dirname(__file__), "suspicious_list.txt")
WHITELIST_PATH = os.path.join(os.path.dirname(__file__), "whitelist.txt")

inspector = Inspector(suspicious_list_path=SUSPICIOUS_LIST_PATH, whitelist_path=WHITELIST_PATH)

# -----------------------------
# Logging helper
# -----------------------------
def write_log(message, level="info"):
    """
    Log message to both console and log file
    level: 'info' or 'warning'
    """
    if level == "warning":
        logging.warning(message)
    else:
        logging.info(message)
    print(message)  # keep console output

# -----------------------------
# Scan running processes
# -----------------------------
def scan_processes():
    write_log(Fore.CYAN + "[*] Scanning running processes..." + Style.RESET_ALL)
    write_log("Starting process scan")
    detections = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            pid = proc.info['pid']
            name = (proc.info['name'] or "").lower()
            exe = proc.info.get('exe') or ""
            username = proc.info.get('username') or ""

            reason = inspector.inspect_process(name=name, exe_path=exe)
            if reason:
                detection = {
                    "pid": pid, "name": name, "exe": exe, "username": username, "reason": reason
                }
                detections.append(detection)
                write_log(f"[!] Suspicious process detected: {detection}", level="warning")
                notify_console(detection)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not detections:
        write_log(Fore.GREEN + "[✓] No suspicious processes detected." + Style.RESET_ALL)

    return detections

# -----------------------------
# Run full scan
# -----------------------------
def run_full_scan():
    write_log(Fore.MAGENTA + "=== Keylogger Detector: Full Scan ===" + Style.RESET_ALL)
    
    # 1. Processes
    proc_detections = scan_processes()

    # 2. Optional: Inspect autostart entries
    if CONFIG.get("inspect_autostart", False):
        try:
            ats = inspector.inspect_autostart()
            if ats:
                for item in ats:
                    write_log(f"[!] Autostart suspicion: {item}", level="warning")
                    notify_console(item)
        except Exception as e:
            logging.exception("Autostart inspection failed")

    # 3. Optional: Inspect scheduled tasks
    if CONFIG.get("inspect_scheduled_tasks", False):
        try:
            st = inspector.inspect_scheduled_tasks()
            if st:
                for item in st:
                    write_log(f"[!] Scheduled task suspicion: {item}", level="warning")
                    notify_console(item)
        except Exception as e:
            logging.exception("Scheduled task inspection failed")

    # 4. Optional: Deep inspect suspicious EXEs
    if CONFIG.get("deep_inspect", False):
        for d in proc_detections:
            exe = d.get("exe")
            if exe and os.path.exists(exe):
                try:
                    deep = inspector.deep_inspect_exe(exe)
                    if deep:
                        write_log(f"[!] Deep inspect result for {exe}: {deep}", level="warning")
                        notify_console({"exe": exe, "reason": deep})
                except Exception:
                    logging.exception(f"Deep inspect failed for {exe}")

    write_log(Fore.MAGENTA + "=== Scan Complete ===" + Style.RESET_ALL)
    write_log("Scan complete")

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    write_log("Keylogger Detector - Starting")
    run_full_scan()
