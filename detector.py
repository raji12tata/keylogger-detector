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

# Setup logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logfile = os.path.join(LOG_DIR, f"detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    filename=logfile,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("").addHandler(console)

# Load configuration
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

SUSPICIOUS_LIST_PATH = os.path.join(os.path.dirname(__file__), "suspicious_list.txt")
WHITELIST_PATH = os.path.join(os.path.dirname(__file__), "whitelist.txt")

inspector = Inspector(suspicious_list_path=SUSPICIOUS_LIST_PATH, whitelist_path=WHITELIST_PATH)

def scan_processes():
    print(Fore.CYAN + "[*] Scanning running processes..." + Style.RESET_ALL)
    logging.info("Starting process scan")
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
                logging.warning(f"Suspicious: {detection}")
                notify_console(detection)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not detections:
        print(Fore.GREEN + "[✓] No suspicious processes detected." + Style.RESET_ALL)
        logging.info("No suspicious processes detected.")
    return detections

def run_full_scan():
    logging.info("Running full scan")
    print(Fore.MAGENTA + "=== Keylogger Detector: Full Scan ===" + Style.RESET_ALL)
    # 1. Processes
    proc_detections = scan_processes()

    # 2. Optionally inspect autostart (Windows registry) and scheduled tasks
    if CONFIG.get("inspect_autostart", False):
        try:
            ats = inspector.inspect_autostart()
            if ats:
                for item in ats:
                    logging.warning(f"Autostart suspicion: {item}")
                    notify_console(item)
        except Exception as e:
            logging.exception("Autostart inspection failed")

    if CONFIG.get("inspect_scheduled_tasks", False):
        try:
            st = inspector.inspect_scheduled_tasks()
            if st:
                for item in st:
                    logging.warning(f"Scheduled task suspicion: {item}")
                    notify_console(item)
        except Exception as e:
            logging.exception("Scheduled task inspection failed")

    # 3. Optionally deep inspect suspicious executables (hashing, size check)
    if CONFIG.get("deep_inspect", False):
        for d in proc_detections:
            exe = d.get("exe")
            if exe and os.path.exists(exe):
                try:
                    deep = inspector.deep_inspect_exe(exe)
                    if deep:
                        logging.warning(f"Deep inspect result for {exe}: {deep}")
                        notify_console({"exe": exe, "reason": deep})
                except Exception:
                    logging.exception("Deep inspect failed for %s", exe)

    print(Fore.MAGENTA + "=== Scan Complete ===" + Style.RESET_ALL)
    logging.info("Scan complete")

if __name__ == "__main__":
    print("Keylogger Detector - Starting")
    run_full_scan()
