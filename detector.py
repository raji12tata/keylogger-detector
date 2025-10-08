"""
detector.py
Main entry point for Keylogger Detector (Cross-Platform).
Scans processes, autostart entries, scheduled tasks and optionally inspects suspicious EXE files.
Educational use only.
"""

import os
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
import psutil
import yaml

from inspector import Inspector
from notifier import notify_console

colorama_init(autoreset=True)

# -----------------------------
# Setup logs folder and logging
# -----------------------------
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = f"detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logfile = os.path.join(LOG_DIR, log_filename)

# Configure logging: file + single console handler (no dupes)
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(logfile),
        logging.StreamHandler()  # Single console output
    ]
)

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
# Scan running processes
# -----------------------------
def scan_processes():
    print(Fore.CYAN + "[*] Scanning running processes..." + Style.RESET_ALL)
    logging.info("Starting process scan")
    detections = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        try:
            pid = proc.info['pid']
            name = (proc.info['name'] or "").lower()
            exe = proc.info.get('exe') or ""
            cmdline = ' '.join(proc.info.get('cmdline', [])).lower() if proc.info.get('cmdline') else ""
            username = proc.info.get('username') or ""

            reason = inspector.inspect_process(name=name, exe_path=exe, cmdline=cmdline)
            if reason:
                detection = {
                    "pid": pid, "name": name, "exe": exe, "cmdline": cmdline, "username": username, "reason": reason
                }
                detections.append(detection)
                logging.warning(f"Suspicious process: {detection}")
                notify_console(detection)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not detections:
        print(Fore.GREEN + "[✓] No suspicious processes detected." + Style.RESET_ALL)
        logging.info("No suspicious processes detected.")

    return detections

# -----------------------------
# Run full scan
# -----------------------------
def run_full_scan():
    print(Fore.MAGENTA + "=== Keylogger Detector: Full Scan ===" + Style.RESET_ALL)
    logging.info("Running full scan")

    # 1. Processes
    proc_detections = scan_processes()

    # 2. Optional: Inspect autostart entries
    if CONFIG.get("inspect_autostart", False):
        try:
            ats = inspector.inspect_autostart()
            if ats:
                for item in ats:
                    logging.warning(f"Autostart suspicion: {item}")
                    notify_console(item)
        except Exception as e:
            logging.exception("Autostart inspection failed")

    # 3. Optional: Inspect scheduled tasks
    if CONFIG.get("inspect_scheduled_tasks", False):
        try:
            st = inspector.inspect_scheduled_tasks()
            if st:
                for item in st:
                    logging.warning(f"Scheduled task suspicion: {item}")
                    notify_console(item)
        except Exception as e:
            logging.exception("Scheduled task inspection failed")

    # 4. Optional: Deep inspect suspicious EXEs
    if CONFIG.get("deep_inspect", False):
        for d in proc_detections:
            exe = d.get("exe") or d.get("cmdline", "").split()[-1] if d.get("cmdline") else ""
            if exe and os.path.exists(exe):
                try:
                    deep = inspector.deep_inspect_exe(exe)
                    if deep:
                        logging.info(f"Deep inspect result for {exe}: {deep}")
                        notify_console({"exe": exe, "details": deep})
                except Exception:
                    logging.exception(f"Deep inspect failed for {exe}")

    print(Fore.MAGENTA + "=== Scan Complete ===" + Style.RESET_ALL)
    logging.info("Scan complete")

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("Keylogger Detector - Starting")
    logging.info("Keylogger Detector - Starting")
    run_full_scan()
