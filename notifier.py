"""
notifier.py
Small wrappers to notify user. For now we use console colors.
Later you can add email or Windows toast notifications.
"""

from colorama import Fore, Style
import logging

def notify_console(detection: dict):
    """
    Print a concise alert to console. detection is a dict:
    { 'pid':..., 'name':..., 'exe':..., 'reason':... } or other shapes.
    """
    try:
        if "pid" in detection:
            # Process detection
            msg = f"[!] Suspicious process: {detection.get('name', 'Unknown')} (PID {detection.get('pid')})"
            if "exe" in detection:
                msg += f" | Path: {detection.get('exe')}"
            msg += f" -> {detection.get('reason', 'Unknown')}"
            color = Fore.RED
        elif "task" in detection:
            # Scheduled task detection
            msg = f"[!] Suspicious task: {detection.get('task', 'Unknown')}"
            if "run" in detection:
                msg += f" | Run: {detection.get('run')}"
            msg += f" -> {detection.get('reason', 'Unknown')}"
            color = Fore.MAGENTA
        elif "source" in detection:
            # Cron/autostart file detection
            msg = f"[!] Suspicious {detection.get('source', 'item')}: {detection.get('path', 'Unknown')}"
            msg += f" -> {detection.get('reason', 'Unknown')}"
            color = Fore.YELLOW
        elif "exe" in detection:
            # Deep inspect or standalone exe
            msg = f"[!] Suspicious exe: {detection.get('exe')} -> {detection.get('reason', 'Unknown')}"
            color = Fore.RED
        else:
            # Generic fallback
            msg = f"[!] Suspicious item: {detection}"
            color = Fore.YELLOW

        print(color + msg + Style.RESET_ALL)
        logging.warning(msg)  # Log for file persistence (no console dupe if logging setup fixed)
    except Exception as e:
        error_msg = "notify_console failed"
        print(Fore.RED + f"[!] {error_msg}: {e}" + Style.RESET_ALL)
        logging.exception(error_msg)