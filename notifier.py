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
            msg = f"[!] Suspicious process: {detection.get('name')} (PID {detection.get('pid')}) -> {detection.get('reason')}"
        elif "exe" in detection:
            msg = f"[!] Suspicious exe: {detection.get('exe')} -> {detection.get('reason')}"
        else:
            msg = f"[!] Suspicious item: {detection}"
        print(Fore.RED + msg + Style.RESET_ALL)
        logging.warning(msg)
    except Exception as e:
        logging.exception("notify_console failed")
