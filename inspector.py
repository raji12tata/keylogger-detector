# inspector.py
import os
import hashlib
import subprocess
import logging
import sys
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class Inspector:
    def __init__(self, suspicious_list_path: str, whitelist_path: str):
        self.suspicious_names = self._load_list(suspicious_list_path)
        self.whitelist = self._load_list(whitelist_path)
        self.platform = self._detect_platform()
        logger.info(f"Platform detected: {self.platform}")
        logger.info(f"Loaded {len(self.suspicious_names)} suspicious signatures and {len(self.whitelist)} whitelist entries")

    def _detect_platform(self) -> str:
        if sys.platform.startswith("win"):
            return "windows"
        elif sys.platform.startswith("linux"):
            return "linux"
        elif sys.platform.startswith("darwin"):
            return "macos"
        else:
            return "unknown"

    def _load_list(self, path: str) -> List[str]:
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")]

    def inspect_process(self, name: str, exe_path: str = "") -> Optional[str]:
        """
        Inspect a single process by name and exe path.
        Returns a reason string when suspicious, else None.
        """
        name_l = (name or "").lower()
        exe_l = (exe_path or "").lower()

        # Whitelist check
        for w in self.whitelist:
            if w in name_l or w in exe_l:
                return None

        # Name-based suspicious
        for s in self.suspicious_names:
            if s in name_l:
                return f"name_match:{s}"

        # Path heuristics (windows and linux variants)
        if self.platform == "windows":
            if "\\temp\\" in exe_l or "\\appdata\\local\\temp\\" in exe_l:
                return "exe_in_temp_folder"
            if "\\downloads\\" in exe_l:
                return "exe_in_downloads"
        elif self.platform == "linux":
            if "/tmp/" in exe_l or "/var/tmp/" in exe_l:
                return "exe_in_tmp_folder"
            if "/home/" in exe_l and ("/Downloads/" in exe_path or "/downloads/" in exe_path):
                return "exe_in_downloads"

        return None

    def deep_inspect_exe(self, exe_path: str) -> Optional[Dict]:
        """Compute sha256 and size of an exe/binary"""
        if not exe_path or not os.path.exists(exe_path):
            return None
        try:
            h = self.sha256(exe_path)
            size = os.path.getsize(exe_path)
            return {"sha256": h, "size_bytes": size}
        except Exception:
            logger.exception("deep_inspect_exe failed")
            return None

    def sha256(self, path: str, block_size: int = 65536) -> str:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                sha.update(block)
        return sha.hexdigest()

    # -------------------------
    # Autostart inspection
    # -------------------------
    def inspect_autostart(self) -> List[Dict]:
        """
        Inspect autostart entries.
        On Windows: check HKCU/HKLM Run keys (requires reg.exe).
        On Linux: check ~/.config/autostart, /etc/xdg/autostart desktop files.
        Returns list of suspicious autostart entries (dicts).
        """
        suspects = []
        try:
            if self.platform == "windows":
                suspects = self._inspect_autostart_windows()
            elif self.platform == "linux":
                suspects = self._inspect_autostart_linux()
            else:
                logger.info("Autostart inspection not implemented for platform: %s", self.platform)
        except Exception:
            logger.exception("inspect_autostart failed")
        return suspects

    def _inspect_autostart_windows(self) -> List[Dict]:
        suspects = []
        keys = [
            r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        ]
        for key in keys:
            try:
                out = subprocess.run(["reg", "query", key], capture_output=True, text=True)
                if out.returncode != 0:
                    continue
                for line in out.stdout.splitlines():
                    if "REG_SZ" in line:
                        parts = [p for p in line.split("    ") if p.strip()]
                        name = parts[0].strip() if parts else ""
                        path = parts[-1].strip() if parts else ""
                        p = path.lower()
                        small_reason = None
                        for s in self.suspicious_names:
                            if s in name.lower() or s in p:
                                small_reason = f"autostart_name_or_path_match:{s}"
                                break
                        if "\\temp\\" in p or "\\downloads\\" in p:
                            small_reason = "autostart_exe_in_temp_or_downloads"
                        if small_reason:
                            suspects.append({"name": name, "path": path, "reason": small_reason})
            except Exception:
                logger.exception("Windows autostart query failed for %s", key)
        return suspects

    def _inspect_autostart_linux(self) -> List[Dict]:
        suspects = []
        # Common autostart locations for desktop environments
        autostart_dirs = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/xdg/autostart"
        ]
        for d in autostart_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    if not fname.endswith(".desktop"):
                        continue
                    path = os.path.join(d, fname)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            # find Exec= line
                            exec_line = None
                            for line in content.splitlines():
                                if line.strip().startswith("exec="):
                                    exec_line = line.split("=", 1)[1].strip()
                                    break
                            reason = None
                            if exec_line:
                                for s in self.suspicious_names:
                                    if s in exec_line:
                                        reason = f"autostart_exec_match:{s}"
                                        break
                                if "/tmp/" in exec_line or "/downloads/" in exec_line:
                                    reason = "autostart_exec_in_tmp_or_downloads"
                            if reason:
                                suspects.append({"file": path, "exec": exec_line, "reason": reason})
                    except Exception:
                        logger.exception("Failed reading autostart file %s", path)
            except Exception:
                logger.exception("Failed listing autostart dir %s", d)
        return suspects

    # -------------------------
    # Scheduled tasks inspection
    # -------------------------
    def inspect_scheduled_tasks(self) -> List[Dict]:
        """
        Inspect scheduled tasks.
        On Windows: use schtasks.exe.
        On Linux: check crontab and systemd timers.
        """
        suspects = []
        try:
            if self.platform == "windows":
                suspects = self._inspect_schtasks_windows()
            elif self.platform == "linux":
                suspects = self._inspect_scheduled_linux()
            else:
                logger.info("Scheduled tasks inspection not implemented for platform: %s", self.platform)
        except Exception:
            logger.exception("inspect_scheduled_tasks failed")
        return suspects

    def _inspect_schtasks_windows(self) -> List[Dict]:
        suspects = []
        try:
            out = subprocess.run(["schtasks", "/Query", "/FO", "LIST", "/V"], capture_output=True, text=True)
            if out.returncode != 0:
                return suspects
            block = {}
            for line in out.stdout.splitlines():
                if not line.strip():
                    if block:
                        taskname = block.get('TaskName', '').lower()
                        taskrun = (block.get('Task To Run') or block.get('Task To Run:') or "").lower()
                        for s in self.suspicious_names:
                            if s in taskname or s in taskrun:
                                suspects.append({"task": block.get('TaskName'), "run": block.get('Task To Run'), "reason": f"task_match:{s}"})
                                break
                        block = {}
                else:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        block[k.strip()] = v.strip()
        except Exception:
            logger.exception("Windows scheduled tasks check failed")
        return suspects

    def _inspect_scheduled_linux(self) -> List[Dict]:
        suspects = []
        # 1) crontab for current user
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if out.returncode == 0 and out.stdout:
                for line in out.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    lower = line.lower()
                    for s in self.suspicious_names:
                        if s in lower:
                            suspects.append({"source": "crontab", "entry": line, "reason": f"cron_match:{s}"})
                            break
        except FileNotFoundError:
            # crontab command might not exist in minimal containers
            logger.debug("crontab not found")
        except Exception:
            logger.exception("crontab inspection failed")

        # 2) systemd timers (if systemctl exists)
        try:
            out = subprocess.run(["systemctl", "list-timers", "--all", "--no-legend"], capture_output=True, text=True)
            if out.returncode == 0 and out.stdout:
                for line in out.stdout.splitlines():
                    # line example: "Mon 2025-09-25 17:00:00 UTC  1h 1min left  some-timer.timer  some-timer.service"
                    lower = line.lower()
                    for s in self.suspicious_names:
                        if s in lower:
                            suspects.append({"source": "systemd-timer", "entry": line.strip(), "reason": f"timer_match:{s}"})
                            break
        except FileNotFoundError:
            logger.debug("systemctl not present")
        except Exception:
            logger.exception("systemd timer inspection failed")

        # 3) /etc/cron.* and /var/spool/cron
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"]
        for d in cron_dirs:
            try:
                if not os.path.isdir(d):
                    continue
                for fname in os.listdir(d):
                    path = os.path.join(d, fname)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                        for s in self.suspicious_names:
                            if s in content:
                                suspects.append({"source": "cronfile", "path": path, "reason": f"cronfile_match:{s}"})
                                break
                    except Exception:
                        logger.exception("Failed reading cron file %s", path)
            except Exception:
                logger.exception("Failed listing cron dir %s", d)

        return suspects
