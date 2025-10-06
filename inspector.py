
#inspector.py

import os
import hashlib
import subprocess
import logging
import re
import platform

class Inspector:
    def __init__(self, suspicious_list_path: str, whitelist_path: str):
        self.suspicious_names = self._load_list(suspicious_list_path)
        self.whitelist = self._load_list(whitelist_path)
        logging.info(f"Loaded {len(self.suspicious_names)} suspicious signatures and {len(self.whitelist)} whitelist entries")

        self.platform = platform.system().lower()
        logging.info(f"Platform detected: {self.platform}")

    def _load_list(self, path):
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

    def name_matches_signature(self, name: str, signature: str) -> bool:
        if not name:
            return False
        # token / word-boundary match
        if re.search(rf'\b{re.escape(signature)}\b', name, flags=re.IGNORECASE):
            return True
        # basename match
        try:
            base = os.path.basename(name)
            if signature.lower() == base.lower() or signature.lower() in base.lower():
                return True
        except Exception:
            pass
        return False

    def inspect_process(self, name: str, exe_path: str):
        """
        Inspect a single process by name and exe path.
        Returns reason string if suspicious, otherwise None.
        """
        name_l = name.lower()
        exe_l = (exe_path or "").lower()

        # Whitelist check
        for w in self.whitelist:
            if self.name_matches_signature(name_l, w) or self.name_matches_signature(exe_l, w):
                return None

        # Name-based suspicious
        for s in self.suspicious_names:
            if self.name_matches_signature(name_l, s):
                return f"name_match:{s}"

        # Path-based heuristics
        if "\\temp\\" in exe_l or "\\appdata\\local\\temp\\" in exe_l or "/tmp/" in exe_l:
            return "exe_in_temp_folder"

        # Suspicious if run from downloads
        if "\\downloads\\" in exe_l or "/home" in exe_l and "/downloads" in exe_l:
            return "exe_in_downloads"

        return None

    def deep_inspect_exe(self, exe_path: str):
        """Compute sha256 and check size heuristics."""
        if not exe_path or not os.path.exists(exe_path):
            return None
        try:
            h = self.sha256(exe_path)
            size = os.path.getsize(exe_path)
            return {"sha256": h, "size_bytes": size}
        except Exception:
            logging.exception("deep_inspect_exe failed")
            return None

    def sha256(self, path, block_size=65536):
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                sha.update(block)
        return sha.hexdigest()

    def inspect_autostart(self):
        """
        Inspect autostart entries (Windows registry or Linux ~/.config/autostart).
        Returns list of suspicious autostart entries.
        """
        suspects = []

        if self.platform == "windows":
            try:
                keys = [
                    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
                ]
                for key in keys:
                    out = subprocess.run(["reg", "query", key], capture_output=True, text=True)
                    if out.returncode != 0:
                        continue
                    for line in out.stdout.splitlines():
                        if "REG_SZ" in line:
                            parts = line.split("    ")
                            name = parts[0].strip() if parts else ""
                            path = parts[-1].strip() if parts else ""
                            small_reason = None
                            p = path.lower()
                            for s in self.suspicious_names:
                                if self.name_matches_signature(name, s) or self.name_matches_signature(p, s):
                                    small_reason = f"autostart_name_or_path_match:{s}"
                                    break
                            if "\\temp\\" in p or "\\downloads\\" in p:
                                small_reason = "autostart_exe_in_temp_or_downloads"
                            if small_reason:
                                suspects.append({"name": name, "path": path, "reason": small_reason})
            except Exception:
                logging.exception("inspect_autostart failed")

        elif self.platform in ["linux", "darwin"]:
            # check ~/.config/autostart
            home = os.path.expanduser("~")
            autostart_dir = os.path.join(home, ".config", "autostart")
            if os.path.exists(autostart_dir):
                for f in os.listdir(autostart_dir):
                    path = os.path.join(autostart_dir, f)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as file:
                            content = file.read().lower()
                            for s in self.suspicious_names:
                                if self.name_matches_signature(content, s):
                                    suspects.append({"name": f, "path": path, "reason": f"autostart_file_content_match:{s}"})
                    except Exception:
                        logging.debug("Failed to read autostart file: %s", path)

        return suspects

    def inspect_scheduled_tasks(self):
        """
        Inspect scheduled tasks (Windows Task Scheduler or Linux cron files).
        Returns list of suspicious scheduled tasks.
        """
        suspects = []

        if self.platform == "windows":
            try:
                out = subprocess.run(["schtasks", "/Query", "/FO", "LIST", "/V"], capture_output=True, text=True)
                if out.returncode != 0:
                    return suspects
                block = {}
                for line in out.stdout.splitlines():
                    if not line.strip():
                        if block:
                            taskname = block.get('TaskName', '').lower()
                            taskrun = block.get('Task To Run', '').lower() or block.get('Task To Run:', '').lower()
                            for s in self.suspicious_names:
                                if self.name_matches_signature(taskname, s) or self.name_matches_signature(taskrun, s):
                                    suspects.append({"task": block.get('TaskName'), "run": block.get('Task To Run'), "reason": f"task_match:{s}"})
                                    break
                            block = {}
                    else:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            block[k.strip()] = v.strip()
            except Exception:
                logging.exception("inspect_scheduled_tasks failed")

        elif self.platform in ["linux", "darwin"]:
            cron_dirs = ["/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.hourly", "/etc/cron.d", "/var/spool/cron/crontabs"]
            for dirpath in cron_dirs:
                if not os.path.exists(dirpath):
                    continue
                if os.path.isfile(dirpath):
                    files = [dirpath]
                else:
                    try:
                        files = [os.path.join(dirpath, f) for f in os.listdir(dirpath)]
                    except PermissionError:
                        logging.debug("Skipping unreadable cron dir: %s", dirpath)
                        continue
                for path in files:
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            for s in self.suspicious_names:
                                if self.name_matches_signature(content, s):
                                    suspects.append({"source": "cronfile", "path": path, "reason": f"cronfile_match:{s}"})
                    except PermissionError:
                        logging.debug("Skipping unreadable cron file: %s", path)
                        continue
                    except Exception:
                        logging.exception("Failed reading cron file %s", path)

        return suspects