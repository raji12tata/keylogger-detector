"""
inspector.py
Contains logic to inspect processes, autostart entries and do deeper checks.
"""

import os
import hashlib
import subprocess
import logging

class Inspector:
    def __init__(self, suspicious_list_path: str, whitelist_path: str):
        self.suspicious_names = self._load_list(suspicious_list_path)
        self.whitelist = self._load_list(whitelist_path)
        logging.info(f"Loaded {len(self.suspicious_names)} suspicious signatures and {len(self.whitelist)} whitelist entries")

    def _load_list(self, path):
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

    def inspect_process(self, name: str, exe_path: str):
        """
        Inspect a single process by name and exe path.
        Returns reason string if suspicious, otherwise None.
        """
        name_l = name.lower()
        exe_l = (exe_path or "").lower()

        # Whitelist check
        for w in self.whitelist:
            if w in name_l or w in exe_l:
                return None

        # Name-based suspicious
        for s in self.suspicious_names:
            if s in name_l:
                return f"name_match:{s}"

        # Path-based heuristics (suspicious if running from Temp or AppData\Local\Temp)
        if "\\temp\\" in exe_l or "\\appdata\\local\\temp\\" in exe_l:
            return "exe_in_temp_folder"

        # Suspicious if run from user download paths
        if "\\downloads\\" in exe_l:
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
        except Exception as e:
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
        Inspect Windows autostart registry keys (HKCU\...\Run and HKLM\...\Run).
        Requires 'reg' command (available on Windows).
        Returns list of suspicious autostart entries.
        """
        suspects = []
        try:
            # Query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
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
                            if s in name.lower() or s in p:
                                small_reason = f"autostart_name_or_path_match:{s}"
                                break
                        if "\\temp\\" in p or "\\downloads\\" in p:
                            small_reason = "autostart_exe_in_temp_or_downloads"
                        if small_reason:
                            suspects.append({"name": name, "path": path, "reason": small_reason})
        except Exception:
            logging.exception("inspect_autostart failed")
        return suspects

    def inspect_scheduled_tasks(self):
        """
        Use schtasks to list scheduled tasks and look for suspicious names/paths.
        """
        suspects = []
        try:
            out = subprocess.run(["schtasks", "/Query", "/FO", "LIST", "/V"], capture_output=True, text=True)
            if out.returncode != 0:
                return suspects
            block = {}
            for line in out.stdout.splitlines():
                if not line.strip():
                    if block:
                        # parse block
                        taskname = block.get('TaskName', '').lower()
                        taskrun = block.get('Task To Run', '').lower() or block.get('Task To Run:', '').lower()
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
            logging.exception("inspect_scheduled_tasks failed")
        return suspects
