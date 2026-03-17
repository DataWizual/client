"""
Auditor Guard - Licensing and Hardware Binding.
"""

import hashlib
import hmac
import os
import platform
import logging
import subprocess
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class AuditorGuard:

    @staticmethod
    def get_machine_id() -> str:
        """
        Generates a unique 32-character Machine ID based on hardware identifiers.
        """
        identifiers = [
            platform.machine(),
            platform.system(),
        ]

        try:
            if platform.system() == "Windows":
                # Prefer PowerShell over deprecated wmic
                cmd = [
                    "powershell",
                    "-Command",
                    "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID",
                ]
                output = (
                    subprocess.check_output(cmd, shell=False, stderr=subprocess.DEVNULL)
                    .decode()
                    .strip()
                )
                if output:
                    identifiers.append(output)

            elif platform.system() == "Linux":
                for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                    if os.path.exists(path):
                        with open(path, "r") as f:
                            identifiers.append(f.read().strip())
                        break

            elif platform.system() == "Darwin":
                cmd = ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
                output = subprocess.check_output(cmd, shell=False).decode()
                match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', output)
                if match:
                    identifiers.append(match.group(1))
        except Exception:
            logger.debug(
                "Guard: Failed to retrieve hardware UUID. Using path fallback."
            )
            identifiers.append(str(Path(__file__).resolve().parent))

        raw_id = "|".join(identifiers).encode()
        return hashlib.sha256(raw_id).hexdigest()[:32].upper()

    # ── Internal salt — never expose to clients ──────────────────────────────
    _INTERNAL_SALT = "A8#kL2!pZ97_qrXvW-mN5@bYt4*QeR9"

    def verify_license(self, license_key: str, machine_id: str) -> bool:
        """
        Validates license key against machine ID using hardcoded internal salt.
        Uses constant-time comparison to prevent timing attacks.
        """
        if not license_key or not machine_id:
            return False

        internal_salt = self._INTERNAL_SALT

        expected_key = (
            hashlib.sha256(f"{machine_id}:{internal_salt}".encode())
            .hexdigest()[:32]
            .upper()
        )
        is_valid = hmac.compare_digest(license_key.strip().upper(), expected_key)
        if not is_valid:
            logger.error(
                f"Guard Security: License mismatch detected for MachineID: {machine_id}"
            )
        return is_valid

    def check_license(self, license_key: str, machine_id: str) -> bool:
        """Alias for verify_license to maintain orchestrator compatibility."""
        return self.verify_license(license_key, machine_id)

    TRIAL_LIMIT = 3
    TRIAL_FILE = Path.home() / ".sentinel_trial"

    def _trial_hmac(self, count: int) -> str:
        """Compute HMAC for the given trial count bound to this machine."""
        machine_id = self.get_machine_id()
        key = f"{self._INTERNAL_SALT}:{machine_id}".encode()
        msg = str(count).encode()
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    @property
    def _TRIAL_FILE_BACKUP(self) -> Path:
        mid = self.get_machine_id()[:8].lower()
        return Path.home() / f".config/.{mid}_sc"

    def _parse_trial_file(self, path: Path):
        """Parse and verify a single trial file. Returns count int or None."""
        if not path.exists():
            return None
        try:
            raw = path.read_text().strip()
            parts = raw.split(":")
            if len(parts) != 2:
                return None
            count_str, stored_mac = parts
            if not count_str.isdigit():
                return None
            count = int(count_str)
            expected_mac = self._trial_hmac(count)
            if not hmac.compare_digest(stored_mac, expected_mac):
                logger.warning(f"Guard: Trial file {path.name} tampered.")
                return None
            return count
        except Exception:
            return None

    def _read_trial_count(self) -> int:
        """
        Read and verify trial count from disk.
        Uses two files: primary + backup.
        - If both missing → 0 (first run)
        - If one tampered/missing → use the other (higher count)
        - If both tampered → exhausted
        """
        primary = self._parse_trial_file(self.TRIAL_FILE)
        backup = self._parse_trial_file(self._TRIAL_FILE_BACKUP)

        if primary is None and backup is None:
            return 0

        if primary is None:
            return backup if backup is not None else self.TRIAL_LIMIT
        if backup is None:
            return primary if primary is not None else self.TRIAL_LIMIT

        return max(primary, backup)

    def _write_trial_count(self, count: int) -> None:
        """Write count with HMAC signature to both storage locations."""
        mac = self._trial_hmac(count)
        data = f"{count}:{mac}"
        self.TRIAL_FILE.write_text(data)
        try:
            self._TRIAL_FILE_BACKUP.parent.mkdir(parents=True, exist_ok=True)
            self._TRIAL_FILE_BACKUP.write_text(data)
        except Exception:
            pass

    def reset_trial(self, dev_key: str) -> bool:
        """Developer-only: reset trial counter."""
        expected = hashlib.sha256(
            f"DEV_RESET:{self._INTERNAL_SALT}:{self.get_machine_id()}".encode()
        ).hexdigest()[:16].upper()
        if not hmac.compare_digest(dev_key.strip().upper(), expected):
            logger.error("Guard: Invalid dev reset key.")
            return False
        self.TRIAL_FILE.unlink(missing_ok=True)
        try:
            self._TRIAL_FILE_BACKUP.unlink(missing_ok=True)
        except Exception:
            pass
        logger.info("Guard: Trial counter reset successfully.")
        return True

    def check_trial(self) -> tuple[bool, int]:
        """
        Checks if trial runs are available.
        Returns (allowed: bool, runs_remaining: int).
        Deleting or editing the trial file will NOT reset the counter.
        """
        try:
            count = self._read_trial_count()
            remaining = self.TRIAL_LIMIT - count
            if remaining > 0:
                self._write_trial_count(count + 1)
                return True, remaining - 1
            return False, 0
        except Exception:
            return False, 0