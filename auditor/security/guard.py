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