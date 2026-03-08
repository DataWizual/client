"""
Sentinel Core — Machine ID Utility
DataWizual Security (c) 2026

Запусти этот скрипт и отправь полученный ID на eldorzufarov66@gmail.com
для получения License Key.

Использование:
    python3 get_id.py
"""
import hashlib
import platform
import subprocess
import os
from pathlib import Path


def get_machine_id() -> str:
    """
    Генерирует уникальный 32-символьный Machine ID.
    Алгоритм идентичен auditor/security/guard.py — ключ будет совместим.
    """
    identifiers = [platform.machine(), platform.system()]

    try:
        if platform.system() == "Windows":
            # Используем PowerShell (wmic устарел)
            cmd = [
                "powershell",
                "-Command",
                "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID",
            ]
            output = subprocess.check_output(
                cmd, shell=False, stderr=subprocess.DEVNULL
            ).decode().strip()
            if output:
                identifiers.append(output)

        elif platform.system() == "Linux":
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        identifiers.append(f.read().strip())
                    break

        elif platform.system() == "Darwin":
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in output.splitlines():
                if "IOPlatformUUID" in line:
                    identifiers.append(line.split('"')[-2])
                    break

    except Exception:
        identifiers.append(str(Path(__file__).resolve().parent))

    raw_id = "|".join(identifiers).encode()
    return hashlib.sha256(raw_id).hexdigest()[:32].upper()


if __name__ == "__main__":
    machine_id = get_machine_id()
    print("")
    print("=" * 50)
    print("  Sentinel Core — Machine ID")
    print("=" * 50)
    print(f"  Machine ID: {machine_id}")
    print("=" * 50)
    print("")
    print("  Отправьте этот ID на:")
    print("  eldorzufarov66@gmail.com")
    print("  для получения License Key.")
    print("")