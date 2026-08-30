import hashlib
import re
from typing import Dict


def calculate_hashes(data: bytes) -> Dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 hashes of binary data."""
    if not isinstance(data, bytes):
        data = str(data).encode("utf-8")

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def calculate_text_hash(text: str) -> str:
    """Calculate SHA-256 hash of a string."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def defang_url(url: str) -> str:
    """Defang URL for safe display in cybersecurity reports and logs."""
    if not url:
        return ""
    # Replace http:// with hxxp:// and https:// with hxxps://
    defanged = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxp://", defanged, flags=re.IGNORECASE)
    # Defang dots in the domain/host part
    return defanged.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    """Defang IP address for safe display."""
    if not ip:
        return ""
    return ip.replace(".", "[.]")
