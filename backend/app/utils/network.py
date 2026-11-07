import ipaddress
import re
from typing import Dict, List, Optional


IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Common IPv6 pattern
IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
)


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def classify_ip(ip_str: str) -> Dict[str, bool]:
    """Classify an IP address as public, private (RFC1918/LAN), loopback, multicast, or reserved."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        is_internal = any(ip_obj in net for net in INTERNAL_NETWORKS)
        is_loop = ip_obj.is_loopback
        is_multi = ip_obj.is_multicast
        is_res = ip_obj.is_reserved
        is_link = ip_obj.is_link_local
        is_public = ip_obj.is_global and not is_multi and not is_res

        return {
            "is_valid": True,
            "version": 4 if ip_obj.version == 4 else 6,
            "is_private": is_internal,
            "is_loopback": is_loop,
            "is_multicast": is_multi,
            "is_reserved": is_res,
            "is_link_local": is_link,
            "is_public": is_public,
            "is_bogon": not is_public,
        }
    except ValueError:
        return {
            "is_valid": False,
            "version": 0,
            "is_private": False,
            "is_loopback": False,
            "is_multicast": False,
            "is_reserved": False,
            "is_link_local": False,
            "is_public": False,
            "is_bogon": False,
        }


def extract_ips_from_text(text: str) -> List[str]:
    """Extract distinct valid IPv4 and IPv6 addresses from text."""
    if not text:
        return []
    
    ipv4_candidates = IPV4_PATTERN.findall(text)
    ipv6_candidates = IPV6_PATTERN.findall(text)
    
    seen = set()
    valid_ips = []
    
    for candidate in ipv4_candidates + ipv6_candidates:
        candidate_clean = candidate.strip("[].,; ")
        if candidate_clean and candidate_clean not in seen and is_valid_ip(candidate_clean):
            seen.add(candidate_clean)
            valid_ips.append(candidate_clean)
            
    return valid_ips
