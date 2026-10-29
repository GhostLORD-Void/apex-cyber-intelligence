"""Offline-first analysis primitives. No network requests are made here."""
from __future__ import annotations
import hashlib, ipaddress, re
from pathlib import Path
from urllib.parse import urlsplit

MAX_TEXT_CHARS = 1_000_000
URL_RE = re.compile(r"(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+")
EMAIL_RE = re.compile(r"\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", re.I)
IP_RE = re.compile(r"(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.])")
SUSPICIOUS_TERMS = ("powershell -enc", "mimikatz", "credential dump", "ransom note", "disable antivirus")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def analyze_text(text: str) -> dict:
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"text exceeds {MAX_TEXT_CHARS} characters")
    urls = sorted(set(URL_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    ips = []
    for candidate in set(IP_RE.findall(text)):
        try:
            ips.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    indicators = [term for term in SUSPICIOUS_TERMS if term in text.lower()]
    return {
        "text_length": len(text),
        "sha256": sha256_bytes(text.encode("utf-8")),
        "urls": urls,
        "emails": emails,
        "ip_addresses": sorted(ips),
        "suspicious_terms": indicators,
        "network_activity": False,
        "limitations": ["Heuristic triage only; findings require analyst verification.", "No DNS, HTTP, port scanning, or exploit activity is performed."],
    }

def analyze_file(path: str | Path) -> dict:
    p = Path(path)
    data = p.read_bytes()
    try:
        text = data.decode("utf-8")
        text_result = analyze_text(text)
    except UnicodeDecodeError:
        text_result = {"text_analysis_skipped": "not valid UTF-8 text"}
    return {
        "file_name": p.name,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "analysis": text_result,
    }

def validate_scope(target: str, allowed: list[str]) -> dict:
    """Check a hostname against an explicit allowlist; never contacts the target."""
    parsed = urlsplit(target if "://" in target else "//" + target)
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return {"allowed": False, "host": None, "reason": "target has no valid hostname"}
    normalized = {item.strip().lower().rstrip(".") for item in allowed if item.strip()}
    matched = any(host == item or host.endswith("." + item) for item in normalized)
    return {"allowed": matched, "host": host, "reason": "matched explicit allowlist" if matched else "host not present in explicit allowlist", "network_activity": False}
