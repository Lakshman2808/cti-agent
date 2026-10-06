"""IOC extraction, refanging and classification. Pure Python, no network."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IOC_TYPES = (
    "ipv4", "ipv6", "domain", "url", "email",
    "md5", "sha1", "sha256", "sha512", "cve", "attack_technique",
)

# Order matters: longer / more specific patterns first.
_REFANG_RULES = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*/\s*/\s*\]|\[://\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}|\\\.", re.I), "."),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)", re.I), "@"),
    (re.compile(r"\s+\[dot\]\s+|\s+dot\s+(?=[a-z]{2,}\b)", re.I), "."),
]

# Things that look like domains but are almost always file names in reports.
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "hta",
    "lnk", "scr", "msi", "jar", "py", "sh", "elf", "bin", "dat", "tmp", "log", "txt",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf", "zip",
    "rar", "7z", "gz", "tar", "iso", "img", "vhd", "png", "jpg", "jpeg", "gif", "bmp",
    "html", "htm", "php", "asp", "aspx", "jsp", "json", "xml", "yml", "yaml", "ini",
    "cfg", "conf", "csv", "md", "db", "sqlite", "lock", "pem", "crt", "key", "plist",
    "so", "dylib", "apk", "ipa", "dmg", "pkg", "deb", "rpm", "go", "rs", "c", "cpp",
    "h", "cs", "rb", "pl", "lua", "ts", "css", "svg", "ico", "mp3", "mp4", "wav",
}

_HEX = r"[A-Fa-f0-9]"
_PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\[)(}{|\\^`]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)"),
    "ipv6": re.compile(r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])"),
    "sha512": re.compile(rf"(?<!{_HEX}){_HEX}{{128}}(?!{_HEX})"),
    "sha256": re.compile(rf"(?<!{_HEX}){_HEX}{{64}}(?!{_HEX})"),
    "sha1": re.compile(rf"(?<!{_HEX}){_HEX}{{40}}(?!{_HEX})"),
    "md5": re.compile(rf"(?<!{_HEX}){_HEX}{{32}}(?!{_HEX})"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "attack_technique": re.compile(r"\b(?:T|TA)\d{4}(?:\.\d{3})?\b"),
    "domain": re.compile(
        r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
    ),
}


def refang(text: str) -> str:
    """Turn defanged indicators (hxxp, [.], [at]) back into their real form."""
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Make an indicator safe to paste into reports and chat (not clickable)."""
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    value = value.replace("://", "[://]").replace("@", "[@]")
    return value.replace(".", "[.]")


def _ip_note(ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    for attr in ("is_private", "is_loopback", "is_link_local", "is_multicast", "is_reserved", "is_unspecified"):
        if getattr(addr, attr):
            return attr.removeprefix("is_")
    return None


def classify(value: str) -> str | None:
    """Return the IOC type of a single value, or None if it is not recognised."""
    value = refang(value.strip()).strip(".,;")
    for kind in ("url", "email", "cve", "attack_technique", "sha512", "sha256", "sha1", "md5"):
        if _PATTERNS[kind].fullmatch(value):
            return kind
    try:
        addr = ipaddress.ip_address(value)
        return "ipv4" if addr.version == 4 else "ipv6"
    except ValueError:
        pass
    if _PATTERNS["domain"].fullmatch(value) and value.rsplit(".", 1)[-1].lower() not in _FILE_EXTENSIONS:
        return "domain"
    return None


@dataclass
class ExtractionResult:
    iocs: dict[str, list[str]] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)

    def flat(self) -> list[tuple[str, str]]:
        return [(kind, v) for kind, values in self.iocs.items() for v in values]

    def count(self) -> int:
        return sum(len(v) for v in self.iocs.values())

    def to_dict(self) -> dict:
        return {"total": self.count(), "iocs": self.iocs, "notes": self.notes}


def extract(text: str, include_private: bool = False) -> ExtractionResult:
    """Extract and de-duplicate IOCs from free text (threat reports, emails, logs)."""
    text = refang(text)
    found: dict[str, dict[str, None]] = {k: {} for k in IOC_TYPES}
    notes: dict[str, str] = {}

    def add(kind: str, value: str) -> None:
        found[kind].setdefault(value, None)

    for m in _PATTERNS["url"].finditer(text):
        add("url", m.group(0).rstrip(".,;:!?'\""))
    for m in _PATTERNS["email"].finditer(text):
        add("email", m.group(0).lower())
    for m in _PATTERNS["cve"].finditer(text):
        add("cve", m.group(0).upper())
    for m in _PATTERNS["attack_technique"].finditer(text):
        add("attack_technique", m.group(0).upper())

    # Hashes, longest first, blanking matches so a sha256 never yields an md5.
    scrubbed = text
    for kind in ("sha512", "sha256", "sha1", "md5"):
        for m in _PATTERNS[kind].finditer(scrubbed):
            add(kind, m.group(0).lower())
        scrubbed = _PATTERNS[kind].sub(" ", scrubbed)

    for m in _PATTERNS["ipv4"].finditer(scrubbed):
        ip = m.group(0)
        note = _ip_note(ip)
        if note and not include_private:
            notes[ip] = f"skipped ({note})"
            continue
        add("ipv4", ip)
        if note:
            notes[ip] = note

    for m in _PATTERNS["ipv6"].finditer(scrubbed):
        candidate = m.group(0)
        if candidate.count(":") < 2:
            continue
        try:
            ip = str(ipaddress.IPv6Address(candidate))
        except ValueError:
            continue
        if ip == "::":
            continue
        note = _ip_note(ip)
        if note and not include_private:
            notes[ip] = f"skipped ({note})"
            continue
        add("ipv6", ip)

    for m in _PATTERNS["domain"].finditer(scrubbed):
        domain = m.group(0).lower().rstrip(".")
        if domain.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        add("domain", domain)

    return ExtractionResult(
        iocs={k: list(v) for k, v in found.items() if v},
        notes=notes,
    )
