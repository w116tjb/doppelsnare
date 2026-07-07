#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                         DOPPELSNARE                                 ║
║  Phishing | Typosquatting | IDN Homograph | Doppelgänger | Bitsquat ║
╚══════════════════════════════════════════════════════════════════════╝

Identifies fraudulent lookalike domains that could be used to perpetrate
wire fraud, brand impersonation, credential harvesting, or other attacks.

Usage:
    python doppelsnare.py example.com
    python doppelsnare.py example.com --keywords keywords/keywords_financial.txt
    python doppelsnare.py example.com --active-only --output report.txt
    python doppelsnare.py example.com --csv siem_lookup.csv --delta-csv delta.csv
    python doppelsnare.py example.com --baseline scans/baseline.json

Dependencies:
    pip install dnspython python-whois
"""

import argparse
import csv
import json
import os
import re
import socket
import sys
import threading
import concurrent.futures
import urllib.request
import urllib.error
from datetime import datetime

# Internal aliases kept for the RDAP/WHOIS helpers below.
_re = re
_json = json
_threading = threading
_urllib_request = urllib.request
_urllib_error = urllib.error

# ── Optional dependencies ──────────────────────────────────────────────────

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION TABLES
# ══════════════════════════════════════════════════════════════════════════════

# TLDs to probe in addition to the target's own TLD
COMMON_TLDS = [
    "com", "net", "org", "info", "biz", "io", "co", "us",
    "online", "site", "app", "cloud", "services", "support",
    "help", "login", "account", "verify",
]

# Prefixes / suffixes used in phishing and doppelgänger generation
PHISHING_WORDS = [
    "secure", "login", "account", "verify", "update", "confirm",
    "support", "help", "service", "access", "signin", "auth",
    "portal", "client", "user", "my", "go", "safe", "official",
    "online", "web", "alert", "pay", "payment", "billing",
    "home", "corp", "inc", "group", "global", "connect",
]

# IDN homograph: ASCII character → visually similar Unicode codepoints
HOMOGRAPH_MAP: dict[str, list[str]] = {
    "a": ["\u0430", "\u00e4", "\u00e1", "\u00e2", "\u00e0", "\u00e3", "\u00e5"],   # а ä á â à ã å
    "b": ["\u0180", "\u044c"],                                                       # ƀ ь
    "c": ["\u0441", "\u00e7"],                                                       # с ç
    "d": ["\u0501"],                                                                  # ԁ
    "e": ["\u0435", "\u00eb", "\u00e9", "\u00ea", "\u00e8"],                         # е ë é ê è
    "g": ["\u0261"],                                                                  # ɡ
    "h": ["\u04bb"],                                                                  # һ
    "i": ["\u0456", "\u00ef", "\u00ed", "\u00ee", "\u00ec"],                         # і ï í î ì
    "j": ["\u03f3"],                                                                  # ϳ
    "k": ["\u03ba", "\u043a"],                                                        # κ к
    "l": ["\u217c", "\u1d0c"],                                                        # ⅼ ᴌ
    "m": ["\u043c"],                                                                  # м
    "n": ["\u043f", "\u00f1"],                                                        # п ñ
    "o": ["\u043e", "\u03bf", "\u00f6", "\u00f3", "\u00f4", "\u00f2", "\u00f5"],    # о ο ö ó ô ò õ
    "p": ["\u0440"],                                                                  # р
    "q": ["\u051b"],                                                                  # ԛ
    "r": ["\u0433"],                                                                  # г
    "s": ["\u0455", "\u015f"],                                                        # ѕ ş
    "t": ["\u0442"],                                                                  # т
    "u": ["\u03c5", "\u00fc", "\u00fa", "\u00fb", "\u00f9"],                         # υ ü ú û ù
    "v": ["\u03bd", "\u0475"],                                                        # ν ѵ
    "w": ["\u0461"],                                                                  # ѡ
    "x": ["\u0445"],                                                                  # х
    "y": ["\u0443", "\u00fd"],                                                        # у ý
    "z": ["\u0290"],                                                                  # ʐ
}

# Keyboard adjacency map for typosquatting (QWERTY layout)
KEYBOARD_ADJACENT: dict[str, str] = {
    "a": "sqzwx",   "b": "vghn",    "c": "xdfv",    "d": "serfcx",
    "e": "wsrdf",   "f": "drtgcv",  "g": "ftyhbv",  "h": "gyujnb",
    "i": "uojkl",   "j": "huikmn",  "k": "jiolm",   "l": "koip",
    "m": "njk",     "n": "bhjm",    "o": "iklp",     "p": "ol",
    "q": "wa",      "r": "edft",    "s": "aqwedxz",  "t": "rfgy",
    "u": "yhji",    "v": "cfgb",    "w": "qase",     "x": "zsdc",
    "y": "tghu",    "z": "asx",
}

# Common visual substitutions (beyond keyboard adjacency)
VISUAL_SUBS: list[tuple[str, str]] = [
    ("rn", "m"), ("m", "rn"),
    ("cl", "d"), ("d", "cl"),
    ("vv", "w"), ("w", "vv"),
    ("o",  "0"), ("0",  "o"),
    ("l",  "1"), ("1",  "l"),
    ("i",  "1"), ("1",  "i"),
    ("i",  "l"), ("l",  "i"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_keywords(filepath: str) -> list[str]:
    """Load brand/industry keywords from a text file (one per line).
    Lines starting with '#' are treated as comments."""
    keywords: list[str] = []
    if not os.path.exists(filepath):
        return keywords
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                keywords.append(word)
    return keywords


def load_allowlist(filepath: str) -> set[str]:
    """
    Load a set of known-good domains to exclude from results.

    The file should contain one domain per line.  Entries that begin with
    '.' are treated as suffix matches (e.g. '.example.com' matches
    'www.example.com' and 'portal.example.com' in addition to 'example.com').
    Lines starting with '#' are comments.
    """
    exact: set[str] = set()
    if not os.path.exists(filepath):
        return exact
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            entry = line.strip().lower()
            if entry and not entry.startswith("#"):
                exact.add(entry.lstrip("."))   # normalise leading dot
    return exact


def apply_allowlist(domains: set[str] | list[str], allowlist: set[str]) -> set[str]:
    """Remove any domain that appears in the allowlist (exact match)."""
    if not allowlist:
        return set(domains)
    return {d for d in domains if d not in allowlist}


# Common multi-part (public-suffix) TLDs. Not exhaustive, but covers the
# cases that would otherwise be mis-split (e.g. example.co.uk → name=example.co).
_MULTI_TLDS = frozenset({
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "com.sg", "com.hk", "com.tw", "com.cn", "com.tr",
    "co.za", "org.za", "gov.za",
    "com.ua", "co.il", "com.ar", "com.co",
})


def parse_domain(raw: str) -> tuple[str, str, str]:
    """
    Return (name, tld, full_domain) from a raw domain/URL string.

    Handles scheme prefixes, paths, ports, a leading 'www.', and common
    multi-part TLDs (e.g. example.co.uk → name='example', tld='co.uk').
    """
    raw = raw.lower().strip()
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
    raw = raw.split("/")[0].split("?")[0].split(":")[0]   # strip path, query, port
    # Drop a leading www. so the registrable label is generated, not 'www.example'
    if raw.startswith("www."):
        raw = raw[4:]
    parts = raw.split(".")

    if len(parts) < 2:
        return raw, "com", raw + ".com"

    # Check for a two-label public suffix first (co.uk, com.au, …)
    if len(parts) >= 3:
        candidate_tld = ".".join(parts[-2:])
        if candidate_tld in _MULTI_TLDS:
            return ".".join(parts[:-2]), candidate_tld, raw

    return ".".join(parts[:-1]), parts[-1], raw


# ══════════════════════════════════════════════════════════════════════════════
#  DOMAIN GENERATION — one function per detection category
# ══════════════════════════════════════════════════════════════════════════════

def generate_typosquatting(name: str, tld: str) -> set[str]:
    """
    Typosquatting — common human typing errors:
      • adjacent-key replacements and insertions
      • character transpositions
      • character omissions
      • character doublings (fat-finger)
      • visual look-alike substitutions (rn→m, cl→d, etc.)
      • hyphen insertion / removal
      • alternate TLDs
    """
    v: set[str] = set()

    def _add(n: str) -> None:
        if n and n[0] != "-" and n[-1] != "-" and len(n) >= 2:
            v.add(f"{n}.{tld}")

    # Transpositions
    for i in range(len(name) - 1):
        t = list(name); t[i], t[i + 1] = t[i + 1], t[i]
        _add("".join(t))

    # Deletions
    for i in range(len(name)):
        _add(name[:i] + name[i + 1:])

    # Keyboard-adjacent insertions & replacements
    for i, ch in enumerate(name):
        for adj in KEYBOARD_ADJACENT.get(ch, ""):
            _add(name[:i] + adj + name[i:])       # insertion
            _add(name[:i] + adj + name[i + 1:])   # replacement

    # Fat-finger doublings
    for i, ch in enumerate(name):
        _add(name[:i] + ch + name[i:])

    # Visual substitutions
    for old, new in VISUAL_SUBS:
        candidate = name.replace(old, new, 1)
        if candidate != name:
            _add(candidate)

    # Hyphen variants
    for i in range(1, len(name)):
        _add(name[:i] + "-" + name[i:])           # insertion
    _add(name.replace("-", ""))                    # removal

    # Alternate TLDs
    for alt in COMMON_TLDS:
        if alt != tld:
            v.add(f"{name}.{alt}")

    return v


def generate_idn_homograph(name: str, tld: str) -> set[str]:
    """
    IDN Homograph — replace ASCII letters with visually identical
    Unicode characters from other scripts (Cyrillic, Greek, etc.).
    Returns both the Unicode form and its punycode (xn--) encoding.
    """
    v: set[str] = set()

    for i, ch in enumerate(name):
        replacements = HOMOGRAPH_MAP.get(ch, [])
        for repl in replacements:
            unicode_name = name[:i] + repl + name[i + 1:]
            v.add(f"{unicode_name}.{tld}")          # Unicode display form
            # Also emit punycode form (what resolvers actually see)
            try:
                label = unicode_name.encode("idna").decode("ascii")
                v.add(f"{label}.{tld}")
            except (UnicodeError, UnicodeDecodeError):
                pass

    return v


def generate_doppelganger(name: str, tld: str, keywords: list[str]) -> set[str]:
    """
    Doppelgänger — domains that contain the brand name combined with
    trusted-sounding words, numbers, or alternate TLDs to appear legitimate.
    """
    v: set[str] = set()
    words = list(dict.fromkeys(PHISHING_WORDS + keywords))   # dedup, preserve order

    for word in words:
        v.add(f"{word}-{name}.{tld}")
        v.add(f"{name}-{word}.{tld}")
        v.add(f"{word}{name}.{tld}")
        v.add(f"{name}{word}.{tld}")
        # Subdomain impersonation (brand.attacker.com style)
        v.add(f"{name}.{word}.{tld}")
        # Alternate TLD with same word combo
        for alt in COMMON_TLDS:
            if alt != tld:
                v.add(f"{word}-{name}.{alt}")
                v.add(f"{name}-{word}.{alt}")

    # Pure TLD variations
    for alt in COMMON_TLDS:
        if alt != tld:
            v.add(f"{name}.{alt}")

    # Numeric suffixes (brand1.com, brand2020.com, etc.)
    for n in range(1, 6):
        v.add(f"{name}{n}.{tld}")
        v.add(f"{name}-{n}.{tld}")

    return v


def generate_bitsquatting(name: str, tld: str) -> set[str]:
    """
    Bitsquatting — single-bit errors in any character of the domain name.
    Hardware/memory errors can cause browsers to request an adjacent
    bit-flipped character. Each of 8 bits is flipped for each character;
    only printable alphanumeric or hyphen results are kept.

    NOTE: bit 5 (0x20) is the ASCII case-toggle bit. Flipping it on a
    lowercase letter produces the uppercase equivalent, which is NOT a
    distinct domain (DNS is case-insensitive). Those variants are skipped.
    """
    v: set[str] = set()

    for i, ch in enumerate(name):
        # name is always lowercased at parse time
        code = ord(ch)
        for bit in range(8):
            flipped = code ^ (1 << bit)
            if 33 <= flipped <= 126:
                flipped_char = chr(flipped)
                # Skip pure case flips — 'r' → 'R' is the same DNS label
                if flipped_char.lower() == ch:
                    continue
                if flipped_char.isalnum() or flipped_char == "-":
                    candidate = name[:i] + flipped_char + name[i + 1:]
                    if candidate and candidate[0] != "-" and candidate[-1] != "-":
                        v.add(f"{candidate}.{tld}")
                        for alt in ("com", "net", "org"):
                            if alt != tld:
                                v.add(f"{candidate}.{alt}")

    return v


def generate_phishing(name: str, tld: str, keywords: list[str]) -> set[str]:
    """
    Phishing — domains explicitly crafted to deceive victims into believing
    they are on a legitimate brand site (login portals, verification pages,
    support sites, etc.).
    """
    v: set[str] = set()
    words = list(dict.fromkeys(PHISHING_WORDS + keywords))

    for word in words:
        for alt in COMMON_TLDS:
            v.add(f"{word}-{name}.{alt}")
            v.add(f"{name}-{word}.{alt}")
            v.add(f"{word}{name}.{alt}")
            v.add(f"{name}{word}.{alt}")

    # account-verify-brand.com / brand-account-verify.com combos
    for w1 in words[:8]:
        for w2 in words[:8]:
            if w1 != w2:
                v.add(f"{w1}-{w2}-{name}.{tld}")
                v.add(f"{name}-{w1}-{w2}.{tld}")

    return v


# ══════════════════════════════════════════════════════════════════════════════
#  DNS & WHOIS ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════════

# Public recursive resolvers — avoids system-stub-resolver quirks and
# rate-limiting issues when firing hundreds of concurrent queries.
_PUBLIC_NS = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9"]


_thread_local = _threading.local()

def _make_resolver(timeout: int = 5) -> "dns.resolver.Resolver":
    """
    Return a dnspython Resolver pointed at well-known public nameservers.
    Cached per-thread so we don't rebuild the resolver object on every query
    (each domain triggers 4 record lookups; without caching that's 4 resolver
    constructions per domain across thousands of domains).
    """
    cached = getattr(_thread_local, "resolver", None)
    if cached is not None:
        return cached
    r = dns.resolver.Resolver()
    r.nameservers = _PUBLIC_NS
    r.timeout    = timeout
    r.lifetime   = timeout * 3   # allow up to 3 retries across nameservers
    _thread_local.resolver = r
    return r


def _resolve(domain: str, rtype: str, timeout: int = 5) -> list[str]:
    """
    Resolve a DNS record type using public recursive resolvers.
    Returns an empty list on NXDOMAIN, NoAnswer, or network failure.
    """
    if not HAS_DNS:
        return []
    try:
        r = _make_resolver(timeout)
        # raise_on_no_answer=False prevents NoAnswer exceptions for empty
        # record sets (e.g. domain exists but has no MX record).
        answers = r.resolve(domain, rtype, raise_on_no_answer=False)
        return [str(a) for a in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    except Exception:
        return []


def _socket_resolve(domain: str) -> list[str]:
    """Fallback A-record lookup via the OS resolver (no dnspython required)."""
    try:
        results = socket.getaddrinfo(domain, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


# ── RDAP + WHOIS registration lookups ────────────────────────────────────────
#
# Strategy (in priority order):
#   1. RDAP over HTTPS (port 443) — structured JSON, modern standard.
#      Uses per-TLD endpoints from a built-in table; unknown TLDs fall back
#      to the rdap.org universal proxy.
#   2. Raw socket WHOIS (port 43) — plain-text fallback for TLDs not yet
#      on RDAP or when the RDAP server returns an error.
#   3. python-whois library — last resort if both above fail.

# RDAP base URLs for common TLDs  (trailing slash required)
_RDAP_SERVERS: dict[str, str] = {
    "com":      "https://rdap.verisign.com/com/v1/",
    "net":      "https://rdap.verisign.com/net/v1/",
    "org":      "https://rdap.publicinterestregistry.org/rdap/",
    "info":     "https://rdap.afilias.net/rdap/",
    "biz":      "https://rdap.nic.biz/",
    "io":       "https://rdap.nic.io/",
    "co":       "https://rdap.nic.co/",
    "us":       "https://rdap.nic.us/",
    "app":      "https://rdap.nic.google/",
    "online":   "https://rdap.nic.online/",
    "site":     "https://rdap.nic.site/",
    "cloud":    "https://rdap.nic.cloud/",
    "services": "https://rdap.nic.services/",
    "support":  "https://rdap.nic.support/",
}

# WHOIS (port 43) servers — used when RDAP is unavailable
_WHOIS_SERVERS: dict[str, str] = {
    "com":      "whois.verisign-grs.com",
    "net":      "whois.verisign-grs.com",
    "org":      "whois.pir.org",
    "info":     "whois.afilias.net",
    "biz":      "whois.neulevel.biz",
    "io":       "whois.nic.io",
    "co":       "whois.nic.co",
    "us":       "whois.nic.us",
    "app":      "whois.nic.google",
    "online":   "whois.nic.online",
    "site":     "whois.nic.site",
    "cloud":    "whois.nic.cloud",
    "services": "whois.nic.services",
    "support":  "whois.nic.support",
}

_PRIVACY_PLACEHOLDERS = frozenset({
    "redacted for privacy", "not disclosed", "data protected",
    "withheld for privacy", "gdpr masked", "contact privacy inc.",
})


def _rdap_lookup(domain: str, timeout: int = 10) -> dict:
    """
    Query an RDAP endpoint (HTTPS) for registration metadata.
    Returns a dict with registrar / creation_date / updated_date keys.
    Falls back to rdap.org universal proxy if the TLD-specific server fails.
    """
    result: dict = {"registrar": None, "creation_date": None, "updated_date": None}
    tld = domain.rsplit(".", 1)[-1].lower()

    urls_to_try: list[str] = []
    if tld in _RDAP_SERVERS:
        urls_to_try.append(_RDAP_SERVERS[tld] + "domain/" + domain)
    # Universal RDAP proxy as fallback (or primary for unknown TLDs)
    urls_to_try.append(f"https://rdap.org/domain/{domain}")

    for url in urls_to_try:
        try:
            req = _urllib_request.Request(
                url,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": "doppelsnare/1.0",
                },
            )
            with _urllib_request.urlopen(req, timeout=timeout) as resp:
                data: dict = _json.loads(resp.read())

            # ── Registrar ────────────────────────────────────────────────────
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    # Try publicIds first (cleaner name)
                    for pid in entity.get("publicIds", []):
                        if pid.get("type") == "IANA Registrar ID":
                            pass  # use the name, not the ID
                    # vcardArray[1] holds the actual vCard properties
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for prop in vcard:
                        if prop[0] == "fn" and prop[3]:
                            val = prop[3].strip()
                            if val.lower() not in _PRIVACY_PLACEHOLDERS:
                                result["registrar"] = val
                            break
                    if result["registrar"]:
                        break

            # ── Dates ────────────────────────────────────────────────────────
            for event in data.get("events", []):
                action = event.get("eventAction", "").lower()
                date   = event.get("eventDate", "")
                # Trim to YYYY-MM-DD for readability
                short  = date[:10] if date else None
                if action == "registration" and not result["creation_date"]:
                    result["creation_date"] = short
                elif action == "last changed" and not result["updated_date"]:
                    result["updated_date"] = short

            # If we got at least something useful, stop trying URLs
            if any(result.values()):
                return result

        except (_urllib_error.URLError, _urllib_error.HTTPError, Exception):
            continue   # try next URL

    return result


def _raw_whois(domain: str, server: str, port: int = 43, timeout: int = 10) -> str:
    """Open a raw TCP connection to a WHOIS server and return the text response."""
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall(f"{domain}\r\n".encode())
            chunks: list[bytes] = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _whois_text_field(raw: str, *labels: str) -> str | None:
    """Extract the first matching field value from plain-text WHOIS output."""
    for label in labels:
        m = _re.search(
            rf"^{_re.escape(label)}\s*:\s*(.+)$",
            raw, _re.MULTILINE | _re.IGNORECASE,
        )
        if m:
            val = m.group(1).strip()
            if val and val.lower() not in _PRIVACY_PLACEHOLDERS:
                return val
    return None


def _whois_socket_lookup(domain: str) -> dict:
    """Port-43 WHOIS lookup. Returns partial result dict."""
    result: dict = {"registrar": None, "creation_date": None, "updated_date": None}
    tld = domain.rsplit(".", 1)[-1].lower()

    server = _WHOIS_SERVERS.get(tld)
    if not server:
        # Ask IANA for the authoritative WHOIS server
        iana_raw = _raw_whois(tld, "whois.iana.org", timeout=8)
        m = _re.search(r"^whois:\s*(\S+)", iana_raw, _re.MULTILINE | _re.IGNORECASE)
        if m:
            server = m.group(1).strip()

    if not server:
        return result

    raw = _raw_whois(domain, server)
    if not raw:
        return result

    result["registrar"] = _whois_text_field(
        raw, "Registrar", "registrar", "Sponsoring Registrar",
    )
    result["creation_date"] = _whois_text_field(
        raw, "Creation Date", "Created On", "Created", "created",
        "Registration Time", "Registered",
    )
    result["updated_date"] = _whois_text_field(
        raw, "Updated Date", "Last Modified", "Last Updated On",
        "Last Updated", "modified", "Last Update",
    )
    return result


def _whois_lookup(domain: str) -> dict:
    """
    Full registration metadata lookup with three-tier fallback:
      1. RDAP (HTTPS / port 443) — structured JSON, preferred
      2. Raw socket WHOIS (port 43) — plain-text fallback
      3. python-whois library — last resort
    """
    # Tier 1: RDAP
    result = _rdap_lookup(domain)
    if any(result.values()):
        return result

    # Tier 2: port-43 WHOIS
    result = _whois_socket_lookup(domain)
    if any(result.values()):
        return result

    # Tier 3: python-whois
    if HAS_WHOIS:
        try:
            w = whois.whois(domain)
            result["registrar"] = result["registrar"] or getattr(w, "registrar", None)
            if not result["creation_date"]:
                cd = getattr(w, "creation_date", None)
                if isinstance(cd, list): cd = cd[0]
                result["creation_date"] = str(cd) if cd else None
            if not result["updated_date"]:
                ud = getattr(w, "updated_date", None)
                if isinstance(ud, list): ud = ud[0]
                result["updated_date"] = str(ud) if ud else None
        except Exception:
            pass

    return result


def enrich_domain(domain: str) -> dict:
    """
    Perform full DNS + WHOIS enrichment for one domain.
    Returns a dict with keys: domain, active, ip_addresses, ipv6_addresses,
    name_servers, mail_servers, registrar, creation_date, updated_date.
    """
    info: dict = {
        "domain":         domain,
        "active":         False,
        "ip_addresses":   [],
        "ipv6_addresses": [],
        "name_servers":   [],
        "mail_servers":   [],
        "registrar":      None,
        "creation_date":  None,
        "updated_date":   None,
    }

    # A records — primary activity probe
    ips = _resolve(domain, "A") or _socket_resolve(domain)
    if not ips:
        return info   # not registered / not resolving

    info["active"]          = True
    info["ip_addresses"]    = ips
    info["ipv6_addresses"]  = _resolve(domain, "AAAA")
    info["name_servers"]    = _resolve(domain, "NS")
    # MX records — mail capability is a critical BEC/phishing indicator
    info["mail_servers"]    = _resolve(domain, "MX")

    # WHOIS — registrar, registration dates
    whois_data = _whois_lookup(domain)
    info.update(whois_data)

    return info


# ══════════════════════════════════════════════════════════════════════════════
#  BASELINE COMPARISON — track changes between scans
# ══════════════════════════════════════════════════════════════════════════════

def load_baseline(filepath: str) -> dict:
    """
    Load a previous scan's baseline JSON file.
    Returns a dict with 'active_domains' keyed by domain name, or an empty
    structure if the file doesn't exist.
    """
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, IOError):
        return {}


def save_baseline(
    enriched:      dict[str, list[dict]],
    target_domain: str,
    filepath:      str,
    previous:      dict | None = None,
) -> None:
    """
    Save current active domains as the new baseline.

    Each active domain stores its enrichment data plus a 'first_seen'
    timestamp.  If the domain existed in the previous baseline, the
    original first_seen is preserved — giving analysts a persistent
    "age of threat" metric.
    """
    scan_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    prev_domains: dict = (previous or {}).get("active_domains", {})

    active_map: dict = {}
    for dtype, domains in enriched.items():
        for info in domains:
            if not info["active"]:
                continue
            d = info["domain"]
            active_map[d] = {
                "detection_type":  dtype,
                "ip_addresses":    info["ip_addresses"],
                "ipv6_addresses":  info["ipv6_addresses"],
                "name_servers":    info["name_servers"],
                "mail_servers":    info["mail_servers"],
                "registrar":       info["registrar"],
                "creation_date":   info["creation_date"],
                "updated_date":    info["updated_date"],
                # Preserve first_seen from prior baseline if it exists
                "first_seen":      prev_domains.get(d, {}).get("first_seen", scan_date),
                "last_seen":       scan_date,
            }

    baseline = {
        "tool":           "doppelsnare",
        "version":        "1.1",
        "target_domain":  target_domain,
        "scan_date":      scan_date,
        "domain_count":   len(active_map),
        "active_domains": active_map,
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, ensure_ascii=False)


def compare_with_baseline(
    enriched: dict[str, list[dict]],
    previous: dict,
) -> dict:
    """
    Compare current scan results against a previous baseline.

    Returns a dict with four categories:
      new       — active now, not in baseline  (new threats)
      removed   — in baseline, not active now  (taken down / expired)
      changed   — still active but IP, MX, or registrar changed
      persistent— still active, unchanged since last scan
    """
    prev_domains: dict = previous.get("active_domains", {})

    # Build current active set
    current: dict[str, dict] = {}
    for dtype, domains in enriched.items():
        for info in domains:
            if info["active"]:
                current[info["domain"]] = {**info, "_detection_type": dtype}

    prev_keys = set(prev_domains.keys())
    curr_keys = set(current.keys())

    new_domains:  list[dict]  = []
    removed:      list[dict]  = []
    changed:      list[dict]  = []
    persistent:   list[str]   = []

    # ── NEW: in current but not in previous ──────────────────────────────────
    for d in sorted(curr_keys - prev_keys):
        entry = current[d]
        new_domains.append({
            "domain":         d,
            "detection_type": entry["_detection_type"],
            "ip_addresses":   entry["ip_addresses"],
            "ipv6_addresses": entry.get("ipv6_addresses", []),
            "name_servers":   entry["name_servers"],
            "mail_servers":   entry["mail_servers"],
            "registrar":      entry["registrar"],
            "creation_date":  entry["creation_date"],
            "has_mx":         bool(entry["mail_servers"]),
        })

    # ── REMOVED: in previous but not in current ─────────────────────────────
    for d in sorted(prev_keys - curr_keys):
        prev = prev_domains[d]
        removed.append({
            "domain":         d,
            "detection_type": prev.get("detection_type", "Unknown"),
            "ip_addresses":   prev.get("ip_addresses", []),
            "first_seen":     prev.get("first_seen", ""),
            "last_seen":      prev.get("last_seen", ""),
        })

    # ── CHANGED vs PERSISTENT: in both ───────────────────────────────────────
    for d in sorted(curr_keys & prev_keys):
        prev = prev_domains[d]
        curr = current[d]

        changes: list[str] = []
        if set(curr["ip_addresses"]) != set(prev.get("ip_addresses", [])):
            changes.append("ip")
        if set(curr["mail_servers"]) != set(prev.get("mail_servers", [])):
            changes.append("mx")
        if (curr["registrar"] or "") != (prev.get("registrar") or ""):
            changes.append("registrar")
        if set(curr["name_servers"]) != set(prev.get("name_servers", [])):
            changes.append("ns")

        if changes:
            changed.append({
                "domain":         d,
                "detection_type": curr["_detection_type"],
                "changes":        changes,
                "prev_ips":       prev.get("ip_addresses", []),
                "curr_ips":       curr["ip_addresses"],
                "prev_mx":        prev.get("mail_servers", []),
                "curr_mx":        curr["mail_servers"],
                "prev_registrar": prev.get("registrar"),
                "curr_registrar": curr["registrar"],
                "prev_ns":        prev.get("name_servers", []),
                "curr_ns":        curr["name_servers"],
                "first_seen":     prev.get("first_seen", ""),
            })
        else:
            persistent.append(d)

    return {
        "new":        new_domains,
        "removed":    removed,
        "changed":    changed,
        "persistent": persistent,
        "prev_scan":  previous.get("scan_date", "unknown"),
    }


def print_delta_report(delta: dict) -> None:
    """Print the baseline comparison report to stdout."""
    new      = delta["new"]
    removed  = delta["removed"]
    changed  = delta["changed"]
    persist  = delta["persistent"]

    print(f"\n{_hr('═')}")
    print(f"  DELTA REPORT — compared to baseline from {delta['prev_scan']}")
    print(_hr("═"))

    # ── NEW ──────────────────────────────────────────────────────────────────
    if new:
        print(f"\n  🔴 NEW ACTIVE DOMAINS ({len(new)})")
        print(f"  {'These were NOT in the previous scan — investigate immediately.'}")
        for entry in new:
            mx_flag = " ⚠ HAS MX" if entry["has_mx"] else ""
            print(f"\n  {_hr()}")
            print(f"  {'Domain':<16}: {entry['domain']}{mx_flag}")
            print(f"  {'Type':<16}: {entry['detection_type']}")
            print(f"  {'IPv4':<16}: {_fmt_list(entry['ip_addresses'])}")
            if entry["ipv6_addresses"]:
                print(f"  {'IPv6':<16}: {_fmt_list(entry['ipv6_addresses'])}")
            print(f"  {'Name Servers':<16}: {_fmt_list(entry['name_servers'])}")
            print(f"  {'Mail Servers':<16}: {_fmt_list(entry['mail_servers'])}")
            print(f"  {'Registrar':<16}: {entry['registrar'] or '—'}")
            print(f"  {'Created':<16}: {entry['creation_date'] or '—'}")
    else:
        print(f"\n  ✅ No new active domains since last scan.")

    # ── CHANGED ──────────────────────────────────────────────────────────────
    if changed:
        print(f"\n\n  🟡 CHANGED INFRASTRUCTURE ({len(changed)})")
        print(f"  {'Active in both scans, but DNS / registration details differ.'}")
        for entry in changed:
            print(f"\n  {_hr()}")
            print(f"  {'Domain':<16}: {entry['domain']}")
            print(f"  {'Changes':<16}: {', '.join(entry['changes'])}")
            print(f"  {'First Seen':<16}: {entry['first_seen'] or '—'}")
            if "ip" in entry["changes"]:
                print(f"  {'IPs (prev)':<16}: {_fmt_list(entry['prev_ips'])}")
                print(f"  {'IPs (curr)':<16}: {_fmt_list(entry['curr_ips'])}")
            if "mx" in entry["changes"]:
                print(f"  {'MX (prev)':<16}: {_fmt_list(entry['prev_mx'])}")
                print(f"  {'MX (curr)':<16}: {_fmt_list(entry['curr_mx'])}")
            if "registrar" in entry["changes"]:
                print(f"  {'Reg (prev)':<16}: {entry['prev_registrar'] or '—'}")
                print(f"  {'Reg (curr)':<16}: {entry['curr_registrar'] or '—'}")
            if "ns" in entry["changes"]:
                print(f"  {'NS (prev)':<16}: {_fmt_list(entry['prev_ns'])}")
                print(f"  {'NS (curr)':<16}: {_fmt_list(entry['curr_ns'])}")

    # ── REMOVED ──────────────────────────────────────────────────────────────
    if removed:
        print(f"\n\n  ⚪ NO LONGER ACTIVE ({len(removed)})")
        print(f"  {'Previously active domains that no longer resolve.'}")
        for entry in removed:
            lifespan = ""
            if entry.get("first_seen") and entry.get("last_seen"):
                lifespan = f"  (seen {entry['first_seen'][:10]} → {entry['last_seen'][:10]})"
            print(f"    {entry['domain']:<40} [{entry['detection_type']}]{lifespan}")

    # ── PERSISTENT ───────────────────────────────────────────────────────────
    if persist:
        print(f"\n\n  🔵 PERSISTENT ({len(persist)})")
        print(f"  {'Still active and unchanged since last scan.'}")
        for d in persist:
            print(f"    {d}")

    # ── Delta summary ────────────────────────────────────────────────────────
    print(f"\n{_hr()}")
    print(f"  {'New':<16}: {len(new)}")
    print(f"  {'Changed':<16}: {len(changed)}")
    print(f"  {'Removed':<16}: {len(removed)}")
    print(f"  {'Persistent':<16}: {len(persist)}")
    print(_hr())


def save_delta_csv(delta: dict, target_domain: str, output_file: str) -> int:
    """
    Write the delta report as a CSV for SIEM alert ingestion.

    Each row represents one changed entry (new, removed, or changed).
    Persistent (unchanged) entries are omitted — they're not actionable.
    """
    fields = [
        "delta_status", "domain", "detection_type", "severity",
        "ip_addresses", "mail_servers", "name_servers",
        "registrar", "creation_date", "changes",
        "first_seen", "target_domain", "scan_date",
    ]
    scan_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    row_count = 0

    with open(output_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        # New domains — highest priority
        for entry in delta["new"]:
            severity = "critical" if entry.get("has_mx") else "high"
            writer.writerow({
                "delta_status":   "NEW",
                "domain":         entry["domain"],
                "detection_type": entry["detection_type"],
                "severity":       severity,
                "ip_addresses":   "|".join(entry.get("ip_addresses", [])),
                "mail_servers":   "|".join(entry.get("mail_servers", [])),
                "name_servers":   "|".join(entry.get("name_servers", [])),
                "registrar":      entry.get("registrar") or "",
                "creation_date":  entry.get("creation_date") or "",
                "changes":        "new_domain",
                "first_seen":     scan_date,
                "target_domain":  target_domain,
                "scan_date":      scan_date,
            })
            row_count += 1

        # Changed domains
        for entry in delta["changed"]:
            writer.writerow({
                "delta_status":   "CHANGED",
                "domain":         entry["domain"],
                "detection_type": entry["detection_type"],
                "severity":       "medium",
                "ip_addresses":   "|".join(entry.get("curr_ips", [])),
                "mail_servers":   "|".join(entry.get("curr_mx", [])),
                "name_servers":   "|".join(entry.get("curr_ns", [])),
                "registrar":      entry.get("curr_registrar") or "",
                "creation_date":  "",
                "changes":        "|".join(entry["changes"]),
                "first_seen":     entry.get("first_seen", ""),
                "target_domain":  target_domain,
                "scan_date":      scan_date,
            })
            row_count += 1

        # Removed domains
        for entry in delta["removed"]:
            writer.writerow({
                "delta_status":   "REMOVED",
                "domain":         entry["domain"],
                "detection_type": entry["detection_type"],
                "severity":       "info",
                "ip_addresses":   "|".join(entry.get("ip_addresses", [])),
                "mail_servers":   "",
                "name_servers":   "",
                "registrar":      "",
                "creation_date":  "",
                "changes":        "no_longer_active",
                "first_seen":     entry.get("first_seen", ""),
                "target_domain":  target_domain,
                "scan_date":      scan_date,
            })
            row_count += 1

    return row_count


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
 ____                         _ ____
|  _ \  ___  _ __  _ __   ___| / ___| _ __   __ _ _ __ ___
| | | |/ _ \| '_ \| '_ \ / _ \ \___ \| '_ \ / _` | '__/ _ \
| |_| | (_) | |_) | |_) |  __/ |___) | | | | (_| | | |  __/
|____/ \___/| .__/| .__/ \___|_|____/|_| |_|\__,_|_|  \___|
            |_|   |_|

    Phishing | Typosquatting | IDN Homograph | Doppelgänger | Bitsquatting
"""

COL_W = 68   # console line width

def _hr(char: str = "─") -> str:
    return "  " + char * COL_W


def _fmt_list(items: list[str]) -> str:
    return ", ".join(items) if items else "—"


def print_active_result(info: dict, dtype: str) -> None:
    """Print a single active-domain card to stdout."""
    print(_hr())
    print(f"  {'Domain':<16}: {info['domain']}")
    print(f"  {'Type':<16}: {dtype}")
    print(f"  {'IPv4':<16}: {_fmt_list(info['ip_addresses'])}")
    if info["ipv6_addresses"]:
        print(f"  {'IPv6':<16}: {_fmt_list(info['ipv6_addresses'])}")
    print(f"  {'Name Servers':<16}: {_fmt_list(info['name_servers'])}")
    print(f"  {'Mail Servers':<16}: {_fmt_list(info['mail_servers'])}")
    print(f"  {'Registrar':<16}: {info['registrar'] or '—'}")
    print(f"  {'Created':<16}: {info['creation_date'] or '—'}")
    print(f"  {'Updated':<16}: {info['updated_date'] or '—'}")


def save_txt_report(
    all_generated: dict[str, list[str]],
    enriched:      dict[str, list[dict]],
    target:        str,
    output_file:   str,
) -> None:
    """Write a full text report (all variants + enrichment for active ones)."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write("=" * 72 + "\n")
        fh.write("  DOPPELSNARE — LOOKALIKE DOMAIN DETECTION REPORT\n")
        fh.write(f"  Target    : {target}\n")
        fh.write(f"  Generated : {ts}\n")
        fh.write("=" * 72 + "\n")

        # Summary table
        fh.write("\n  SUMMARY\n")
        fh.write("  " + "-" * 54 + "\n")
        fh.write(f"  {'Detection Type':<24} {'Generated':>10} {'Active':>8}\n")
        fh.write("  " + "-" * 54 + "\n")
        total_gen = total_act = 0
        for dtype, domains in enriched.items():
            gen = len(all_generated[dtype])
            act = sum(1 for d in domains if d["active"])
            fh.write(f"  {dtype:<24} {gen:>10} {act:>8}\n")
            total_gen += gen; total_act += act
        fh.write("  " + "-" * 54 + "\n")
        fh.write(f"  {'TOTAL':<24} {total_gen:>10} {total_act:>8}\n\n")

        # Detail per category
        for dtype, domains in enriched.items():
            active  = [d for d in domains if d["active"]]
            passive = [d for d in domains if not d["active"]]
            fh.write("\n" + "=" * 72 + "\n")
            fh.write(f"  {dtype.upper()} — {len(active)} active / {len(domains)} checked\n")
            fh.write("=" * 72 + "\n")

            if active:
                fh.write("\n  ● ACTIVE DOMAINS\n")
                for info in active:
                    fh.write(f"\n    Domain      : {info['domain']}\n")
                    fh.write(f"    IPv4        : {_fmt_list(info['ip_addresses'])}\n")
                    if info["ipv6_addresses"]:
                        fh.write(f"    IPv6        : {_fmt_list(info['ipv6_addresses'])}\n")
                    fh.write(f"    Name Servers: {_fmt_list(info['name_servers'])}\n")
                    fh.write(f"    Mail Servers: {_fmt_list(info['mail_servers'])}\n")
                    fh.write(f"    Registrar   : {info['registrar'] or '—'}\n")
                    fh.write(f"    Created     : {info['creation_date'] or '—'}\n")
                    fh.write(f"    Updated     : {info['updated_date'] or '—'}\n")

            if passive:
                fh.write(f"\n  ○ INACTIVE / UNREGISTERED ({len(passive)} domains)\n")
                for info in passive:
                    fh.write(f"    {info['domain']}\n")


def save_siem_csv(
    enriched:      dict[str, list[dict]],
    target_domain: str,
    output_file:   str,
    active_only:   bool = False,
) -> int:
    """
    Write a SIEM-optimized CSV lookup table.

    Design decisions for SIEM import:
      • Denormalised: one row per (domain, ip) pair so the table can be
        keyed on EITHER field in a correlation rule or lookup command.
        If a domain has 3 A-records, it produces 3 rows.  Inactive
        domains get one row with ip="".
      • severity field: quick triage tier (critical / high / medium / low)
        based on whether mail is configured and the domain is active.
      • has_mx flag: a domain with MX records can receive/send email —
        critical indicator for BEC / wire-fraud phishing.
      • scan_date + target_domain: so the lookup table is self-documenting
        when loaded into Splunk, CrowdStrike NG-SIEM, Sentinel, etc.

    Returns the number of data rows written.
    """
    fields = [
        "domain",
        "ip",
        "ip_version",
        "detection_type",
        "is_active",
        "has_mx",
        "severity",
        "name_servers",
        "mail_servers",
        "registrar",
        "creation_date",
        "updated_date",
        "target_domain",
        "scan_date",
    ]

    scan_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    row_count = 0

    with open(output_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        for dtype, domains in enriched.items():
            for info in domains:
                if active_only and not info["active"]:
                    continue

                # Severity logic:
                #   critical = active + has MX (can send phishing email)
                #   high     = active, no MX
                #   medium   = inactive but was generated (monitor)
                has_mx   = bool(info["mail_servers"])
                is_active = info["active"]
                if is_active and has_mx:
                    severity = "critical"
                elif is_active:
                    severity = "high"
                else:
                    severity = "medium"

                # Common fields shared across all rows for this domain
                common = {
                    "domain":         info["domain"],
                    "detection_type": dtype,
                    "is_active":      str(is_active).lower(),
                    "has_mx":         str(has_mx).lower(),
                    "severity":       severity,
                    "name_servers":   "|".join(info["name_servers"]),
                    "mail_servers":   "|".join(info["mail_servers"]),
                    "registrar":      info["registrar"] or "",
                    "creation_date":  info["creation_date"] or "",
                    "updated_date":   info["updated_date"] or "",
                    "target_domain":  target_domain,
                    "scan_date":      scan_date,
                }

                # Denormalise: one row per IP (v4 then v6)
                all_ips: list[tuple[str, str]] = []
                for ip in info["ip_addresses"]:
                    all_ips.append((ip, "4"))
                for ip in info["ipv6_addresses"]:
                    all_ips.append((ip, "6"))

                if all_ips:
                    for ip, ver in all_ips:
                        writer.writerow({**common, "ip": ip, "ip_version": ver})
                        row_count += 1
                else:
                    # Inactive — still emit a row so the domain appears in the table
                    writer.writerow({**common, "ip": "", "ip_version": ""})
                    row_count += 1

    return row_count


def save_blocklist_csv(
    enriched:      dict[str, list[dict]],
    target_domain: str,
    output_file:   str,
    active_only:   bool = True,
) -> int:
    """
    Write a minimal domain+IP blocklist CSV suitable for direct import
    into Palo Alto EDL, CrowdStrike IOC feeds, or SIEM watchlists.

    Columns: indicator, indicator_type, detection_type, target_domain
    Each unique domain and each unique IP is its own row.
    """
    fields = ["indicator", "indicator_type", "detection_type", "target_domain"]
    seen: set[str] = set()
    row_count = 0

    with open(output_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        for dtype, domains in enriched.items():
            for info in domains:
                if active_only and not info["active"]:
                    continue
                # Domain row
                d = info["domain"]
                if d not in seen:
                    seen.add(d)
                    writer.writerow({
                        "indicator":      d,
                        "indicator_type": "domain",
                        "detection_type": dtype,
                        "target_domain":  target_domain,
                    })
                    row_count += 1
                # IP rows
                for ip in info["ip_addresses"] + info["ipv6_addresses"]:
                    if ip not in seen:
                        seen.add(ip)
                        writer.writerow({
                            "indicator":      ip,
                            "indicator_type": "ipv4" if ":" not in ip else "ipv6",
                            "detection_type": dtype,
                            "target_domain":  target_domain,
                        })
                        row_count += 1

    return row_count

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="DoppelSnare — Lookalike Domain Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python doppelsnare.py example.com
  python doppelsnare.py example.com --keywords keywords/keywords_financial.txt
  python doppelsnare.py example.com --allowlist known_good.txt
  python doppelsnare.py example.com --csv siem_lookup.csv --blocklist-csv blocklist.csv
  python doppelsnare.py example.com --baseline scans/baseline.json --delta-csv delta.csv
  python doppelsnare.py example.com --no-baseline --types phishing typosquatting
        """,
    )
    ap.add_argument("domain",
        help="Target domain to analyse (e.g. example.com)")
    ap.add_argument("--keywords", default="keywords.txt", metavar="FILE",
        help="Path to keywords file (default: keywords.txt)")
    ap.add_argument("--allowlist", default=None, metavar="FILE",
        help="Path to known-good domains file — matched domains are excluded")
    ap.add_argument("--types", nargs="+", metavar="TYPE",
        choices=["phishing","typosquatting","homograph","doppelganger","bitsquatting","all"],
        default=["all"],
        help="Detection types to run (default: all)")
    ap.add_argument("--active-only", action="store_true",
        help="Only display / save active (resolving) domains")
    ap.add_argument("--no-enrich", action="store_true",
        help="Skip DNS/WHOIS lookup — just print generated variants")
    ap.add_argument("--output", metavar="FILE",
        help="Save text report to FILE (auto-named if omitted)")
    ap.add_argument("--csv", metavar="FILE",
        help="Save SIEM lookup table CSV (denormalised: one row per domain×IP)")
    ap.add_argument("--blocklist-csv", metavar="FILE",
        help="Save flat indicator blocklist CSV (domains + IPs, for EDL/IOC feeds)")
    ap.add_argument("--threads", type=int, default=15, metavar="N",
        help="Concurrent DNS threads (default: 15)")
    ap.add_argument("--baseline", metavar="FILE",
        default="doppelsnare_baseline.json",
        help="Baseline JSON file for delta comparison (default: doppelsnare_baseline.json)")
    ap.add_argument("--no-baseline", action="store_true",
        help="Skip baseline comparison and do not save a baseline file")
    ap.add_argument("--delta-csv", metavar="FILE",
        help="Save delta report (new/changed/removed) as CSV for SIEM alerting")
    args = ap.parse_args()

    # ── Header ────────────────────────────────────────────────────────────────
    print(BANNER)

    # ── Dependency warnings ───────────────────────────────────────────────────
    if not HAS_DNS:
        print("  [!] dnspython not installed — DNS resolution limited (pip install dnspython)")
    if not HAS_WHOIS:
        print("  [!] python-whois not installed — WHOIS data unavailable (pip install python-whois)")

    # ── Parse target ──────────────────────────────────────────────────────────
    name, tld, full_domain = parse_domain(args.domain)
    print(f"  {'Target Domain':<16}: {full_domain}")
    print(f"  {'Label':<16}: {name}")
    print(f"  {'TLD':<16}: {tld}")
    print(f"  {'Timestamp':<16}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Keywords ──────────────────────────────────────────────────────────────
    keywords = load_keywords(args.keywords)
    if keywords:
        print(f"  {'Keywords':<16}: {len(keywords)} loaded from '{args.keywords}'")
        print(f"  {'  └─ sample':<16}: {', '.join(keywords[:6])}" + (" …" if len(keywords) > 6 else ""))
    else:
        print(f"  {'Keywords':<16}: none ('{args.keywords}' not found or empty)")

    # ── Allowlist ─────────────────────────────────────────────────────────────
    allowlist: set[str] = set()
    if args.allowlist:
        allowlist = load_allowlist(args.allowlist)
        if allowlist:
            print(f"  {'Allowlist':<16}: {len(allowlist)} domains loaded from '{args.allowlist}'")
        else:
            print(f"  {'Allowlist':<16}: empty or not found ('{args.allowlist}')")
    # Always allowlist the target itself
    allowlist.add(full_domain)

    # ── Baseline ──────────────────────────────────────────────────────────────
    previous_baseline: dict = {}
    if not args.no_enrich and not args.no_baseline:
        previous_baseline = load_baseline(args.baseline)
        if previous_baseline:
            prev_count = previous_baseline.get("domain_count", 0)
            prev_date  = previous_baseline.get("scan_date", "unknown")
            print(f"  {'Baseline':<16}: {prev_count} domains from {prev_date}")
        else:
            print(f"  {'Baseline':<16}: none (first scan — will create '{args.baseline}')")

    # ── Determine which detection types to run ────────────────────────────────
    run_all = "all" in args.types
    run = {
        "phishing":      run_all or "phishing"      in args.types,
        "typosquatting": run_all or "typosquatting"  in args.types,
        "homograph":     run_all or "homograph"      in args.types,
        "doppelganger":  run_all or "doppelganger"   in args.types,
        "bitsquatting":  run_all or "bitsquatting"   in args.types,
    }

    # ── Generate variants ─────────────────────────────────────────────────────
    print(f"\n{_hr('═')}")
    print("  GENERATING VARIANTS")
    print(_hr("═"))

    all_generated: dict[str, list[str]] = {}
    labels = {
        "phishing":      "Phishing",
        "typosquatting": "Typosquatting",
        "homograph":     "IDN Homograph",
        "doppelganger":  "Doppelgänger",
        "bitsquatting":  "Bitsquatting",
    }
    generators = {
        "phishing":      lambda: generate_phishing(name, tld, keywords),
        "typosquatting": lambda: generate_typosquatting(name, tld),
        "homograph":     lambda: generate_idn_homograph(name, tld),
        "doppelganger":  lambda: generate_doppelganger(name, tld, keywords),
        "bitsquatting":  lambda: generate_bitsquatting(name, tld),
    }
    for key, label in labels.items():
        if run[key]:
            variants = apply_allowlist(generators[key](), allowlist)
            all_generated[label] = sorted(variants)
            print(f"  {label:<22}: {len(variants):>5} variants generated")

    total = sum(len(v) for v in all_generated.values())
    print(f"\n  {'TOTAL':<22}: {total:>5} variants")

    # ── Skip enrichment if requested ──────────────────────────────────────────
    if args.no_enrich:
        print(f"\n  [!] Enrichment skipped (--no-enrich). Listing all variants:\n")
        for dtype, domains in all_generated.items():
            print(f"\n  [{dtype}]")
            for d in domains:
                print(f"    {d}")
        return

    # ── DNS + WHOIS enrichment ────────────────────────────────────────────────
    print(f"\n{_hr('═')}")
    print(f"  DNS ENRICHMENT  (threads={args.threads})")
    print(_hr("═"))

    # Build the UNIQUE domain set across all categories. A domain generated by
    # more than one detection type (very common between phishing/doppelgänger)
    # is enriched only ONCE here, then the result is shared to every category
    # that produced it — eliminating redundant DNS/WHOIS lookups.
    domain_to_types: dict[str, list[str]] = {}
    for dtype, domain_list in all_generated.items():
        for d in domain_list:
            domain_to_types.setdefault(d, []).append(dtype)

    unique_domains = list(domain_to_types.keys())
    total_gen = sum(len(v) for v in all_generated.values())
    dupes = total_gen - len(unique_domains)
    print(f"\n  {len(unique_domains)} unique domains to probe"
          f" ({dupes} cross-category duplicates skipped)")

    # Enrich every unique domain once, with a live progress bar.
    enrichment_cache: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(enrich_domain, d): d for d in unique_domains}
        done = 0
        total = len(unique_domains)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            bar_done = int(done / total * 30)
            bar = "█" * bar_done + "░" * (30 - bar_done)
            pct = int(done / total * 100)
            print(f"\r    [{bar}] {pct:>3}%  {done}/{total}", end="", flush=True)
            d = futures[fut]
            try:
                enrichment_cache[d] = fut.result()
            except Exception:
                enrichment_cache[d] = {"domain": d, "active": False,
                                       "ip_addresses": [], "ipv6_addresses": [],
                                       "name_servers": [], "mail_servers": [],
                                       "registrar": None, "creation_date": None,
                                       "updated_date": None}
    print()  # newline after progress bar

    # Map cached results back to each category that generated the domain.
    enriched: dict[str, list[dict]] = {}
    for dtype, domain_list in all_generated.items():
        results = [enrichment_cache[d] for d in domain_list if d in enrichment_cache]
        results.sort(key=lambda x: (not x["active"], x["domain"]))
        enriched[dtype] = [d for d in results if d["active"]] if args.active_only else results
        active_count = sum(1 for d in results if d["active"])
        print(f"  {dtype:<22}: {active_count} active / {len(domain_list)} checked")

    # Report unique active domains (deduped) alongside per-category totals.
    unique_active = sum(1 for info in enrichment_cache.values() if info["active"])
    print(f"\n  └─ {unique_active} unique ACTIVE domain(s) found")

    # ── Print active results ──────────────────────────────────────────────────
    total_active = sum(1 for dt in enriched.values() for d in dt if d["active"])

    print(f"\n{_hr('═')}")
    print(f"  ACTIVE LOOKALIKE DOMAINS SNARED — {total_active} found")
    print(_hr("═"))

    if total_active == 0:
        print("\n  No active lookalike domains snared.")
    else:
        for dtype, domains in enriched.items():
            active = [d for d in domains if d["active"]]
            if active:
                print(f"\n  ▶ {dtype.upper()} ({len(active)} active)\n")
                for info in active:
                    print_active_result(info, dtype)
        print(_hr())

    # ── Summary table ─────────────────────────────────────────────────────────
    print(f"\n{_hr('═')}")
    print("  SUMMARY TABLE")
    print(_hr("═"))
    print(f"\n  {'Detection Type':<24} {'Generated':>10} {'Active':>8}")
    print("  " + "-" * 44)
    t_gen = t_act = 0
    for dtype, domains in enriched.items():
        gen = len(all_generated[dtype])
        act = sum(1 for d in domains if d["active"])
        print(f"  {dtype:<24} {gen:>10} {act:>8}")
        t_gen += gen; t_act += act
    print("  " + "-" * 44)
    print(f"  {'TOTAL':<24} {t_gen:>10} {t_act:>8}\n")

    # ── Baseline comparison ───────────────────────────────────────────────────
    delta: dict | None = None
    if not args.no_baseline:
        if previous_baseline:
            delta = compare_with_baseline(enriched, previous_baseline)
            print_delta_report(delta)

        # Save current results as the new baseline
        save_baseline(enriched, full_domain, args.baseline, previous_baseline)
        print(f"\n  [+] Baseline saved   : {args.baseline}")

    # ── Save reports ──────────────────────────────────────────────────────────
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_txt = args.output or f"doppelsnare_{name}_{ts_str}.txt"
    save_txt_report(all_generated, enriched, full_domain, out_txt)
    print(f"  [+] Text report      : {out_txt}")

    if args.csv:
        rows = save_siem_csv(enriched, full_domain, args.csv, args.active_only)
        print(f"  [+] SIEM lookup CSV  : {args.csv}  ({rows} rows)")

    if args.blocklist_csv:
        rows = save_blocklist_csv(enriched, full_domain, args.blocklist_csv, args.active_only)
        print(f"  [+] Blocklist CSV    : {args.blocklist_csv}  ({rows} indicators)")

    if args.delta_csv and delta:
        rows = save_delta_csv(delta, full_domain, args.delta_csv)
        print(f"  [+] Delta CSV        : {args.delta_csv}  ({rows} changes)")

    print()


if __name__ == "__main__":
    main()
