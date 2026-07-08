#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                     DOPPELSNARE RECON                               ║
║         Active Domain Reconnaissance & Threat Assessment            ║
╚══════════════════════════════════════════════════════════════════════╝

Performs deep reconnaissance on active lookalike domains detected by
DoppelSnare.  Produces an analyst-ready report with port scans, TLS
certificate inspection, HTTP fingerprinting, content analysis, email
security posture, reputation scoring, and optional screenshots.

Usage:
    python doppelsnare_recon.py --baseline doppelsnare_baseline.json
    python doppelsnare_recon.py --csv siem_lookup.csv
    python doppelsnare_recon.py --domains evil-example.com,phish-example.com
    python doppelsnare_recon.py --domain-file targets.txt --vt-key YOUR_KEY

Dependencies (required):
    pip install requests dnspython

Dependencies (optional):
    pip install playwright && playwright install chromium   # screenshots
"""

import argparse
import csv
import hashlib
import html
import json
import os
import re
import socket
import ssl
import sys
import time
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Optional dependencies ────────────────────────────────────────────────────

try:
    import requests as _requests
    # Suppress insecure-request warnings (we intentionally hit suspect sites)
    from urllib3.exceptions import InsecureRequestWarning
    _requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# Shared DNS resolution + domain parsing (see doppelsnare_common.py). HAS_DNS
# and the resolver live there so a fix lands in one place for both scripts.
from doppelsnare_common import (
    HAS_DNS,
    resolve as _dns_resolve,
    resolve_txt as _dns_txt,
    reverse_dns,
    socket_resolve as resolve_ip,
)


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Ports to scan — organised by threat relevance
SCAN_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    587:  "SMTP-Submission",
    993:  "IMAPS",
    995:  "POP3S",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt-2",
    9090: "Admin-Console",
}

# Certificate issuers frequently used by attackers (free / automated)
HIGH_RISK_CA = [
    "let's encrypt",
    "letsencrypt",
    "r3",                    # Let's Encrypt intermediate
    "r10", "r11",            # Let's Encrypt newer intermediates
    "e5", "e6",              # Let's Encrypt ECDSA intermediates
    "zerossl",
    "buypass",
    "ssl.com",
    "cloudflare",            # Cloudflare universal SSL (hides origin)
]

MEDIUM_RISK_CA = [
    "comodo",
    "sectigo",
    "rapidssl",
    "thawte",
    "positivessl",
]

# Content indicators of credential harvesting / phishing
LOGIN_FORM_PATTERNS = [
    r'<input[^>]+type=["\']?password',
    r'<form[^>]+(?:login|signin|auth|credential)',
    r'name=["\'](?:user|username|email|login|password|passwd|pass)["\']',
    r'placeholder=["\'](?:email|username|password|enter your)',
    r'<button[^>]*>(?:log\s*in|sign\s*in|submit|verify|continue)<',
]

# Suspicious page title patterns
SUSPICIOUS_TITLE_PATTERNS = [
    r'login|log in|sign in|signin',
    r'verify|verification|confirm|confirmation',
    r'account.*(?:update|secure|suspend|limit)',
    r'security.*(?:alert|warning|notice|update)',
    r'password.*(?:reset|change|update|expire)',
    r'unlock|restore|recover',
    r'authenticate|authorization',
]

# Technology detection patterns (header + body)
TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress":     [r'wp-content', r'wp-includes', r'wordpress'],
    "Joomla":        [r'/media/joo', r'joomla'],
    "Drupal":        [r'Drupal|drupal\.js', r'/sites/default/'],
    "PHP":           [r'X-Powered-By.*PHP', r'\.php'],
    "ASP.NET":       [r'X-AspNet-Version', r'X-Powered-By.*ASP'],
    "nginx":         [r'Server.*nginx'],
    "Apache":        [r'Server.*Apache'],
    "IIS":           [r'Server.*IIS', r'X-Powered-By.*ASP'],
    "Cloudflare":    [r'Server.*cloudflare', r'cf-ray'],
    "GoPhish":       [r'gophish', r'X-Gophish'],
    "Evilginx":      [r'evilginx'],
    "HiddenEye":     [r'hiddeneye'],
    "SocialFish":    [r'socialfish'],
    "King Phisher":  [r'king.phisher'],
}


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_targets_from_baseline(filepath: str) -> list[dict]:
    """Load active domains from a DoppelSnare baseline JSON file."""
    with open(filepath, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    targets = []
    for domain, info in data.get("active_domains", {}).items():
        targets.append({
            "domain":         domain,
            "detection_type": info.get("detection_type", "Unknown"),
            "ip_addresses":   info.get("ip_addresses", []),
        })
    return targets


def load_targets_from_csv(filepath: str) -> list[dict]:
    """Load active domains from a DoppelSnare SIEM CSV file."""
    seen: set[str] = set()
    targets = []
    with open(filepath, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            d = row.get("domain", "")
            active = row.get("is_active", "true").lower()
            if d and d not in seen and active == "true":
                seen.add(d)
                targets.append({
                    "domain":         d,
                    "detection_type": row.get("detection_type", "Unknown"),
                    "ip_addresses":   row.get("ip", "").split("|") if row.get("ip") else [],
                })
    return targets


def load_targets_from_domains(domain_str: str) -> list[dict]:
    """Parse a comma-separated domain list."""
    return [{"domain": d.strip(), "detection_type": "Manual", "ip_addresses": []}
            for d in domain_str.split(",") if d.strip()]


def load_targets_from_file(filepath: str) -> list[dict]:
    """Load one domain per line from a text file."""
    targets = []
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            d = line.strip().lower()
            if d and not d.startswith("#"):
                targets.append({"domain": d, "detection_type": "File", "ip_addresses": []})
    return targets


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 1: PORT SCANNING
# ══════════════════════════════════════════════════════════════════════════════

# Ports where a plaintext service typically emits a greeting banner on
# connect (or responds to a bare CRLF). HTTP/TLS/RDP/DB ports are excluded —
# probing them with a raw CRLF yields nothing and just burns the recv timeout.
_BANNER_PORTS = frozenset({21, 22, 25, 110, 143, 465, 587, 993, 995})


def _scan_port(host: str, port: int, timeout: float = 3.0) -> dict | None:
    """
    Attempt a TCP connect to host:port. Returns a result dict if the port
    is open. A short banner grab is attempted only for ports that are
    expected to emit a greeting (see _BANNER_PORTS); for all other ports
    the connection success alone marks the port open, avoiding a wasted
    recv timeout.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            if port in _BANNER_PORTS:
                try:
                    s.settimeout(2.0)
                    # Most banner services greet on connect; a bare CRLF nudges
                    # the few that wait for input.
                    s.sendall(b"\r\n")
                    banner = s.recv(512).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            return {
                "port":    port,
                "service": SCAN_PORTS.get(port, "Unknown"),
                "state":   "open",
                "banner":  banner[:200] if banner else "",
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def port_scan(host: str, ports: dict[int, str] | None = None,
              threads: int = 20) -> list[dict]:
    """Scan a host for open ports using concurrent TCP connect probes."""
    ports = ports or SCAN_PORTS
    open_ports: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_port, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 2: TLS / CERTIFICATE INSPECTION
# ══════════════════════════════════════════════════════════════════════════════

def tls_inspect(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Connect via TLS and inspect the certificate chain.

    Uses a two-pass strategy:
      1. CERT_REQUIRED — gives a full parsed dict for valid certs.
      2. CERT_NONE + DER parsing via cryptography lib — handles self-signed,
         expired, and otherwise invalid certificates.

    Returns issuer, subject, validity dates, SANs, self-signed flag,
    protocol version, and a CA risk classification.
    """
    result: dict = {
        "available":      False,
        "issuer":         None,
        "issuer_org":     None,
        "subject_cn":     None,
        "san":            [],
        "not_before":     None,
        "not_after":      None,
        "days_remaining": None,
        "serial":         None,
        "protocol":       None,
        "self_signed":    False,
        "wildcard":       False,
        "ca_risk":        None,
        "cert_age_days":  None,
        "error":          None,
    }

    cert_dict: dict | None = None
    protocol: str | None   = None

    # ── Pass 1: CERT_REQUIRED (valid chain) ──────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                cert_dict = s.getpeercert(binary_form=False)
                protocol  = s.version()
    except (ssl.SSLCertVerificationError, ssl.SSLError):
        pass  # fall through to pass 2
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
        return result

    # ── Pass 2: CERT_NONE + DER parse (invalid certs) ───────────────────────
    if not cert_dict:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as raw:
                with ctx2.wrap_socket(raw, server_hostname=domain) as s:
                    der = s.getpeercert(binary_form=True)
                    protocol = protocol or s.version()
                    if not der:
                        return result
                    cert_dict = _parse_der_cert(der)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["error"] = f"Connection failed: {e}"
            return result
        except Exception as e:
            result["error"] = f"TLS error: {e}"
            return result

    if not cert_dict:
        return result

    # ── Extract fields from the parsed cert dict ─────────────────────────────
    result["available"] = True
    result["protocol"]  = protocol

    subj = dict(x[0] for x in cert_dict.get("subject", ()))
    iss  = dict(x[0] for x in cert_dict.get("issuer", ()))

    result["subject_cn"] = subj.get("commonName", "")
    result["issuer"]     = iss.get("commonName", "")
    result["issuer_org"] = iss.get("organizationName", "")

    if subj == iss:
        result["self_signed"] = True

    # SANs
    sans = []
    for san_type, san_val in cert_dict.get("subjectAltName", ()):
        if san_type == "DNS":
            sans.append(san_val)
            if san_val.startswith("*."):
                result["wildcard"] = True
    result["san"] = sans

    # Validity dates
    nb = cert_dict.get("notBefore", "")
    na = cert_dict.get("notAfter", "")
    for date_str, key_date, key_calc in [
        (nb, "not_before", "cert_age_days"),
        (na, "not_after",  "days_remaining"),
    ]:
        if not date_str:
            continue
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(date_str, fmt)
                result[key_date] = dt.strftime("%Y-%m-%d")
                if key_calc == "cert_age_days":
                    result[key_calc] = (datetime.now(timezone.utc).replace(tzinfo=None) - dt).days
                else:
                    result[key_calc] = (dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
                break
            except ValueError:
                result[key_date] = date_str

    result["serial"] = cert_dict.get("serialNumber", "")

    # CA risk classification
    issuer_lower = (result["issuer"] or "").lower()
    org_lower    = (result["issuer_org"] or "").lower()
    combined     = f"{issuer_lower} {org_lower}"

    if result["self_signed"]:
        result["ca_risk"] = "high"
    elif any(ca in combined for ca in HIGH_RISK_CA):
        result["ca_risk"] = "elevated"
    elif any(ca in combined for ca in MEDIUM_RISK_CA):
        result["ca_risk"] = "moderate"
    else:
        result["ca_risk"] = "standard"

    return result


def _parse_der_cert(der: bytes) -> dict | None:
    """
    Parse a DER-encoded certificate into the same dict format that
    ssl.getpeercert() returns, using the `cryptography` library.
    """
    try:
        from cryptography import x509 as cx509
        from cryptography.x509.oid import NameOID, ExtensionOID

        cert = cx509.load_der_x509_certificate(der)

        def _name_tuples(name: cx509.Name) -> tuple:
            mapping = {
                NameOID.COMMON_NAME:         "commonName",
                NameOID.ORGANIZATION_NAME:   "organizationName",
                NameOID.COUNTRY_NAME:        "countryName",
                NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
                NameOID.LOCALITY_NAME:       "localityName",
            }
            return tuple(
                ((mapping.get(attr.oid, attr.oid.dotted_string), attr.value),)
                for attr in name
            )

        result: dict = {
            "subject":      _name_tuples(cert.subject),
            "issuer":       _name_tuples(cert.issuer),
            "serialNumber": format(cert.serial_number, "X"),
            "notBefore":    cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "notAfter":     cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = san_ext.value.get_values_for_type(cx509.DNSName)
            result["subjectAltName"] = tuple(("DNS", n) for n in dns_names)
        except cx509.ExtensionNotFound:
            result["subjectAltName"] = ()

        return result
    except ImportError:
        return None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 3: TLS INSPECTION WITH CERT_REQUIRED (validation check)
# ══════════════════════════════════════════════════════════════════════════════

def tls_validate(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Test whether the certificate is actually valid (trusted chain)."""
    result = {"valid_chain": False, "validation_error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                result["valid_chain"] = True
    except ssl.SSLCertVerificationError as e:
        result["validation_error"] = str(e)
    except Exception as e:
        result["validation_error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 4: HTTP FINGERPRINTING & CONTENT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def http_fingerprint(domain: str, timeout: int = 10) -> dict:
    """
    Perform HTTP/HTTPS fingerprinting:
      - Response headers (server, powered-by, security headers)
      - Redirect chain
      - Page title
      - Technology detection
      - Login form detection
      - Favicon hash
      - Content length
    """
    result: dict = {
        "reachable":        False,
        "final_url":        None,
        "status_code":      None,
        "redirect_chain":   [],
        "server":           None,
        "powered_by":       None,
        "content_type":     None,
        "content_length":   None,
        "title":            None,
        "technologies":     [],
        "has_login_form":   False,
        "login_indicators": [],
        "suspicious_title": False,
        "favicon_hash":     None,
        "security_headers": {},
        "headers_raw":      {},
        "error":            None,
    }

    if not HAS_REQUESTS:
        result["error"] = "requests library not installed"
        return result

    # Try HTTPS first, fall back to HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = _requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/125.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )

            result["reachable"]      = True
            result["final_url"]      = resp.url
            result["status_code"]    = resp.status_code
            result["server"]         = resp.headers.get("Server", "")
            result["powered_by"]     = resp.headers.get("X-Powered-By", "")
            result["content_type"]   = resp.headers.get("Content-Type", "")
            result["content_length"] = len(resp.content)
            result["headers_raw"]    = dict(resp.headers)

            # Redirect chain
            result["redirect_chain"] = [
                {"url": r.url, "status": r.status_code}
                for r in resp.history
            ]

            # Security headers (absence is notable)
            sec_headers = {}
            for hdr in ("Strict-Transport-Security", "X-Frame-Options",
                        "X-Content-Type-Options", "Content-Security-Policy",
                        "X-XSS-Protection", "Referrer-Policy",
                        "Permissions-Policy"):
                sec_headers[hdr] = resp.headers.get(hdr, None)
            result["security_headers"] = sec_headers

            body = resp.text[:50000]   # Limit for analysis
            # Expose the fetched body (lower-cased) so downstream checks
            # (e.g. brand-keyword detection) can reuse it instead of
            # issuing a second HTTP GET for the same page.
            result["page_text_lower"] = body.lower()

            # Page title
            title_match = re.search(r'<title[^>]*>(.*?)</title>',
                                    body, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                title = re.sub(r'\s+', ' ', title)[:200]
                result["title"] = title
                # Check for suspicious titles
                for pat in SUSPICIOUS_TITLE_PATTERNS:
                    if re.search(pat, title, re.IGNORECASE):
                        result["suspicious_title"] = True
                        break

            # Login form detection
            indicators = []
            for pat in LOGIN_FORM_PATTERNS:
                matches = re.findall(pat, body, re.IGNORECASE)
                if matches:
                    indicators.append(pat.split(r'["\']')[0][:40])
            if indicators:
                result["has_login_form"]   = True
                result["login_indicators"] = list(set(indicators))[:5]

            # Technology detection
            techs = []
            combined_text = str(resp.headers) + "\n" + body[:20000]
            for tech, patterns in TECH_SIGNATURES.items():
                for pat in patterns:
                    if re.search(pat, combined_text, re.IGNORECASE):
                        techs.append(tech)
                        break
            result["technologies"] = techs

            # Favicon hash (useful for clone detection)
            try:
                fav_url = f"{scheme}://{domain}/favicon.ico"
                fav_resp = _requests.get(fav_url, timeout=5, verify=False)
                if fav_resp.status_code == 200 and len(fav_resp.content) > 0:
                    result["favicon_hash"] = hashlib.md5(
                        fav_resp.content
                    ).hexdigest()
            except Exception:
                pass

            return result   # Success on first scheme that works

        except _requests.exceptions.ConnectionError:
            continue
        except _requests.exceptions.Timeout:
            result["error"] = f"Timeout on {scheme}"
            continue
        except Exception as e:
            result["error"] = str(e)
            continue

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 5: EMAIL SECURITY (SPF / DKIM / DMARC)
# ══════════════════════════════════════════════════════════════════════════════
#
# DNS helpers (_dns_txt, reverse_dns, resolve_ip) are imported from
# doppelsnare_common at the top of this module.

def email_security(domain: str) -> dict:
    """
    Check email authentication records:
      - SPF (TXT on domain)
      - DMARC (TXT on _dmarc.domain)
      - DKIM (probe common selectors)
      - MX presence
    """
    result: dict = {
        "spf":           None,
        "spf_present":   False,
        "dmarc":         None,
        "dmarc_present": False,
        "dmarc_policy":  None,
        "dkim_selectors_found": [],
        "mx_present":    False,
        "mx_records":    [],
        "assessment":    None,
    }

    # SPF
    for txt in _dns_txt(domain):
        if txt.startswith("v=spf1"):
            result["spf"] = txt
            result["spf_present"] = True
            break

    # DMARC
    for txt in _dns_txt(f"_dmarc.{domain}"):
        if txt.startswith("v=DMARC1"):
            result["dmarc"] = txt
            result["dmarc_present"] = True
            # Extract policy
            m = re.search(r'p=(\w+)', txt)
            if m:
                result["dmarc_policy"] = m.group(1)
            break

    # DKIM — probe common selectors
    dkim_selectors = [
        "default", "selector1", "selector2", "google", "k1", "k2",
        "dkim", "mail", "smtp", "s1", "s2", "email",
    ]
    for sel in dkim_selectors:
        records = _dns_txt(f"{sel}._domainkey.{domain}")
        for txt in records:
            if "DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
                result["dkim_selectors_found"].append(sel)
                break

    # MX
    mx = _dns_resolve(domain, "MX")
    result["mx_present"] = bool(mx)
    result["mx_records"] = mx

    # Assessment
    if result["mx_present"] and not result["spf_present"] and not result["dmarc_present"]:
        result["assessment"] = "DANGEROUS — MX active with no SPF/DMARC; can send spoofed mail freely"
    elif result["mx_present"] and not result["dmarc_present"]:
        result["assessment"] = "RISKY — MX active with no DMARC; spoofed mail may not be rejected"
    elif result["mx_present"] and result["dmarc_policy"] == "none":
        result["assessment"] = "WEAK — DMARC exists but policy is 'none' (monitor only)"
    elif result["mx_present"] and result["dmarc_policy"] in ("quarantine", "reject"):
        result["assessment"] = "CONFIGURED — MX with enforced DMARC policy"
    elif not result["mx_present"]:
        result["assessment"] = "NO MAIL — No MX records (cannot receive email)"
    else:
        result["assessment"] = "PARTIAL — Some email auth present"

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 6: REVERSE DNS & GEOLOCATION
# ══════════════════════════════════════════════════════════════════════════════
#
# reverse_dns() and resolve_ip() are imported from doppelsnare_common at the
# top of this module (resolve_ip is the shared socket_resolve helper).


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 7: REPUTATION CHECKS (optional API keys)
# ══════════════════════════════════════════════════════════════════════════════

def check_virustotal(domain: str, api_key: str) -> dict:
    """Query VirusTotal API v3 for domain reputation."""
    result: dict = {
        "available":        False,
        "malicious":        0,
        "suspicious":       0,
        "harmless":         0,
        "undetected":       0,
        "reputation_score": None,
        "categories":       {},
        "error":            None,
    }
    if not HAS_REQUESTS or not api_key:
        return result

    try:
        resp = _requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result["available"]   = True
            result["malicious"]   = stats.get("malicious", 0)
            result["suspicious"]  = stats.get("suspicious", 0)
            result["harmless"]    = stats.get("harmless", 0)
            result["undetected"]  = stats.get("undetected", 0)
            result["reputation_score"] = data.get("reputation", 0)
            result["categories"]  = data.get("categories", {})
        elif resp.status_code == 429:
            result["error"] = "Rate limited (VT free tier: 4 req/min)"
        else:
            result["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB API v2 for IP reputation."""
    result: dict = {
        "available":        False,
        "abuse_score":      None,
        "total_reports":    0,
        "country":          None,
        "isp":              None,
        "usage_type":       None,
        "error":            None,
    }
    if not HAS_REQUESTS or not api_key or not ip:
        return result

    try:
        resp = _requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result["available"]     = True
            result["abuse_score"]   = data.get("abuseConfidenceScore", 0)
            result["total_reports"] = data.get("totalReports", 0)
            result["country"]       = data.get("countryCode", "")
            result["isp"]           = data.get("isp", "")
            result["usage_type"]    = data.get("usageType", "")
        elif resp.status_code == 429:
            result["error"] = "Rate limited"
        else:
            result["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  RECON MODULE 8: SCREENSHOT CAPTURE
# ══════════════════════════════════════════════════════════════════════════════

def capture_screenshot(domain: str, output_dir: str,
                       timeout: int = 15000) -> str | None:
    """
    Capture a screenshot of the domain's web interface using Playwright.
    Returns the file path on success, None on failure.
    """
    if not HAS_PLAYWRIGHT:
        return None

    os.makedirs(output_dir, exist_ok=True)
    safe_name = re.sub(r'[^\w\-.]', '_', domain)
    filepath  = os.path.join(output_dir, f"{safe_name}.png")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()
            # Try HTTPS first, fallback to HTTP
            for scheme in ("https", "http"):
                try:
                    page.goto(f"{scheme}://{domain}", timeout=timeout,
                              wait_until="domcontentloaded")
                    # Wait a moment for JS rendering
                    page.wait_for_timeout(2000)
                    page.screenshot(path=filepath, full_page=False)
                    browser.close()
                    return filepath
                except Exception:
                    continue
            browser.close()
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  RISK SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def calculate_risk(recon: dict) -> tuple[int, list[str]]:
    """
    Compute an aggregate risk score (0-100) based on all recon findings.
    Returns (score, list_of_risk_factors).

    Higher scores indicate greater likelihood of malicious intent.
    """
    score   = 0
    factors: list[str] = []

    # ── TLS / Certificate ────────────────────────────────────────────────────
    tls = recon.get("tls", {})
    if tls.get("self_signed"):
        score += 20
        factors.append("Self-signed TLS certificate")
    elif tls.get("ca_risk") == "elevated":
        score += 12
        factors.append(f"Free/automated CA: {tls.get('issuer', 'unknown')}")
    if tls.get("cert_age_days") is not None and tls["cert_age_days"] < 30:
        score += 10
        factors.append(f"Certificate issued {tls['cert_age_days']} days ago")

    validation = recon.get("tls_validation", {})
    if tls.get("available") and not validation.get("valid_chain"):
        score += 10
        factors.append("TLS certificate fails chain validation")

    # ── HTTP Content ─────────────────────────────────────────────────────────
    http = recon.get("http", {})
    if http.get("has_login_form"):
        score += 25
        factors.append("Login / credential form detected on page")
    if http.get("suspicious_title"):
        score += 15
        factors.append(f"Suspicious page title: \"{http.get('title', '')[:60]}\"")

    # Phishing toolkit detection
    phish_tools = {"GoPhish", "Evilginx", "HiddenEye", "SocialFish", "King Phisher"}
    detected_tools = phish_tools & set(http.get("technologies", []))
    if detected_tools:
        score += 30
        factors.append(f"Phishing toolkit detected: {', '.join(detected_tools)}")

    # Missing security headers (legit sites usually have some)
    sec = http.get("security_headers", {})
    missing = [h for h, v in sec.items() if v is None]
    if len(missing) >= 5 and http.get("reachable"):
        score += 5
        factors.append(f"Missing {len(missing)}/7 standard security headers")

    # ── Email Security ───────────────────────────────────────────────────────
    email = recon.get("email_security", {})
    if email.get("mx_present") and not email.get("spf_present"):
        score += 12
        factors.append("MX active with no SPF record — can send spoofed email")
    if email.get("mx_present") and not email.get("dmarc_present"):
        score += 8
        factors.append("MX active with no DMARC — no email authentication enforcement")

    # ── Open Ports ───────────────────────────────────────────────────────────
    ports = recon.get("ports", [])
    open_nums = {p["port"] for p in ports}

    smtp_ports = open_nums & {25, 465, 587}
    if smtp_ports:
        score += 10
        factors.append(f"SMTP port(s) open: {sorted(smtp_ports)} — can send email directly")

    admin_ports = open_nums & {2082, 2083, 2086, 2087, 3306, 5432, 9090}
    if admin_ports:
        score += 8
        factors.append(f"Admin/database port(s) open: {sorted(admin_ports)}")

    if 3389 in open_nums:
        score += 8
        factors.append("RDP (3389) open — potential C2 or compromised host")

    # ── Reputation (if available) ────────────────────────────────────────────
    vt = recon.get("virustotal", {})
    if vt.get("available"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal >= 5:
            score += 25
            factors.append(f"VirusTotal: {mal} engines flag as malicious")
        elif mal >= 1:
            score += 15
            factors.append(f"VirusTotal: {mal} engine(s) flag as malicious")
        if sus >= 3:
            score += 5
            factors.append(f"VirusTotal: {sus} engines flag as suspicious")

    abuseipdb = recon.get("abuseipdb", {})
    if abuseipdb.get("available"):
        abuse = abuseipdb.get("abuse_score", 0)
        if abuse >= 50:
            score += 20
            factors.append(f"AbuseIPDB confidence score: {abuse}%")
        elif abuse >= 10:
            score += 10
            factors.append(f"AbuseIPDB confidence score: {abuse}%")

    # Cap at 100
    score = min(score, 100)

    return score, factors


def risk_label(score: int) -> str:
    """Return a human-readable risk tier."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
#  FULL RECON PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def recon_domain(domain: str, detection_type: str, known_ips: list[str],
                 screenshot_dir: str | None, vt_key: str, abuseipdb_key: str,
                 brand_keywords: list[str]) -> dict:
    """Run the full recon pipeline on a single domain."""

    print(f"\n  ┌─ {domain} [{detection_type}]")

    # Resolve IPs if not already known
    ips = known_ips or resolve_ip(domain)
    primary_ip = ips[0] if ips else ""

    # Reverse DNS
    print(f"  │  Reverse DNS …", end="", flush=True)
    ptr = reverse_dns(primary_ip) if primary_ip else None
    print(f" {ptr or '—'}")

    # Port scan
    print(f"  │  Port scan ({len(SCAN_PORTS)} ports) …", end="", flush=True)
    ports = port_scan(domain)
    open_list = [f"{p['port']}/{p['service']}" for p in ports]
    print(f" {len(ports)} open" + (f" [{', '.join(open_list[:6])}]" if ports else ""))

    # TLS inspection
    print(f"  │  TLS certificate …", end="", flush=True)
    tls = tls_inspect(domain)
    tls_val = tls_validate(domain)
    if tls["available"]:
        ca = tls["issuer"] or "unknown"
        risk_tag = f" [{tls['ca_risk']}]" if tls["ca_risk"] else ""
        print(f" {ca}{risk_tag}")
    else:
        print(f" not available")

    # HTTP fingerprint
    print(f"  │  HTTP fingerprint …", end="", flush=True)
    http = http_fingerprint(domain)
    if http["reachable"]:
        parts = []
        if http["server"]:
            parts.append(http["server"])
        if http["title"]:
            parts.append(f'"{http["title"][:40]}"')
        print(f" {http['status_code']} — {' | '.join(parts) or 'OK'}")
    else:
        print(f" unreachable")

    # Content: brand keyword detection.
    # Reuse the page body already downloaded by http_fingerprint rather than
    # issuing a second GET for the same URL.
    brand_hits = []
    if brand_keywords:
        body_lower = http.get("page_text_lower", "")
        for kw in brand_keywords:
            if kw.lower() in body_lower:
                brand_hits.append(kw)
    if brand_hits:
        print(f"  │  Brand keywords … {', '.join(brand_hits[:5])}")

    # Email security
    print(f"  │  Email security …", end="", flush=True)
    email = email_security(domain)
    print(f" {email['assessment'][:50]}")

    # Reputation: VirusTotal
    # NOTE: the caller is responsible for inter-request pacing on the free tier
    # (see the --vt-delay handling in main()); we no longer sleep unconditionally
    # here, which previously wasted ~15s even after the final domain.
    vt = {}
    if vt_key:
        print(f"  │  VirusTotal …", end="", flush=True)
        vt = check_virustotal(domain, vt_key)
        if vt.get("available"):
            print(f" {vt['malicious']} malicious, {vt['suspicious']} suspicious")
        else:
            print(f" {vt.get('error', 'unavailable')}")

    # Reputation: AbuseIPDB
    abuseipdb = {}
    if abuseipdb_key and primary_ip:
        print(f"  │  AbuseIPDB …", end="", flush=True)
        abuseipdb = check_abuseipdb(primary_ip, abuseipdb_key)
        if abuseipdb.get("available"):
            print(f" score={abuseipdb['abuse_score']}%, "
                  f"reports={abuseipdb['total_reports']}, "
                  f"ISP={abuseipdb.get('isp','?')}")
        else:
            print(f" {abuseipdb.get('error', 'unavailable')}")

    # Screenshot
    screenshot_path = None
    if screenshot_dir:
        print(f"  │  Screenshot …", end="", flush=True)
        screenshot_path = capture_screenshot(domain, screenshot_dir)
        print(f" {'saved' if screenshot_path else 'failed'}")

    # Drop the transient full-page body used only for brand-keyword matching;
    # keeping it would bloat JSON reports (up to ~50KB per domain) and
    # duplicate content already summarised in title/technologies/etc.
    http.pop("page_text_lower", None)

    # Assemble recon result
    recon: dict = {
        "domain":          domain,
        "detection_type":  detection_type,
        "ip_addresses":    ips,
        "reverse_dns":     ptr,
        "ports":           ports,
        "tls":             tls,
        "tls_validation":  tls_val,
        "http":            http,
        "email_security":  email,
        "brand_keywords":  brand_hits,
        "virustotal":      vt,
        "abuseipdb":       abuseipdb,
        "screenshot":      screenshot_path,
    }

    # Risk scoring
    score, factors = calculate_risk(recon)
    recon["risk_score"]   = score
    recon["risk_label"]   = risk_label(score)
    recon["risk_factors"] = factors

    tier = risk_label(score)
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[tier]
    print(f"  └─ Risk: {icon} {score}/100 ({tier})")

    return recon


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT: JSON REPORT
# ══════════════════════════════════════════════════════════════════════════════

def save_json_report(results: list[dict], filepath: str) -> None:
    """Save full recon results as JSON."""
    report = {
        "tool":       "doppelsnare_recon",
        "version":    "1.0",
        "scan_date":  datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total":      len(results),
        "results":    results,
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT: CSV SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def save_csv_summary(results: list[dict], filepath: str) -> None:
    """Save a one-row-per-domain CSV for SIEM import."""
    fields = [
        "domain", "detection_type", "risk_score", "risk_label",
        "ip_addresses", "reverse_dns", "open_ports",
        "tls_issuer", "tls_ca_risk", "tls_valid_chain", "cert_age_days",
        "http_status", "http_server", "page_title", "has_login_form",
        "suspicious_title", "technologies", "favicon_hash",
        "mx_present", "spf_present", "dmarc_present", "dmarc_policy",
        "email_assessment",
        "vt_malicious", "vt_suspicious", "abuseipdb_score",
        "brand_keywords_found", "risk_factors",
        "screenshot",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "domain":              r["domain"],
                "detection_type":      r["detection_type"],
                "risk_score":          r["risk_score"],
                "risk_label":          r["risk_label"],
                "ip_addresses":        "|".join(r.get("ip_addresses", [])),
                "reverse_dns":         r.get("reverse_dns") or "",
                "open_ports":          "|".join(str(p["port"]) for p in r.get("ports", [])),
                "tls_issuer":          r.get("tls", {}).get("issuer") or "",
                "tls_ca_risk":         r.get("tls", {}).get("ca_risk") or "",
                "tls_valid_chain":     r.get("tls_validation", {}).get("valid_chain", ""),
                "cert_age_days":       r.get("tls", {}).get("cert_age_days") or "",
                "http_status":         r.get("http", {}).get("status_code") or "",
                "http_server":         r.get("http", {}).get("server") or "",
                "page_title":          r.get("http", {}).get("title") or "",
                "has_login_form":      r.get("http", {}).get("has_login_form", False),
                "suspicious_title":    r.get("http", {}).get("suspicious_title", False),
                "technologies":        "|".join(r.get("http", {}).get("technologies", [])),
                "favicon_hash":        r.get("http", {}).get("favicon_hash") or "",
                "mx_present":          r.get("email_security", {}).get("mx_present", False),
                "spf_present":         r.get("email_security", {}).get("spf_present", False),
                "dmarc_present":       r.get("email_security", {}).get("dmarc_present", False),
                "dmarc_policy":        r.get("email_security", {}).get("dmarc_policy") or "",
                "email_assessment":    r.get("email_security", {}).get("assessment") or "",
                "vt_malicious":        r.get("virustotal", {}).get("malicious") or "",
                "vt_suspicious":       r.get("virustotal", {}).get("suspicious") or "",
                "abuseipdb_score":     r.get("abuseipdb", {}).get("abuse_score") or "",
                "brand_keywords_found":"|".join(r.get("brand_keywords", [])),
                "risk_factors":        " | ".join(r.get("risk_factors", [])),
                "screenshot":          r.get("screenshot") or "",
            })


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT: HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════

def save_html_report(results: list[dict], filepath: str) -> None:
    """Generate an analyst-ready HTML report with embedded screenshots."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Sort by risk score descending
    results = sorted(results, key=lambda r: r["risk_score"], reverse=True)

    rows_html = ""
    detail_html = ""

    for i, r in enumerate(results):
        score = r["risk_score"]
        label = r["risk_label"]
        color = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f","LOW":"#2ecc71"}[label]
        d = html.escape(r["domain"])
        dtype = html.escape(r["detection_type"])

        # Summary table row
        tls_issuer = html.escape(r.get("tls",{}).get("issuer") or "—")
        http_title = html.escape((r.get("http",{}).get("title") or "—")[:50])
        login_flag = "⚠ YES" if r.get("http",{}).get("has_login_form") else "—"
        ports_str  = ", ".join(str(p["port"]) for p in r.get("ports",[]))
        ips_str    = html.escape(", ".join(r.get("ip_addresses",[])))
        email_a    = html.escape(r.get("email_security",{}).get("assessment","")[:40])

        rows_html += f"""
        <tr onclick="document.getElementById('detail-{i}').scrollIntoView({{behavior:'smooth'}})"
            style="cursor:pointer">
            <td><span style="display:inline-block;width:12px;height:12px;
                border-radius:50%;background:{color};margin-right:6px"></span>
                {score}</td>
            <td><strong>{d}</strong></td>
            <td>{dtype}</td>
            <td>{tls_issuer}</td>
            <td>{login_flag}</td>
            <td style="font-size:0.85em">{ports_str or '—'}</td>
        </tr>"""

        # Detail card
        factors_html = "".join(f"<li>{html.escape(f)}</li>" for f in r.get("risk_factors",[]))
        ports_detail = ""
        for p in r.get("ports",[]):
            banner = html.escape(p.get("banner","")[:80])
            ports_detail += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td><code>{banner}</code></td></tr>"

        screenshot_html = ""
        if r.get("screenshot") and os.path.exists(r["screenshot"]):
            import base64
            with open(r["screenshot"], "rb") as sf:
                b64 = base64.b64encode(sf.read()).decode()
            screenshot_html = f"""
            <div style="margin-top:12px">
                <strong>Screenshot</strong><br>
                <img src="data:image/png;base64,{b64}"
                     style="max-width:100%;border:1px solid #ccc;border-radius:4px;margin-top:6px">
            </div>"""

        tls_info = r.get("tls", {})
        tls_html = f"""
        <tr><td>Issuer</td><td>{html.escape(tls_info.get('issuer') or '—')}</td></tr>
        <tr><td>Issuer Org</td><td>{html.escape(tls_info.get('issuer_org') or '—')}</td></tr>
        <tr><td>Subject CN</td><td>{html.escape(tls_info.get('subject_cn') or '—')}</td></tr>
        <tr><td>Valid From</td><td>{tls_info.get('not_before') or '—'}</td></tr>
        <tr><td>Valid Until</td><td>{tls_info.get('not_after') or '—'}</td></tr>
        <tr><td>Cert Age</td><td>{tls_info.get('cert_age_days','—')} days</td></tr>
        <tr><td>Self-Signed</td><td>{'Yes ⚠' if tls_info.get('self_signed') else 'No'}</td></tr>
        <tr><td>CA Risk</td><td>{tls_info.get('ca_risk') or '—'}</td></tr>
        <tr><td>Valid Chain</td><td>{'Yes' if r.get('tls_validation',{}).get('valid_chain') else 'No ⚠'}</td></tr>"""

        email_info = r.get("email_security", {})
        spf_val = html.escape(email_info.get("spf") or "—")
        dmarc_val = html.escape(email_info.get("dmarc") or "—")

        detail_html += f"""
        <div id="detail-{i}" style="border:2px solid {color};border-radius:8px;
             padding:16px;margin-bottom:24px;background:#fff">
            <h3 style="margin-top:0;color:{color}">{d}
                <span style="font-size:0.7em;background:{color};color:#fff;
                      padding:2px 8px;border-radius:4px;margin-left:8px">{label} — {score}/100</span></h3>
            <p style="color:#666;margin-top:-8px">{dtype} | IPs: {ips_str} | rDNS: {html.escape(r.get('reverse_dns') or '—')}</p>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
                <div>
                    <strong>Risk Factors</strong>
                    <ul style="margin-top:4px;padding-left:20px">{factors_html or '<li>None identified</li>'}</ul>

                    <strong>TLS Certificate</strong>
                    <table class="detail">{tls_html}</table>
                </div>
                <div>
                    <strong>Open Ports</strong>
                    <table class="detail">
                        <tr><th>Port</th><th>Service</th><th>Banner</th></tr>
                        {ports_detail or '<tr><td colspan="3">No open ports detected</td></tr>'}
                    </table>

                    <strong>Email Security</strong>
                    <table class="detail">
                        <tr><td>MX</td><td>{'Active' if email_info.get('mx_present') else 'None'}</td></tr>
                        <tr><td>SPF</td><td style="font-size:0.8em;word-break:break-all">{spf_val}</td></tr>
                        <tr><td>DMARC</td><td style="font-size:0.8em;word-break:break-all">{dmarc_val}</td></tr>
                        <tr><td>Assessment</td><td>{html.escape(email_info.get('assessment') or '—')}</td></tr>
                    </table>
                </div>
            </div>

            <div style="margin-top:12px">
                <strong>HTTP</strong>:
                Status {r.get('http',{}).get('status_code','—')} |
                Server: {html.escape(r.get('http',{}).get('server') or '—')} |
                Title: "{http_title}" |
                Login form: {login_flag} |
                Techs: {html.escape(', '.join(r.get('http',{}).get('technologies',[])) or '—')} |
                Favicon MD5: <code>{r.get('http',{}).get('favicon_hash') or '—'}</code>
            </div>
            {screenshot_html}
        </div>"""

    page_html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>DoppelSnare Recon Report — {ts}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           max-width: 1100px; margin: 0 auto; padding: 20px; background: #f5f5f5; color: #333; }}
    h1 {{ border-bottom: 3px solid #2c3e50; padding-bottom: 8px; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 16px; }}
    th, td {{ padding: 6px 10px; text-align: left; border-bottom: 1px solid #ddd; font-size: 0.9em; }}
    th {{ background: #2c3e50; color: #fff; }}
    tr:hover {{ background: #eef; }}
    table.detail {{ width: 100%; }}
    table.detail td:first-child {{ font-weight: 600; width: 120px; white-space: nowrap; }}
    .summary {{ background: #fff; padding: 16px; border-radius: 8px; margin-bottom: 24px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 0.85em; }}
</style></head><body>
<h1>DoppelSnare Recon Report</h1>
<p>Generated: {ts} | Domains analysed: {len(results)}</p>

<div class="summary">
<h2>Summary</h2>
<table>
<tr><th>Risk</th><th>Domain</th><th>Type</th><th>TLS Issuer</th><th>Login Form</th><th>Open Ports</th></tr>
{rows_html}
</table>
</div>

<h2>Detailed Findings</h2>
{detail_html}

<p style="color:#999;font-size:0.8em;margin-top:40px">
    Generated by DoppelSnare Recon | {ts}
</p>
</body></html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(page_html)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
 ____                         _ ____
|  _ \  ___  _ __  _ __   ___| / ___| _ __   __ _ _ __ ___
| | | |/ _ \| '_ \| '_ \ / _ \ \___ \| '_ \ / _` | '__/ _ \
| |_| | (_) | |_) | |_) |  __/ |___) | | | | (_| | | |  __/
|____/ \___/| .__/| .__/ \___|_|____/|_| |_|\__,_|_|  \___|
            |_|   |_|                         R E C O N
"""


def main() -> None:
    ap = argparse.ArgumentParser(
        description="DoppelSnare Recon — Active domain reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
input sources (pick one):
  --baseline FILE    DoppelSnare baseline JSON
  --csv FILE         DoppelSnare SIEM lookup CSV
  --domains A,B,C    Comma-separated domain list
  --domain-file FILE One domain per line

examples:
  python doppelsnare_recon.py --baseline doppelsnare_baseline.json
  python doppelsnare_recon.py --csv siem_lookup.csv --screenshots ./shots
  python doppelsnare_recon.py --domains evil.com,bad.com --vt-key YOUR_KEY
  python doppelsnare_recon.py --domain-file targets.txt --html report.html
        """,
    )

    # Input sources
    inp = ap.add_argument_group("input")
    inp.add_argument("--baseline", metavar="FILE",
        help="DoppelSnare baseline JSON file")
    inp.add_argument("--csv", metavar="FILE",
        help="DoppelSnare SIEM lookup CSV file")
    inp.add_argument("--domains", metavar="LIST",
        help="Comma-separated domain list")
    inp.add_argument("--domain-file", metavar="FILE",
        help="Text file with one domain per line")

    # Output
    out = ap.add_argument_group("output")
    out.add_argument("--json", metavar="FILE", default=None,
        help="Save full JSON report (auto-named if omitted)")
    out.add_argument("--report-csv", metavar="FILE",
        help="Save CSV summary for SIEM import")
    out.add_argument("--html", metavar="FILE",
        help="Save HTML report with embedded screenshots")
    out.add_argument("--screenshots", metavar="DIR",
        help="Directory to save screenshots (requires playwright)")

    # API keys
    api = ap.add_argument_group("reputation APIs (optional)")
    api.add_argument("--vt-key", metavar="KEY",
        help="VirusTotal API key (free tier: 4 req/min)")
    api.add_argument("--vt-delay", type=float, default=15.5, metavar="SEC",
        help="Seconds to wait between VirusTotal calls (default: 15.5 for free "
             "tier's 4 req/min; set to 0 for paid keys)")
    api.add_argument("--abuseipdb-key", metavar="KEY",
        help="AbuseIPDB API key")

    # Options
    ap.add_argument("--brand-keywords", metavar="WORDS",
        help="Comma-separated brand keywords to detect in page content")
    ap.add_argument("--threads", type=int, default=10, metavar="N",
        help="Port scan threads per domain (default: 10)")

    args = ap.parse_args()

    print(BANNER)

    # ── Dependency check ─────────────────────────────────────────────────────
    if not HAS_REQUESTS:
        print("  [!] requests not installed — HTTP fingerprinting disabled")
        print("      pip install requests")
    if not HAS_DNS:
        print("  [!] dnspython not installed — email security checks disabled")
        print("      pip install dnspython")
    if not HAS_PLAYWRIGHT:
        if args.screenshots:
            print("  [!] playwright not installed — screenshots disabled")
            print("      pip install playwright && playwright install chromium")
            args.screenshots = None

    # ── Load targets ─────────────────────────────────────────────────────────
    targets: list[dict] = []
    if args.baseline:
        targets = load_targets_from_baseline(args.baseline)
        print(f"  Input: {len(targets)} active domains from baseline '{args.baseline}'")
    elif args.csv:
        targets = load_targets_from_csv(args.csv)
        print(f"  Input: {len(targets)} active domains from CSV '{args.csv}'")
    elif args.domains:
        targets = load_targets_from_domains(args.domains)
        print(f"  Input: {len(targets)} domains from command line")
    elif args.domain_file:
        targets = load_targets_from_file(args.domain_file)
        print(f"  Input: {len(targets)} domains from '{args.domain_file}'")
    else:
        ap.error("No input specified. Use --baseline, --csv, --domains, or --domain-file")

    if not targets:
        print("  No targets to scan.")
        return

    # ── Parse brand keywords ─────────────────────────────────────────────────
    brand_kw = []
    if args.brand_keywords:
        brand_kw = [w.strip() for w in args.brand_keywords.split(",") if w.strip()]
        print(f"  Brand keywords: {', '.join(brand_kw)}")

    print(f"\n  Scanning {len(targets)} domain(s) …")
    print(f"  {'═' * 60}")

    # ── Run recon ────────────────────────────────────────────────────────────
    results: list[dict] = []
    use_vt = bool(args.vt_key)
    for idx, target in enumerate(targets):
        recon = recon_domain(
            domain=target["domain"],
            detection_type=target["detection_type"],
            known_ips=target.get("ip_addresses", []),
            screenshot_dir=args.screenshots,
            vt_key=args.vt_key or "",
            abuseipdb_key=args.abuseipdb_key or "",
            brand_keywords=brand_kw,
        )
        results.append(recon)

        # VirusTotal free-tier pacing: sleep BETWEEN calls only, never after
        # the final domain. Skip entirely when no VT key or delay is 0.
        if use_vt and args.vt_delay > 0 and idx < len(targets) - 1:
            time.sleep(args.vt_delay)

    # ── Print summary ────────────────────────────────────────────────────────
    results.sort(key=lambda r: r["risk_score"], reverse=True)

    print(f"\n  {'═' * 60}")
    print(f"  RECON SUMMARY — {len(results)} domains analysed")
    print(f"  {'═' * 60}")
    print(f"\n  {'Domain':<35} {'Risk':>6}  {'Label':<10} {'Login':<7} {'CA Risk':<10}")
    print(f"  {'─' * 75}")
    for r in results:
        d = r["domain"][:34]
        login = "⚠ YES" if r.get("http",{}).get("has_login_form") else "—"
        ca = r.get("tls",{}).get("ca_risk") or "—"
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}[r["risk_label"]]
        print(f"  {d:<35} {r['risk_score']:>4}  {icon} {r['risk_label']:<8} {login:<7} {ca}")

    crit = sum(1 for r in results if r["risk_label"] == "CRITICAL")
    high = sum(1 for r in results if r["risk_label"] == "HIGH")
    med  = sum(1 for r in results if r["risk_label"] == "MEDIUM")
    low  = sum(1 for r in results if r["risk_label"] == "LOW")
    print(f"\n  Breakdown: {crit} critical, {high} high, {med} medium, {low} low\n")

    # ── Save outputs ─────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = args.json or f"recon_report_{ts}.json"
    save_json_report(results, json_path)
    print(f"  [+] JSON report  : {json_path}")

    if args.report_csv:
        save_csv_summary(results, args.report_csv)
        print(f"  [+] CSV summary  : {args.report_csv}")

    if args.html:
        save_html_report(results, args.html)
        print(f"  [+] HTML report  : {args.html}")

    print()


if __name__ == "__main__":
    main()
