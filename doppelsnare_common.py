#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                    DOPPELSNARE — COMMON                             ║
║   Shared DNS resolution and domain-parsing helpers                    ║
╚══════════════════════════════════════════════════════════════════════╝

Code shared by both DoppelSnare scripts:

    doppelsnare.py         — domain generation + DNS/WHOIS enrichment
    doppelsnare_recon.py   — active-domain reconnaissance

Both need to resolve DNS records against public resolvers and to break a raw
domain/URL into its registrable parts. That logic lived in both files with
subtly different resolver settings; it now lives here so a fix lands in one
place.

Depends only on the standard library plus optional dnspython — without it,
resolution degrades to the OS resolver (A records only), exactly as before.
"""

import socket
import threading

# ── Optional dependency ─────────────────────────────────────────────────────

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ══════════════════════════════════════════════════════════════════════════════
#  DNS RESOLUTION
# ══════════════════════════════════════════════════════════════════════════════

# Public recursive resolvers — avoids system-stub-resolver quirks and
# rate-limiting issues when firing hundreds of concurrent queries.
PUBLIC_NS = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9"]

_thread_local = threading.local()


def make_resolver(timeout: int = 5) -> "dns.resolver.Resolver":
    """
    Return a dnspython Resolver pointed at well-known public nameservers.

    Cached per-thread so we don't rebuild the resolver object on every query
    (each domain can trigger several record lookups; without caching that's a
    fresh resolver construction per lookup across thousands of domains).  A
    per-thread instance also keeps concurrent enrichment threads independent.
    """
    cached = getattr(_thread_local, "resolver", None)
    if cached is not None:
        return cached
    r = dns.resolver.Resolver()
    r.nameservers = PUBLIC_NS
    r.timeout     = timeout
    r.lifetime    = timeout * 3   # allow retries across the nameserver list
    _thread_local.resolver = r
    return r


def resolve(domain: str, rtype: str, timeout: int = 5) -> list[str]:
    """
    Resolve a DNS record type using public recursive resolvers.
    Returns an empty list on NXDOMAIN, NoAnswer, or any network failure.
    """
    if not HAS_DNS:
        return []
    try:
        r = make_resolver(timeout)
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


def resolve_txt(domain: str, timeout: int = 5) -> list[str]:
    """
    Resolve TXT records, stripping the surrounding quotes dnspython includes.
    Used for SPF / DMARC / DKIM inspection.
    """
    return [txt.strip('"') for txt in resolve(domain, "TXT", timeout)]


def socket_resolve(domain: str) -> list[str]:
    """Fallback A/AAAA lookup via the OS resolver (no dnspython required)."""
    try:
        results = socket.getaddrinfo(domain, None)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> str | None:
    """Perform a PTR lookup on an IP address; None if it has no reverse record."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  DOMAIN PARSING
# ══════════════════════════════════════════════════════════════════════════════

# Common multi-part (public-suffix) TLDs. Not exhaustive, but covers the
# cases that would otherwise be mis-split (e.g. example.co.uk → name=example.co).
MULTI_TLDS = frozenset({
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
        if candidate_tld in MULTI_TLDS:
            return ".".join(parts[:-2]), candidate_tld, raw

    return ".".join(parts[:-1]), parts[-1], raw
