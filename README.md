# DoppelSnare

> Detect and investigate fraudulent lookalike domains targeting your brand — generation, DNS/WHOIS enrichment, change tracking, and deep reconnaissance with SIEM-ready output.

**DoppelSnare** is a threat intelligence toolset for detecting and investigating fraudulent lookalike domains that could be used for phishing, wire fraud, brand impersonation, and credential harvesting. It generates candidate domains an attacker might register against your brand, enriches the ones that are live, tracks changes over time, and performs deep reconnaissance to help analysts assess intent and capability.

Built for security teams in regulated industries where domain-based fraud (BEC, wire redirection, credential theft) is a persistent threat.

## Components

### `doppelsnare.py` — Domain generation and enrichment engine

Generates lookalike domains across five detection categories:

- **Typosquatting** — keyboard-adjacent errors, transpositions, omissions, doublings, and visual substitutions (`rn`→`m`, `cl`→`d`)
- **IDN Homograph** — Cyrillic/Greek lookalike characters, emitted in both Unicode and punycode (`xn--`) form
- **Doppelgänger** — brand name combined with trust-signaling keywords, hyphens, and alternate TLDs
- **Bitsquatting** — single-bit memory errors (case-flip variants correctly excluded)
- **Phishing** — multi-keyword credential-harvest patterns swept across TLDs

Live domains are enriched with A/AAAA records, name servers, mail servers (MX), and registrar/registration data via RDAP with a WHOIS fallback chain. A baseline system tracks new, changed, and removed domains between scans, with `first_seen` threat-age tracking.

### `doppelsnare_recon.py` — Active domain reconnaissance and threat assessment

Deep-fingerprints the live domains DoppelSnare surfaces:

- **Port scanning** across services common to malicious infrastructure
- **TLS certificate inspection** — flags free/automated CAs (Let's Encrypt, ZeroSSL) and self-signed certs commonly favored by attackers
- **HTTP fingerprinting** — technology detection including known phishing toolkits (GoPhish, Evilginx, etc.), login-form and credential-harvest detection
- **Email security posture** — SPF/DKIM/DMARC analysis to gauge spoofing/BEC capability
- **Reputation checks** — VirusTotal and AbuseIPDB integration
- **Screenshots** via headless Chromium for visual evidence — with configurable timeout, full-page capture, partial-render salvage, and a debug mode that surfaces the exact failure reason
- **Aggregate risk scoring** (0–100) with an analyst-ready HTML report

### `doppelsnare_gui.py` — Desktop interface

A native graphical front-end over both engines, for analysts who prefer a
point-and-click workflow to the command line. It drives the exact same
`doppelsnare.py` and `doppelsnare_recon.py` pipelines — no separate logic to
keep in sync — across two tabs.

**Detection tab** — generation + DNS/WHOIS enrichment, streaming results into a
live table as domains resolve:

- **Scan configuration panel** — target domain, keyword list (a dropdown
  auto-populated with all 21 industry libraries plus a file browser), allowlist,
  the five detection types as checkboxes, active-only / generate-only toggles,
  and a DNS-thread selector
- **Live results table** — type, domain, IP(s), an MX indicator (rows with mail
  capability are highlighted, since that is a key BEC/phishing signal),
  registrar, and creation date, populated as each domain is enriched; a progress
  bar, active-domain counter, and a log console mirror the CLI output.
  Double-click a row to copy the domain
- **Change tracking and exports** — baseline comparison plus the SIEM lookup,
  blocklist, and delta CSV outputs, each with a save-as picker

**Recon tab** — deep-fingerprints active domains and scores them for likely
malicious intent, following the natural investigate-what-you-found workflow:

- **Target sources** — the active domains from the last Detection scan (one
  click, no re-entry), a DoppelSnare baseline JSON, a domain file, or an
  ad-hoc comma-separated list
- **Options** — brand keywords for content matching, an optional screenshots
  directory, and VirusTotal / AbuseIPDB API keys with free-tier pacing
- **Risk-scored results table** — each domain rendered as it completes, colour-
  coded by risk tier (critical/high/medium/low) with its score, a login-form
  flag, CA-risk, open ports, and email-security assessment; JSON, CSV, and
  embedded-screenshot HTML reports are written on completion

Both tabs run scans on a background thread with a working **Cancel** button, so
the window stays interactive throughout. Each tab has an **Output folder**
setting (defaulting to the install directory) so reports and baselines land in a
predictable, writable place — and the log always shows the absolute path
written — even when the GUI is launched from outside the repository.

Built on Tkinter, which ships with Python — the GUI adds **no new
dependencies** beyond what the two scripts already use, and reports any missing
optional libraries at startup just like the CLI.

### `doppelsnare_common.py` — Shared helpers

Not run directly. DNS resolution (public-resolver setup, record lookups, the
OS-resolver fallback, PTR and TXT helpers) and domain parsing (scheme/port/`www.`
stripping, multi-part TLD handling) live here so both scripts share one
implementation — a resolver or parsing fix lands in a single place. Depends
only on the standard library plus optional dnspython.

## Features

- **21 industry-specific keyword libraries** (financial, healthcare, real estate, crypto, government, and more) to tune domain generation to your sector
- **Allowlist support** to suppress false positives from your own properties and known partners
- **SIEM-ready output** — denormalized CSV lookup tables keyed on domain or IP, flat indicator blocklists for EDL/IOC feeds, and delta CSVs for automated alerting
- **Change tracking** for continuous monitoring via scheduled scans
- **Graceful degradation** — optional dependencies fail cleanly rather than blocking a scan

## Quick start

```bash
# Install from a checkout (editable, so the bundled keyword lists resolve).
# Add extras for the recon stage and/or screenshots — see Requirements below.
pip install -e '.[recon]'

# Prefer a point-and-click workflow? Launch the desktop interface
doppelsnare-gui

# Generate and enrich lookalikes for your domain
doppelsnare yourbrand.com \
  --keywords keywords/keywords_financial.txt \
  --allowlist known_good.txt \
  --csv siem_lookup.csv \
  --baseline baseline.json

# Investigate the active domains it found
doppelsnare-recon --baseline baseline.json \
  --html report.html \
  --screenshots ./evidence
```

Installing the package puts three commands on your `PATH` — `doppelsnare`,
`doppelsnare-recon`, and `doppelsnare-gui`. If you'd rather not install, the
scripts also run directly (`python doppelsnare.py …`, etc.). Either way, run
from the repository directory so the bundled keyword libraries are found.

## Requirements

Dependencies are declared in `pyproject.toml` and split into extras so you only
install what you use. Everything degrades gracefully — a missing optional
library disables its feature rather than blocking a scan.

| Install | Pulls in | Enables |
|---------|----------|---------|
| `pip install -e .` | `dnspython`, `python-whois` | Detection engine + GUI Detection tab |
| `pip install -e '.[recon]'` | `+ requests`, `cryptography` | Recon (HTTP fingerprinting, cert parsing) |
| `pip install -e '.[screenshots]'` | `+ playwright` | Screenshot capture (see below) |
| `pip install -e '.[all]'` | all of the above | Full toolset |
| `pip install -e '.[dev]'` | `+ pytest` | Test suite |

`pip install -r requirements.txt` still works and installs the core runtime.

### Screenshots (optional)

The `screenshots` extra installs the [Playwright](https://playwright.dev/python/)
Python library, but that alone is **not** enough — you also need the browser
binary:

```bash
pip install -e '.[screenshots]'   # 1. the Python library (via the extra)
playwright install chromium       # 2. the Chromium browser binary
playwright install-deps           # 3. Linux only: system libs for Chromium
```

> **Note:** the most common cause of every screenshot reporting `failed` is a
> missing Chromium binary. `pip install playwright` makes the module importable,
> but without `playwright install chromium` the browser can't launch. DoppelSnare
> Recon runs a pre-flight browser check and will tell you if this is the problem.
> You can also run any scan with `--screenshot-debug` to see the exact error.

All optional dependencies degrade gracefully — a missing library disables its
associated feature rather than blocking the scan.

## Usage

### Desktop interface

```bash
# Launch the GUI — no arguments needed
python doppelsnare_gui.py
```

On the **Detection** tab, enter a target domain, pick a keyword library and any
exports you want, then click **Run scan**. Active domains stream into the
results table as they resolve; the log console and CSV/baseline outputs match
the CLI exactly. Switch to the **Recon** tab and choose *Active domains from
last scan* to deep-fingerprint everything the scan just surfaced (or point it at
a baseline, a domain file, or a typed list), then **Run recon** for risk-scored,
colour-coded findings and JSON/CSV/HTML reports. Run it from the repository
directory so it can auto-discover the bundled keyword lists.

> Tkinter ships with most Python installs. If it is missing, install the
> python.org build or `brew install python-tk` (macOS), or
> `sudo apt install python3-tk` (Debian/Ubuntu).

### Domain generation and enrichment

```bash
# Basic scan with the default keyword list
python doppelsnare.py yourbrand.com

# Tune generation to your industry
python doppelsnare.py yourbrand.com --keywords keywords/keywords_healthcare.txt

# Combine universal + industry keywords for maximum coverage
cat keywords/keywords_universal.txt keywords/keywords_financial.txt > combined.txt
python doppelsnare.py yourbrand.com --keywords combined.txt

# Full pipeline with change tracking and SIEM output
python doppelsnare.py yourbrand.com \
  --keywords combined.txt \
  --allowlist known_good.txt \
  --active-only \
  --csv siem_lookup.csv \
  --blocklist-csv blocklist.csv \
  --delta-csv delta.csv \
  --baseline baseline.json
```

### Active domain reconnaissance

```bash
# Recon from a DoppelSnare baseline
python doppelsnare_recon.py --baseline baseline.json

# Full investigation with reputation APIs and screenshots
python doppelsnare_recon.py --baseline baseline.json \
  --report-csv recon_siem.csv \
  --html report.html \
  --screenshots ./evidence \
  --brand-keywords "yourbrand,yourproduct" \
  --vt-key YOUR_VT_KEY \
  --abuseipdb-key YOUR_ABUSE_KEY

# Tune or troubleshoot screenshot capture
python doppelsnare_recon.py --domains suspect-lookalike.com \
  --screenshots ./evidence \
  --screenshot-timeout 45000 \    # raise timeout for slow-loading sites (ms)
  --screenshot-full-page \        # capture the whole scrollable page
  --screenshot-debug              # print the real error if a capture fails

# Recon on an ad-hoc list of domains
python doppelsnare_recon.py --domains evil-lookalike.com,phish-lookalike.com
```

## Output formats

| Format | Produced by | Purpose |
|--------|-------------|---------|
| Text report | `doppelsnare.py` | Human-readable summary of generated and active domains |
| SIEM lookup CSV | `doppelsnare.py` | Denormalized table keyed on domain or IP for correlation rules |
| Blocklist CSV | `doppelsnare.py` | Flat indicator feed for Palo Alto EDL, CrowdStrike IOC, watchlists |
| Delta CSV | `doppelsnare.py` | New/changed/removed domains for automated alerting |
| Baseline JSON | `doppelsnare.py` | Persistent state for scan-over-scan change tracking |
| JSON report | `doppelsnare_recon.py` | Full structured recon findings |
| CSV summary | `doppelsnare_recon.py` | One row per domain for SIEM import |
| HTML report | `doppelsnare_recon.py` | Analyst-ready findings with embedded screenshots |

## Keyword libraries

The `keywords/` directory ships with 21 industry-tuned lists to focus domain
generation on the terms an attacker is most likely to weaponize against your
sector:

```
keywords_universal.txt        keywords_financial.txt      keywords_insurance.txt
keywords_healthcare.txt       keywords_pharma.txt         keywords_technology.txt
keywords_ecommerce.txt        keywords_realestate.txt     keywords_legal.txt
keywords_government.txt        keywords_education.txt      keywords_energy.txt
keywords_manufacturing.txt    keywords_telecom.txt        keywords_logistics.txt
keywords_hospitality.txt      keywords_media.txt          keywords_crypto.txt
keywords_aerospace.txt        keywords_food.txt           keywords_nonprofit.txt
```

## Testing

The `tests/` directory holds a `pytest` suite covering the pure logic that
matters most — a silent generation bug in a lookalike-detection tool is a
*missed threat*, not a cosmetic glitch. It exercises domain parsing (schemes,
ports, `www.`, multi-part TLDs), all five generators (determinism, well-formed
labels, the bitsquat case-flip exclusion, IDN punycode emission), allowlist
filtering, baseline change-detection (new/changed/removed/persistent, with
`first_seen` preservation), and both CSV writers. It needs no network access
and none of the optional runtime dependencies.

```bash
pip install -r requirements-dev.txt
pytest
```

## Troubleshooting

**Screenshots all report `failed`**
Almost always a missing Chromium binary. `pip install playwright` installs only
the Python module; you also need `playwright install chromium` (and, on Linux,
`playwright install-deps`). Run with `--screenshot-debug` to see the exact
underlying error, or rely on the pre-flight browser check that prints a fix hint
at startup. For slow-loading sites, raise `--screenshot-timeout` (default 30000 ms).

**Registrar / creation date come back empty**
Registration data is fetched via RDAP (HTTPS) with a WHOIS (port 43) fallback.
If your network blocks outbound port 43 and the RDAP endpoints, these fields will
be blank while DNS data still populates. This is a network restriction, not a bug.

**VirusTotal reports rate-limit errors**
The free VT tier allows 4 requests/minute. DoppelSnare Recon paces calls
automatically (`--vt-delay`, default 15.5s between domains). For paid keys set
`--vt-delay 0` to remove the wait.

## Typical workflow

DoppelSnare is designed to run on a schedule for continuous monitoring:

1. **Generate & enrich** — `doppelsnare.py` produces the current set of active lookalike domains and updates the baseline.
2. **Track changes** — the delta report highlights newly registered domains (the highest-priority threats) and infrastructure changes on existing ones.
3. **Investigate** — `doppelsnare_recon.py` deep-fingerprints the active domains, scoring each for likely malicious intent.
4. **Act** — feed the blocklist/SIEM CSVs into your security stack and use the HTML report and screenshots for takedown requests.

## Disclaimer

DoppelSnare is intended for **defensive security use** — protecting your own brand and infrastructure. Reconnaissance features (port scanning, HTTP probing) should only be run against domains you are authorized to investigate. Users are responsible for compliance with applicable laws and terms of service.
