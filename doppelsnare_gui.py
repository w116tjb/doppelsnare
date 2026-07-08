#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                      DOPPELSNARE — GUI                              ║
║   Desktop front-end for the lookalike-domain detection toolset        ║
╚══════════════════════════════════════════════════════════════════════╝

A native Tkinter interface over the DoppelSnare toolset, in two tabs:

  Detection — drives doppelsnare.py's generation + DNS/WHOIS enrichment +
              baseline/CSV pipeline, streaming active domains into a table.
  Recon     — drives doppelsnare_recon.py against the active domains a scan
              surfaces (or any target list), deep-fingerprinting each and
              scoring it for likely malicious intent.

Usage:
    python doppelsnare_gui.py

Requires only the standard library (Tkinter) plus whatever optional
dependencies the underlying scripts use (dnspython / python-whois / requests /
playwright).  All degrade gracefully — the GUI reports which are missing.
"""

import contextlib
import io
import os
import queue
import sys
import threading
import concurrent.futures
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:  # pragma: no cover - platform without Tk
    sys.stderr.write(
        "Tkinter is not available in this Python build.\n"
        "On macOS install the python.org build or `brew install python-tk`.\n"
        "On Debian/Ubuntu: `sudo apt install python3-tk`.\n"
    )
    sys.exit(1)

# The GUI is a thin shell around the two engines — import them as libraries.
import doppelsnare as ds
import doppelsnare_recon as recon

# Directory the GUI/scripts live in. Used as the default output folder so
# reports land in a predictable, writable place even when the GUI is launched
# from elsewhere (e.g. double-clicked, where the process CWD is '/').
APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_output(path: str | None, outdir: str) -> str | None:
    """Place a relative output path inside outdir; leave absolute paths as-is."""
    if not path:
        return path
    return path if os.path.isabs(path) else os.path.join(outdir, path)


# Detection types, in display order: (engine label, config key, generator).
# Labels match the keys doppelsnare.main() uses so the save_* helpers work
# unchanged.
DETECTION_TYPES = [
    ("Phishing",       "phishing"),
    ("Typosquatting",  "typosquatting"),
    ("IDN Homograph",  "homograph"),
    ("Doppelgänger",   "doppelganger"),
    ("Bitsquatting",   "bitsquatting"),
]


def _generators(name, tld, keywords):
    """Map an engine label to a zero-arg generator callable."""
    return {
        "Phishing":      lambda: ds.generate_phishing(name, tld, keywords),
        "Typosquatting": lambda: ds.generate_typosquatting(name, tld),
        "IDN Homograph": lambda: ds.generate_idn_homograph(name, tld),
        "Doppelgänger":  lambda: ds.generate_doppelganger(name, tld, keywords),
        "Bitsquatting":  lambda: ds.generate_bitsquatting(name, tld),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER — runs the scan off the UI thread, reporting via a queue
# ══════════════════════════════════════════════════════════════════════════════

class ScanWorker(threading.Thread):
    """
    Runs one scan in the background.  Communicates with the UI exclusively
    through `self.q`, posting (kind, payload) messages the main thread polls.
    """

    def __init__(self, config: dict, q: "queue.Queue", cancel: threading.Event):
        super().__init__(daemon=True)
        self.cfg = config
        self.q = q
        self.cancel = cancel

    # -- small helpers to keep the run() body readable ----------------------
    def _log(self, msg: str) -> None:
        self.q.put(("log", msg))

    def _status(self, msg: str) -> None:
        self.q.put(("status", msg))

    def run(self) -> None:
        try:
            self._run()
        except Exception as exc:  # surface any failure to the UI, don't crash
            self.q.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            self.q.put(("done", None))

    def _run(self) -> None:
        cfg = self.cfg

        if not ds.HAS_DNS:
            self._log("[!] dnspython not installed — DNS resolution limited "
                      "(pip install dnspython)")
        if not ds.HAS_WHOIS:
            self._log("[!] python-whois not installed — WHOIS data unavailable "
                      "(pip install python-whois)")

        # ── Parse target ───────────────────────────────────────────────────
        name, tld, full_domain = ds.parse_domain(cfg["domain"])
        self._log(f"Target : {full_domain}   (label='{name}', tld='{tld}')")

        # ── Keywords ───────────────────────────────────────────────────────
        keywords = ds.load_keywords(cfg["keywords"])
        if keywords:
            self._log(f"Keywords: {len(keywords)} loaded from "
                      f"'{cfg['keywords']}'")
        else:
            self._log(f"Keywords: none ('{cfg['keywords']}' not found/empty)")

        # ── Allowlist (target is always excluded) ──────────────────────────
        allowlist: set = set()
        if cfg["allowlist"]:
            allowlist = ds.load_allowlist(cfg["allowlist"])
            self._log(f"Allowlist: {len(allowlist)} domains from "
                      f"'{cfg['allowlist']}'")
        allowlist.add(full_domain)

        # ── Baseline (load prior state for delta) ──────────────────────────
        # Resolve once so the same absolute path is used to load AND save.
        outdir = cfg["outdir"]
        baseline_path = _resolve_output(cfg["baseline"], outdir)
        previous_baseline: dict = {}
        use_baseline = cfg["use_baseline"] and not cfg["no_enrich"]
        if use_baseline:
            previous_baseline = ds.load_baseline(baseline_path)
            if previous_baseline:
                self._log(f"Baseline: {previous_baseline.get('domain_count', 0)} "
                          f"domains from "
                          f"{previous_baseline.get('scan_date', 'unknown')}")
            else:
                self._log(f"Baseline: none — first scan will create "
                          f"'{baseline_path}'")

        # ── Generate variants ──────────────────────────────────────────────
        self._status("Generating variants…")
        gens = _generators(name, tld, keywords)
        all_generated: dict[str, list[str]] = {}
        for label in cfg["types"]:
            variants = ds.apply_allowlist(gens[label](), allowlist)
            all_generated[label] = sorted(variants)
            self._log(f"  {label:<16}: {len(variants):>5} variants")
            if self.cancel.is_set():
                self._log("Cancelled during generation.")
                return

        total_gen = sum(len(v) for v in all_generated.values())
        self._log(f"  {'TOTAL':<16}: {total_gen:>5} variants")

        # ── No-enrich mode: just hand the variant lists back ───────────────
        if cfg["no_enrich"]:
            self.q.put(("variants_only", all_generated))
            self._status(f"Done — {total_gen} variants generated (no enrichment)")
            return

        # ── Enrich unique domains once, sharing results across categories ──
        domain_to_types: dict[str, list[str]] = {}
        for label, domains in all_generated.items():
            for d in domains:
                domain_to_types.setdefault(d, []).append(label)
        unique_domains = list(domain_to_types.keys())
        dupes = total_gen - len(unique_domains)
        self._log(f"\nEnriching {len(unique_domains)} unique domains "
                  f"({dupes} cross-category duplicates skipped), "
                  f"threads={cfg['threads']}")
        self._status(f"Enriching 0/{len(unique_domains)}…")

        enrichment_cache: dict[str, dict] = {}
        total = len(unique_domains)
        self.q.put(("progress", (0, total)))

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=cfg["threads"]) as pool:
            futures = {pool.submit(ds.enrich_domain, d): d
                       for d in unique_domains}
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                if self.cancel.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    self._log("Cancelled during enrichment.")
                    return
                d = futures[fut]
                try:
                    info = fut.result()
                except Exception:
                    info = {"domain": d, "active": False, "ip_addresses": [],
                            "ipv6_addresses": [], "name_servers": [],
                            "mail_servers": [], "registrar": None,
                            "creation_date": None, "updated_date": None}
                enrichment_cache[d] = info
                done += 1
                self.q.put(("progress", (done, total)))
                self._status(f"Enriching {done}/{total}…")
                # Stream active hits into the table as they land.
                if info["active"]:
                    self.q.put(("active_hit",
                                (", ".join(domain_to_types[d]), info)))

        # ── Assemble per-category enriched results (engine format) ─────────
        enriched: dict[str, list[dict]] = {}
        for label, domains in all_generated.items():
            results = [enrichment_cache[d] for d in domains
                       if d in enrichment_cache]
            results.sort(key=lambda x: (not x["active"], x["domain"]))
            enriched[label] = ([d for d in results if d["active"]]
                               if cfg["active_only"] else results)

        unique_active = sum(1 for i in enrichment_cache.values() if i["active"])
        self._log(f"\n{unique_active} unique ACTIVE domain(s) found")

        # ── Baseline compare + save ────────────────────────────────────────
        delta = None
        if use_baseline:
            if previous_baseline:
                delta = ds.compare_with_baseline(enriched, previous_baseline)
                self._log(
                    f"Delta vs {delta['prev_scan']}: "
                    f"{len(delta['new'])} new, {len(delta['changed'])} changed, "
                    f"{len(delta['removed'])} removed, "
                    f"{len(delta['persistent'])} persistent")
            ds.save_baseline(enriched, full_domain, baseline_path,
                             previous_baseline)
            self._log(f"[+] Baseline saved: {baseline_path}")

        # ── Reports (relative paths resolved into the output folder) ────────
        saved: list[str] = []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_txt = _resolve_output(cfg["output"] or f"doppelsnare_{name}_{ts}.txt",
                                  outdir)
        ds.save_txt_report(all_generated, enriched, full_domain, out_txt)
        saved.append(f"Text report : {out_txt}")

        csv_path = _resolve_output(cfg["csv"], outdir)
        blocklist_path = _resolve_output(cfg["blocklist_csv"], outdir)
        delta_path = _resolve_output(cfg["delta_csv"], outdir)
        if csv_path:
            rows = ds.save_siem_csv(enriched, full_domain, csv_path,
                                    cfg["active_only"])
            saved.append(f"SIEM CSV    : {csv_path} ({rows} rows)")
        if blocklist_path:
            rows = ds.save_blocklist_csv(enriched, full_domain,
                                         blocklist_path, cfg["active_only"])
            saved.append(f"Blocklist   : {blocklist_path} ({rows} IOCs)")
        if delta_path and delta:
            rows = ds.save_delta_csv(delta, full_domain, delta_path)
            saved.append(f"Delta CSV   : {delta_path} ({rows} changes)")

        for line in saved:
            self._log(f"[+] {line}")

        self.q.put(("summary", (enriched, all_generated, delta, saved)))
        self._status(f"Done — {unique_active} active of {total} probed")


# ══════════════════════════════════════════════════════════════════════════════
#  RECON WORKER — deep-fingerprints active domains off the UI thread
# ══════════════════════════════════════════════════════════════════════════════

class ReconWorker(threading.Thread):
    """
    Runs the recon pipeline over a list of targets in the background.

    Targets are processed sequentially — matching the CLI, which paces
    VirusTotal calls between domains — with a live per-domain result streamed
    to the UI. recon_domain() prints its own step-by-step progress; that output
    is captured and discarded so it never leaks to the terminal.

    Messages are namespaced with a 'recon_' prefix so a single UI queue can
    carry both this worker's and ScanWorker's events without collision.
    """

    def __init__(self, config: dict, q: "queue.Queue", cancel: threading.Event):
        super().__init__(daemon=True)
        self.cfg = config
        self.q = q
        self.cancel = cancel

    def _log(self, msg: str) -> None:
        self.q.put(("recon_log", msg))

    def _status(self, msg: str) -> None:
        self.q.put(("recon_status", msg))

    def run(self) -> None:
        try:
            self._run()
        except Exception as exc:
            self.q.put(("recon_error", f"{type(exc).__name__}: {exc}"))
        finally:
            self.q.put(("recon_done", None))

    def _run(self) -> None:
        cfg = self.cfg
        targets = cfg["targets"]
        outdir = cfg["outdir"]

        if not recon.HAS_REQUESTS:
            self._log("[!] requests not installed — HTTP fingerprinting disabled "
                      "(pip install requests)")
        if not recon.HAS_DNS:
            self._log("[!] dnspython not installed — email-security checks disabled")
        if cfg["screenshots"] and not recon.HAS_PLAYWRIGHT:
            self._log("[!] playwright not installed — screenshots disabled "
                      "(pip install playwright && playwright install chromium)")
            cfg["screenshots"] = None
        # Resolve the screenshot directory into the output folder if relative.
        cfg["screenshots"] = _resolve_output(cfg["screenshots"], outdir)

        total = len(targets)
        self._log(f"Reconnaissance on {total} domain(s)"
                  + (f", brand keywords: {', '.join(cfg['brand_keywords'])}"
                     if cfg["brand_keywords"] else ""))
        self.q.put(("recon_progress", (0, total)))

        use_vt = bool(cfg["vt_key"])
        results: list[dict] = []

        for idx, target in enumerate(targets):
            if self.cancel.is_set():
                self._log("Cancelled.")
                break

            domain = target["domain"]
            self._status(f"Scanning {idx + 1}/{total}: {domain}")

            # recon_domain prints a running commentary; swallow it.
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    result = recon.recon_domain(
                        domain=domain,
                        detection_type=target.get("detection_type", "Manual"),
                        known_ips=target.get("ip_addresses", []),
                        screenshot_dir=cfg["screenshots"],
                        vt_key=cfg["vt_key"],
                        abuseipdb_key=cfg["abuseipdb_key"],
                        brand_keywords=cfg["brand_keywords"],
                    )
            except Exception as exc:
                self._log(f"  {domain}: recon failed — {type(exc).__name__}: {exc}")
                self.q.put(("recon_progress", (idx + 1, total)))
                continue

            results.append(result)
            self.q.put(("recon_hit", result))
            self.q.put(("recon_progress", (idx + 1, total)))
            self._log(f"  {domain}: {result['risk_label']} "
                      f"({result['risk_score']}/100)")

            # VirusTotal free-tier pacing: sleep between calls, never after the
            # last domain, and bail out early if cancelled during the wait.
            if use_vt and cfg["vt_delay"] > 0 and idx < total - 1:
                self._status(f"Waiting {cfg['vt_delay']:.0f}s (VirusTotal pacing)…")
                if self.cancel.wait(cfg["vt_delay"]):
                    self._log("Cancelled.")
                    break

        if not results:
            self._status("No results.")
            return

        # ── Save reports (relative paths resolved into the output folder) ───
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        saved: list[str] = []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        json_path = _resolve_output(cfg["json"] or f"recon_report_{ts}.json",
                                    outdir)
        recon.save_json_report(results, json_path)
        saved.append(f"JSON report : {json_path}")
        report_csv = _resolve_output(cfg["report_csv"], outdir)
        html_path = _resolve_output(cfg["html"], outdir)
        if report_csv:
            recon.save_csv_summary(results, report_csv)
            saved.append(f"CSV summary : {report_csv}")
        if html_path:
            recon.save_html_report(results, html_path)
            saved.append(f"HTML report : {html_path}")
        for line in saved:
            self._log(f"[+] {line}")

        crit = sum(1 for r in results if r["risk_label"] == "CRITICAL")
        high = sum(1 for r in results if r["risk_label"] == "HIGH")
        self._status(f"Done — {len(results)} scanned "
                     f"({crit} critical, {high} high)")


# ══════════════════════════════════════════════════════════════════════════════
#  APPLICATION WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class DoppelSnareGUI(tk.Tk):

    RESULT_COLS = [
        ("type",      "Type",       120),
        ("domain",    "Domain",     260),
        ("ips",       "IP(s)",      160),
        ("mx",        "MX",          50),
        ("registrar", "Registrar",  180),
        ("created",   "Created",    110),
    ]

    RECON_COLS = [
        ("risk",   "Risk",   55),
        ("label",  "Tier",   85),
        ("domain", "Domain", 240),
        ("login",  "Login",  55),
        ("ca",     "CA risk", 110),
        ("ports",  "Ports",  120),
        ("assess", "Email assessment", 260),
    ]

    def __init__(self):
        super().__init__()
        self.title("DoppelSnare — Lookalike Domain Detection")
        self.geometry("1120x760")
        self.minsize(920, 600)

        self.q: "queue.Queue" = queue.Queue()

        # Detection scan state
        self.cancel = threading.Event()
        self.worker: ScanWorker | None = None
        self._active_count = 0
        # Active domains from the most recent detection scan — fed to recon.
        self.detection_active_targets: list[dict] = []

        # Recon state
        self.recon_cancel = threading.Event()
        self.recon_worker: ReconWorker | None = None
        self._recon_count = 0

        self._build_style()
        self._build_layout()
        self._populate_keyword_files()
        self._refresh_recon_source_state()
        self.after(100, self._poll_queue)

    # -- styling ------------------------------------------------------------
    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24)
        style.configure("Heading.TLabel", font=("Helvetica", 11, "bold"))
        style.configure("Run.TButton", font=("Helvetica", 11, "bold"))

    # -- layout -------------------------------------------------------------
    def _build_layout(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        detection = ttk.Frame(nb, padding=(4, 6))
        recon_tab = ttk.Frame(nb, padding=(4, 6))
        nb.add(detection, text="  Detection  ")
        nb.add(recon_tab, text="  Recon  ")

        # Detection tab: config panel + results panel side by side.
        outer = ttk.Panedwindow(detection, orient="horizontal")
        outer.pack(fill="both", expand=True)
        left = ttk.Frame(outer, padding=(4, 4))
        right = ttk.Frame(outer, padding=(4, 4))
        outer.add(left, weight=0)
        outer.add(right, weight=1)
        self._build_config_panel(left)
        self._build_results_panel(right)

        self._build_recon_tab(recon_tab)

    def _build_config_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Scan configuration",
                  style="Heading.TLabel").grid(row=0, column=0, columnspan=3,
                                               sticky="w", pady=(0, 8))
        r = 1

        # Domain
        ttk.Label(parent, text="Target domain").grid(row=r, column=0,
                                                     sticky="w")
        r += 1
        self.var_domain = tk.StringVar()
        ent = ttk.Entry(parent, textvariable=self.var_domain, width=34)
        ent.grid(row=r, column=0, columnspan=3, sticky="we", pady=(0, 8))
        ent.focus_set()
        r += 1

        # Keyword file
        ttk.Label(parent, text="Keyword list").grid(row=r, column=0, sticky="w")
        r += 1
        self.var_keywords = tk.StringVar(value="keywords.txt")
        self.cmb_keywords = ttk.Combobox(parent, textvariable=self.var_keywords,
                                         width=28)
        self.cmb_keywords.grid(row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=self._browse_keywords).grid(row=r, column=2,
                                                       sticky="e")
        r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # Allowlist
        ttk.Label(parent, text="Allowlist (known-good)").grid(row=r, column=0,
                                                             sticky="w")
        r += 1
        self.var_allowlist = tk.StringVar()
        ttk.Entry(parent, textvariable=self.var_allowlist, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=self._browse_allowlist).grid(row=r, column=2,
                                                       sticky="e")
        r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # Detection types
        ttk.Label(parent, text="Detection types").grid(row=r, column=0,
                                                       sticky="w")
        r += 1
        self.type_vars: dict[str, tk.BooleanVar] = {}
        for label, _key in DETECTION_TYPES:
            v = tk.BooleanVar(value=True)
            self.type_vars[label] = v
            ttk.Checkbutton(parent, text=label, variable=v).grid(
                row=r, column=0, columnspan=3, sticky="w")
            r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # Toggles
        self.var_active_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Active (resolving) domains only",
                        variable=self.var_active_only).grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.var_no_enrich = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Skip DNS/WHOIS (generate only)",
                        variable=self.var_no_enrich).grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1

        # Threads
        tf = ttk.Frame(parent)
        tf.grid(row=r, column=0, columnspan=3, sticky="w", pady=(4, 8))
        ttk.Label(tf, text="DNS threads").pack(side="left")
        self.var_threads = tk.IntVar(value=15)
        ttk.Spinbox(tf, from_=1, to=100, width=5,
                    textvariable=self.var_threads).pack(side="left", padx=6)
        r += 1

        # Baseline
        self.var_use_baseline = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="Track changes (baseline)",
                        variable=self.var_use_baseline).grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.var_baseline = tk.StringVar(value="doppelsnare_baseline.json")
        ttk.Entry(parent, textvariable=self.var_baseline, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=self._browse_baseline).grid(row=r, column=2,
                                                      sticky="e")
        r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # Optional CSV outputs
        ttk.Label(parent, text="Optional exports").grid(row=r, column=0,
                                                       sticky="w")
        r += 1
        self.var_csv = tk.StringVar()
        self.var_blocklist = tk.StringVar()
        self.var_delta = tk.StringVar()
        for lbl, var in (("SIEM lookup CSV", self.var_csv),
                         ("Blocklist CSV", self.var_blocklist),
                         ("Delta CSV", self.var_delta)):
            ttk.Label(parent, text=lbl, font=("Helvetica", 9)).grid(
                row=r, column=0, columnspan=3, sticky="w")
            r += 1
            ttk.Entry(parent, textvariable=var, width=28).grid(
                row=r, column=0, columnspan=2, sticky="we")
            ttk.Button(parent, text="…", width=3,
                       command=lambda v=var: self._browse_save(v)).grid(
                row=r, column=2, sticky="e")
            r += 1

        # Output folder — where reports/baseline are written (relative paths
        # and auto-named files land here). Defaults to the app directory.
        ttk.Label(parent, text="Output folder").grid(row=r, column=0, sticky="w",
                                                     pady=(6, 0))
        r += 1
        self.var_outdir = tk.StringVar(value=APP_DIR)
        ttk.Entry(parent, textvariable=self.var_outdir, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=lambda: self._browse_outdir(self.var_outdir)).grid(
            row=r, column=2, sticky="e")
        r += 1

        ttk.Frame(parent, height=10).grid(row=r, column=0)
        r += 1

        # Run / Cancel
        btns = ttk.Frame(parent)
        btns.grid(row=r, column=0, columnspan=3, sticky="we", pady=(4, 0))
        self.btn_run = ttk.Button(btns, text="▶  Run scan", style="Run.TButton",
                                  command=self._start_scan)
        self.btn_run.pack(side="left")
        self.btn_cancel = ttk.Button(btns, text="Cancel", state="disabled",
                                     command=self._cancel_scan)
        self.btn_cancel.pack(side="left", padx=6)

        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)

    def _build_results_panel(self, parent: ttk.Frame) -> None:
        # Header row: title + counters
        head = ttk.Frame(parent)
        head.pack(fill="x")
        ttk.Label(head, text="Active lookalike domains",
                  style="Heading.TLabel").pack(side="left")
        self.var_count = tk.StringVar(value="0 active")
        ttk.Label(head, textvariable=self.var_count).pack(side="right")

        # Results tree
        tree_wrap = ttk.Frame(parent)
        tree_wrap.pack(fill="both", expand=True, pady=(6, 6))
        cols = [c[0] for c in self.RESULT_COLS]
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings",
                                 selectmode="browse")
        for key, heading, width in self.RESULT_COLS:
            self.tree.heading(key, text=heading)
            anchor = "center" if key == "mx" else "w"
            self.tree.column(key, width=width, anchor=anchor,
                             stretch=(key == "domain"))
        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)
        self.tree.tag_configure("mx", background="#3a1f1f", foreground="#ffd7d7")
        self.tree.bind("<Double-1>", self._copy_selected_domain)

        # Progress bar + status
        prog = ttk.Frame(parent)
        prog.pack(fill="x")
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True)
        self.var_status = tk.StringVar(value="Ready.")
        ttk.Label(prog, textvariable=self.var_status, width=28,
                  anchor="e").pack(side="right", padx=(8, 0))

        # Log console
        ttk.Label(parent, text="Log").pack(anchor="w", pady=(8, 2))
        log_wrap = ttk.Frame(parent)
        log_wrap.pack(fill="both", expand=False)
        self.log = tk.Text(log_wrap, height=10, wrap="word",
                           background="#111417", foreground="#d6dde3",
                           insertbackground="#d6dde3", font=("Menlo", 10))
        lsb = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set, state="disabled")
        self.log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")

    # -- keyword file discovery --------------------------------------------
    def _populate_keyword_files(self) -> None:
        here = os.path.dirname(os.path.abspath(__file__))
        choices: list[str] = []
        if os.path.isfile(os.path.join(here, "keywords.txt")):
            choices.append("keywords.txt")
        kdir = os.path.join(here, "keywords")
        if os.path.isdir(kdir):
            for fn in sorted(os.listdir(kdir)):
                if fn.endswith(".txt"):
                    choices.append(os.path.join("keywords", fn))
        self.cmb_keywords["values"] = choices or ["keywords.txt"]

    # -- file pickers -------------------------------------------------------
    def _browse_keywords(self) -> None:
        p = filedialog.askopenfilename(title="Select keyword list",
                                       filetypes=[("Text", "*.txt"),
                                                  ("All", "*.*")])
        if p:
            self.var_keywords.set(p)

    def _browse_allowlist(self) -> None:
        p = filedialog.askopenfilename(title="Select allowlist",
                                       filetypes=[("Text", "*.txt"),
                                                  ("All", "*.*")])
        if p:
            self.var_allowlist.set(p)

    def _browse_baseline(self) -> None:
        p = filedialog.asksaveasfilename(title="Baseline JSON",
                                         defaultextension=".json",
                                         filetypes=[("JSON", "*.json")])
        if p:
            self.var_baseline.set(p)

    def _browse_save(self, var: tk.StringVar) -> None:
        p = filedialog.asksaveasfilename(title="Save CSV as",
                                         defaultextension=".csv",
                                         filetypes=[("CSV", "*.csv")])
        if p:
            var.set(p)

    def _browse_outdir(self, var: tk.StringVar) -> None:
        p = filedialog.askdirectory(title="Output folder")
        if p:
            var.set(p)

    def _copy_selected_domain(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        domain = self.tree.item(sel[0], "values")[1]
        self.clipboard_clear()
        self.clipboard_append(domain)
        self.var_status.set(f"Copied {domain}")

    # -- scan lifecycle -----------------------------------------------------
    def _collect_config(self) -> dict | None:
        domain = self.var_domain.get().strip()
        if not domain:
            messagebox.showwarning("Missing domain",
                                   "Enter a target domain to scan.")
            return None
        types = [lbl for lbl, _ in DETECTION_TYPES
                 if self.type_vars[lbl].get()]
        if not types:
            messagebox.showwarning("No detection types",
                                   "Select at least one detection type.")
            return None
        try:
            threads = max(1, int(self.var_threads.get()))
        except (tk.TclError, ValueError):
            threads = 15
        return {
            "domain":        domain,
            "keywords":      self.var_keywords.get().strip() or "keywords.txt",
            "allowlist":     self.var_allowlist.get().strip() or None,
            "types":         types,
            "active_only":   self.var_active_only.get(),
            "no_enrich":     self.var_no_enrich.get(),
            "threads":       threads,
            "use_baseline":  self.var_use_baseline.get(),
            "baseline":      self.var_baseline.get().strip()
                             or "doppelsnare_baseline.json",
            "output":        None,
            "csv":           self.var_csv.get().strip() or None,
            "blocklist_csv": self.var_blocklist.get().strip() or None,
            "delta_csv":     self.var_delta.get().strip() or None,
            "outdir":        self.var_outdir.get().strip() or APP_DIR,
        }

    def _start_scan(self) -> None:
        cfg = self._collect_config()
        if cfg is None:
            return
        # Reset UI state
        self.tree.delete(*self.tree.get_children())
        self._active_count = 0
        self.detection_active_targets = []
        self.var_count.set("0 active")
        self.progress.configure(value=0, maximum=100)
        self._clear_log()
        self.cancel.clear()
        self.btn_run.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self.var_status.set("Starting…")

        self.worker = ScanWorker(cfg, self.q, self.cancel)
        self.worker.start()

    def _cancel_scan(self) -> None:
        self.cancel.set()
        self.var_status.set("Cancelling…")
        self.btn_cancel.configure(state="disabled")

    # -- queue polling ------------------------------------------------------
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle(self, kind: str, payload) -> None:
        if kind == "log":
            self._append_log(payload)
        elif kind == "status":
            self.var_status.set(payload)
        elif kind == "progress":
            done, total = payload
            self.progress.configure(maximum=max(total, 1), value=done)
        elif kind == "active_hit":
            self._add_row(*payload)
        elif kind == "variants_only":
            self._show_variants(payload)
        elif kind == "summary":
            pass  # rows already streamed; files already logged
        elif kind == "error":
            self._append_log(f"[ERROR] {payload}")
            messagebox.showerror("Scan failed", payload)
        elif kind == "done":
            self.btn_run.configure(state="normal")
            self.btn_cancel.configure(state="disabled")
            self.worker = None
            self._refresh_recon_source_state()
        # ── Recon-tab events (namespaced) ────────────────────────────────
        elif kind == "recon_log":
            self._recon_append_log(payload)
        elif kind == "recon_status":
            self.recon_var_status.set(payload)
        elif kind == "recon_progress":
            done, total = payload
            self.recon_progress.configure(maximum=max(total, 1), value=done)
        elif kind == "recon_hit":
            self._add_recon_row(payload)
        elif kind == "recon_error":
            self._recon_append_log(f"[ERROR] {payload}")
            messagebox.showerror("Recon failed", payload)
        elif kind == "recon_done":
            self.recon_btn_run.configure(state="normal")
            self.recon_btn_cancel.configure(state="disabled")
            self.recon_worker = None

    # -- results rendering --------------------------------------------------
    def _add_row(self, types: str, info: dict) -> None:
        ips = ", ".join(info.get("ip_addresses", []))
        has_mx = "✉" if info.get("mail_servers") else ""
        created = (info.get("creation_date") or "")
        created = str(created)[:10] if created else ""
        registrar = info.get("registrar") or ""
        self.tree.insert("", "end",
                         values=(types, info["domain"], ips, has_mx,
                                 registrar, created),
                         tags=("mx",) if info.get("mail_servers") else ())
        self._active_count += 1
        self.var_count.set(f"{self._active_count} active")
        # Remember it as a candidate recon target (first category wins).
        self.detection_active_targets.append({
            "domain":         info["domain"],
            "detection_type": types.split(",")[0].strip(),
            "ip_addresses":   list(info.get("ip_addresses", [])),
        })

    def _show_variants(self, all_generated: dict[str, list[str]]) -> None:
        # No-enrich mode: list every generated variant (inactive-style rows).
        for label, domains in all_generated.items():
            for d in domains:
                self.tree.insert("", "end",
                                 values=(label, d, "", "", "", ""))
        total = sum(len(v) for v in all_generated.values())
        self.var_count.set(f"{total} variants")

    # -- log helpers --------------------------------------------------------
    def _append_log(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ══════════════════════════════════════════════════════════════════════
    #  RECON TAB
    # ══════════════════════════════════════════════════════════════════════

    def _build_recon_tab(self, parent: ttk.Frame) -> None:
        outer = ttk.Panedwindow(parent, orient="horizontal")
        outer.pack(fill="both", expand=True)
        cfg = ttk.Frame(outer, padding=(4, 4))
        res = ttk.Frame(outer, padding=(4, 4))
        outer.add(cfg, weight=0)
        outer.add(res, weight=1)

        self._build_recon_config(cfg)
        self._build_recon_results(res)

    def _build_recon_config(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Recon configuration",
                  style="Heading.TLabel").grid(row=0, column=0, columnspan=3,
                                               sticky="w", pady=(0, 8))
        r = 1

        # ── Target source ───────────────────────────────────────────────
        ttk.Label(parent, text="Targets").grid(row=r, column=0, sticky="w")
        r += 1
        self.recon_source = tk.StringVar(value="last")

        self.recon_rb_last = ttk.Radiobutton(
            parent, text="Active domains from last scan",
            variable=self.recon_source, value="last")
        self.recon_rb_last.grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1

        ttk.Radiobutton(parent, text="DoppelSnare baseline JSON",
                        variable=self.recon_source, value="baseline").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.recon_var_baseline = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_baseline, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=self._browse_recon_baseline).grid(row=r, column=2,
                                                             sticky="e")
        r += 1

        ttk.Radiobutton(parent, text="Domain file (one per line)",
                        variable=self.recon_source, value="file").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.recon_var_domainfile = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_domainfile, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=self._browse_recon_domainfile).grid(row=r, column=2,
                                                               sticky="e")
        r += 1

        ttk.Radiobutton(parent, text="Domains (comma-separated)",
                        variable=self.recon_source, value="domains").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.recon_var_domains = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_domains, width=32).grid(
            row=r, column=0, columnspan=3, sticky="we")
        r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # ── Detection options ───────────────────────────────────────────
        ttk.Label(parent, text="Brand keywords (comma-sep, optional)").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.recon_var_brand = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_brand, width=32).grid(
            row=r, column=0, columnspan=3, sticky="we")
        r += 1

        ttk.Label(parent, text="Screenshots directory (needs playwright)").grid(
            row=r, column=0, columnspan=3, sticky="w", pady=(6, 0))
        r += 1
        self.recon_var_screens = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_screens, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=self._browse_recon_screenshots).grid(row=r, column=2,
                                                                sticky="e")
        r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # ── Reputation APIs ─────────────────────────────────────────────
        ttk.Label(parent, text="VirusTotal API key (optional)").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        self.recon_var_vtkey = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_vtkey, width=32,
                  show="•").grid(row=r, column=0, columnspan=3, sticky="we")
        r += 1
        df = ttk.Frame(parent)
        df.grid(row=r, column=0, columnspan=3, sticky="w", pady=(2, 0))
        ttk.Label(df, text="VT delay (s)").pack(side="left")
        self.recon_var_vtdelay = tk.StringVar(value="15.5")
        ttk.Spinbox(df, from_=0, to=60, increment=0.5, width=6,
                    textvariable=self.recon_var_vtdelay).pack(side="left", padx=6)
        ttk.Label(df, text="(0 for paid keys)",
                  font=("Helvetica", 9)).pack(side="left")
        r += 1

        ttk.Label(parent, text="AbuseIPDB API key (optional)").grid(
            row=r, column=0, columnspan=3, sticky="w", pady=(6, 0))
        r += 1
        self.recon_var_abusekey = tk.StringVar()
        ttk.Entry(parent, textvariable=self.recon_var_abusekey, width=32,
                  show="•").grid(row=r, column=0, columnspan=3, sticky="we")
        r += 1
        ttk.Frame(parent, height=8).grid(row=r, column=0)
        r += 1

        # ── Optional report exports (JSON auto-named) ───────────────────
        ttk.Label(parent, text="Optional reports").grid(row=r, column=0,
                                                        sticky="w")
        r += 1
        self.recon_var_reportcsv = tk.StringVar()
        self.recon_var_html = tk.StringVar()
        for lbl, var, browse in (
            ("CSV summary", self.recon_var_reportcsv,
             lambda v=None: self._browse_recon_save(self.recon_var_reportcsv, ".csv")),
            ("HTML report", self.recon_var_html,
             lambda v=None: self._browse_recon_save(self.recon_var_html, ".html")),
        ):
            ttk.Label(parent, text=lbl, font=("Helvetica", 9)).grid(
                row=r, column=0, columnspan=3, sticky="w")
            r += 1
            ttk.Entry(parent, textvariable=var, width=28).grid(
                row=r, column=0, columnspan=2, sticky="we")
            ttk.Button(parent, text="…", width=3, command=browse).grid(
                row=r, column=2, sticky="e")
            r += 1

        # Output folder — where the JSON/CSV/HTML reports (and any relative
        # screenshots directory) are written. Defaults to the app directory.
        ttk.Label(parent, text="Output folder").grid(row=r, column=0, sticky="w",
                                                     pady=(6, 0))
        r += 1
        self.recon_var_outdir = tk.StringVar(value=APP_DIR)
        ttk.Entry(parent, textvariable=self.recon_var_outdir, width=28).grid(
            row=r, column=0, columnspan=2, sticky="we")
        ttk.Button(parent, text="…", width=3,
                   command=lambda: self._browse_outdir(self.recon_var_outdir)).grid(
            row=r, column=2, sticky="e")
        r += 1

        ttk.Frame(parent, height=10).grid(row=r, column=0)
        r += 1

        btns = ttk.Frame(parent)
        btns.grid(row=r, column=0, columnspan=3, sticky="we")
        self.recon_btn_run = ttk.Button(btns, text="▶  Run recon",
                                        style="Run.TButton",
                                        command=self._start_recon)
        self.recon_btn_run.pack(side="left")
        self.recon_btn_cancel = ttk.Button(btns, text="Cancel", state="disabled",
                                           command=self._cancel_recon)
        self.recon_btn_cancel.pack(side="left", padx=6)

        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)

    def _build_recon_results(self, parent: ttk.Frame) -> None:
        head = ttk.Frame(parent)
        head.pack(fill="x")
        ttk.Label(head, text="Recon findings",
                  style="Heading.TLabel").pack(side="left")
        self.recon_var_count = tk.StringVar(value="0 scanned")
        ttk.Label(head, textvariable=self.recon_var_count).pack(side="right")

        tree_wrap = ttk.Frame(parent)
        tree_wrap.pack(fill="both", expand=True, pady=(6, 6))
        cols = [c[0] for c in self.RECON_COLS]
        self.recon_tree = ttk.Treeview(tree_wrap, columns=cols,
                                       show="headings", selectmode="browse")
        for key, heading, width in self.RECON_COLS:
            self.recon_tree.heading(key, text=heading)
            anchor = "center" if key in ("risk", "login") else "w"
            self.recon_tree.column(key, width=width, anchor=anchor,
                                   stretch=(key in ("domain", "assess")))
        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",
                            command=self.recon_tree.yview)
        self.recon_tree.configure(yscrollcommand=vsb.set)
        self.recon_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)
        # Colour rows by risk tier.
        self.recon_tree.tag_configure("CRITICAL", background="#4a1414",
                                      foreground="#ffcaca")
        self.recon_tree.tag_configure("HIGH", background="#4a2f14",
                                      foreground="#ffe0c0")
        self.recon_tree.tag_configure("MEDIUM", background="#413f16",
                                      foreground="#f4efc0")
        self.recon_tree.tag_configure("LOW", background="#153f1f",
                                      foreground="#c8f0d2")
        self.recon_tree.bind("<Double-1>", self._copy_selected_recon_domain)

        prog = ttk.Frame(parent)
        prog.pack(fill="x")
        self.recon_progress = ttk.Progressbar(prog, mode="determinate")
        self.recon_progress.pack(side="left", fill="x", expand=True)
        self.recon_var_status = tk.StringVar(value="Ready.")
        ttk.Label(prog, textvariable=self.recon_var_status, width=30,
                  anchor="e").pack(side="right", padx=(8, 0))

        ttk.Label(parent, text="Log").pack(anchor="w", pady=(8, 2))
        log_wrap = ttk.Frame(parent)
        log_wrap.pack(fill="both", expand=False)
        self.recon_log = tk.Text(log_wrap, height=10, wrap="word",
                                 background="#111417", foreground="#d6dde3",
                                 insertbackground="#d6dde3", font=("Menlo", 10))
        lsb = ttk.Scrollbar(log_wrap, orient="vertical",
                            command=self.recon_log.yview)
        self.recon_log.configure(yscrollcommand=lsb.set, state="disabled")
        self.recon_log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")

    # -- recon file pickers -------------------------------------------------
    def _browse_recon_baseline(self) -> None:
        p = filedialog.askopenfilename(title="Select baseline JSON",
                                       filetypes=[("JSON", "*.json"),
                                                  ("All", "*.*")])
        if p:
            self.recon_var_baseline.set(p)
            self.recon_source.set("baseline")

    def _browse_recon_domainfile(self) -> None:
        p = filedialog.askopenfilename(title="Select domain file",
                                       filetypes=[("Text", "*.txt"),
                                                  ("All", "*.*")])
        if p:
            self.recon_var_domainfile.set(p)
            self.recon_source.set("file")

    def _browse_recon_screenshots(self) -> None:
        p = filedialog.askdirectory(title="Screenshots output directory")
        if p:
            self.recon_var_screens.set(p)

    def _browse_recon_save(self, var: tk.StringVar, ext: str) -> None:
        p = filedialog.asksaveasfilename(title="Save report as",
                                         defaultextension=ext)
        if p:
            var.set(p)

    def _copy_selected_recon_domain(self, _event=None) -> None:
        sel = self.recon_tree.selection()
        if not sel:
            return
        domain = self.recon_tree.item(sel[0], "values")[2]
        self.clipboard_clear()
        self.clipboard_append(domain)
        self.recon_var_status.set(f"Copied {domain}")

    # -- recon source state -------------------------------------------------
    def _refresh_recon_source_state(self) -> None:
        n = len(self.detection_active_targets)
        self.recon_rb_last.configure(
            text=f"Active domains from last scan ({n})")

    # -- recon config -------------------------------------------------------
    def _collect_recon_config(self) -> dict | None:
        source = self.recon_source.get()
        targets: list[dict] = []
        try:
            if source == "last":
                targets = list(self.detection_active_targets)
                if not targets:
                    messagebox.showwarning(
                        "No targets",
                        "No active domains from the last scan yet.\n"
                        "Run a Detection scan first, or choose another source.")
                    return None
            elif source == "baseline":
                path = self.recon_var_baseline.get().strip()
                if not path:
                    messagebox.showwarning("No baseline",
                                           "Choose a baseline JSON file.")
                    return None
                targets = recon.load_targets_from_baseline(path)
            elif source == "file":
                path = self.recon_var_domainfile.get().strip()
                if not path:
                    messagebox.showwarning("No file",
                                           "Choose a domain file.")
                    return None
                targets = recon.load_targets_from_file(path)
            elif source == "domains":
                raw = self.recon_var_domains.get().strip()
                if not raw:
                    messagebox.showwarning("No domains",
                                           "Enter one or more domains.")
                    return None
                targets = recon.load_targets_from_domains(raw)
        except Exception as exc:
            messagebox.showerror("Could not load targets",
                                 f"{type(exc).__name__}: {exc}")
            return None

        if not targets:
            messagebox.showwarning("No targets",
                                   "The selected source produced no domains.")
            return None

        try:
            vt_delay = max(0.0, float(self.recon_var_vtdelay.get()))
        except (tk.TclError, ValueError):
            vt_delay = 15.5

        brand = [w.strip() for w in self.recon_var_brand.get().split(",")
                 if w.strip()]

        return {
            "targets":        targets,
            "brand_keywords": brand,
            "screenshots":    self.recon_var_screens.get().strip() or None,
            "vt_key":         self.recon_var_vtkey.get().strip(),
            "vt_delay":       vt_delay,
            "abuseipdb_key":  self.recon_var_abusekey.get().strip(),
            "json":           None,
            "report_csv":     self.recon_var_reportcsv.get().strip() or None,
            "html":           self.recon_var_html.get().strip() or None,
            "outdir":         self.recon_var_outdir.get().strip() or APP_DIR,
        }

    def _start_recon(self) -> None:
        cfg = self._collect_recon_config()
        if cfg is None:
            return
        self.recon_tree.delete(*self.recon_tree.get_children())
        self._recon_count = 0
        self.recon_var_count.set("0 scanned")
        self.recon_progress.configure(value=0, maximum=max(len(cfg["targets"]), 1))
        self._recon_clear_log()
        self.recon_cancel.clear()
        self.recon_btn_run.configure(state="disabled")
        self.recon_btn_cancel.configure(state="normal")
        self.recon_var_status.set("Starting…")

        self.recon_worker = ReconWorker(cfg, self.q, self.recon_cancel)
        self.recon_worker.start()

    def _cancel_recon(self) -> None:
        self.recon_cancel.set()
        self.recon_var_status.set("Cancelling…")
        self.recon_btn_cancel.configure(state="disabled")

    # -- recon results rendering -------------------------------------------
    def _add_recon_row(self, r: dict) -> None:
        http = r.get("http", {})
        tls = r.get("tls", {})
        login = "⚠" if http.get("has_login_form") else ""
        ca = tls.get("ca_risk") or ""
        ports = ", ".join(str(p["port"]) for p in r.get("ports", []))
        assess = (r.get("email_security", {}).get("assessment") or "")[:60]
        label = r["risk_label"]
        self.recon_tree.insert(
            "", "end",
            values=(r["risk_score"], label, r["domain"], login, ca,
                    ports, assess),
            tags=(label,))
        self._recon_count += 1
        self.recon_var_count.set(f"{self._recon_count} scanned")

    # -- recon log ----------------------------------------------------------
    def _recon_append_log(self, msg: str) -> None:
        self.recon_log.configure(state="normal")
        self.recon_log.insert("end", msg + "\n")
        self.recon_log.see("end")
        self.recon_log.configure(state="disabled")

    def _recon_clear_log(self) -> None:
        self.recon_log.configure(state="normal")
        self.recon_log.delete("1.0", "end")
        self.recon_log.configure(state="disabled")


def main() -> None:
    app = DoppelSnareGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
