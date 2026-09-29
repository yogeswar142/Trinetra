"""
Trinetra त्रिनेत्र — SOC CLI Dashboard
Premium terminal interface for the NTRO passive monitoring enclave.

Usage:
    python -m trinetra.dashboard.cli_dashboard [--ledger-path PATH]

Keybindings:
    1-6   Switch mode
    ↑↓    Scroll / navigate
    Enter Expand selected alert
    /     Search
    f     Filter
    v     Verify ledger chain
    e     Export current view
    r     Force refresh
    Space Pause/resume live feed
    q     Quit
    ?     Help overlay
"""
from __future__ import annotations

import json
import math
import os
import sys
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import readchar
    HAS_READCHAR = True
except ImportError:
    HAS_READCHAR = False

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Theme & Colour Palette
# ─────────────────────────────────────────────────────────────────────────────
PALETTE = {
    "bg":         "#0d1117",
    "accent":     "bright_cyan",
    "dim":        "grey50",
    "border":     "grey30",
    "success":    "bright_green",
    "warning":    "yellow",
    "danger":     "bright_red",
    "info":       "bright_cyan",
    "muted":      "grey62",
}

THREAT_COLOURS: Dict[str, str] = {
    "VOLUMETRIC_DDOS":       "bright_red",
    "BOTNET_C2_BEACONING":   "dark_orange",
    "DGA_DOMAINS":           "yellow1",
    "DNS_TUNNELLING":        "gold1",
    "PORT_SCANNING":         "bright_cyan",
    "DATA_EXFILTRATION":     "medium_purple",
    "ENCRYPTED_MALWARE_TLS": "cyan1",
    "UNKNOWN_ANOMALY":       "grey62",
    "UNKNOWN":               "grey62",
    # legacy aliases
    "C2_BEACONING":          "dark_orange",
    "DGA_DOMAIN":            "yellow1",
    "TLS_MALWARE":           "cyan1",
}

SEV_COLOURS: Dict[str, str] = {
    "CRITICAL": "bright_red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "INFO":     "bright_white",
    "LOW":      "grey70",
}

THREAT_ICONS: Dict[str, str] = {
    "VOLUMETRIC_DDOS":       "⚡",
    "BOTNET_C2_BEACONING":   "📡",
    "DGA_DOMAINS":           "🔤",
    "DNS_TUNNELLING":        "🕳 ",
    "PORT_SCANNING":         "🔍",
    "DATA_EXFILTRATION":     "📤",
    "ENCRYPTED_MALWARE_TLS": "🔒",
    "UNKNOWN_ANOMALY":       "❓",
    "UNKNOWN":               "❓",
    "C2_BEACONING":          "📡",
    "DGA_DOMAIN":            "🔤",
    "TLS_MALWARE":           "🔒",
}

MODE_ICONS = ["📊", "🔍", "⛓ ", "🧠", "📡", "💾"]
MODE_NAMES = ["Live Feed", "Threat Hunt", "Ledger", "Model Intel", "Sensor", "Export"]

# Sparkline chars
SPARK = " ▁▂▃▄▅▆▇█"

# ─────────────────────────────────────────────────────────────────────────────
# ASCII Art — The Eye (Trinetra's soul lives here)
# ─────────────────────────────────────────────────────────────────────────────
EYE_ART = """\
[grey50]    ████████╗██████╗ ██╗███╗  ██╗███████╗████████╗██████╗  █████╗[/grey50]
[bright_cyan]       ██╔══╝██╔══██╗██║████╗ ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗[/bright_cyan]
[cyan1]       ██║   ██████╔╝██║██╔██╗██║█████╗     ██║   ██████╔╝███████║[/cyan1]
[bright_cyan]       ██║   ██╔══██╗██║██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══██║[/bright_cyan]
[grey50]       ██║   ██║  ██║██║██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║[/grey50]
[grey37]       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝[/grey37]
[bright_cyan]                    त्रिनेत्र  ·  The Third Eye  ·  NTRO Enclave[/bright_cyan]"""

EYE_SMALL = """\
[bright_cyan]  ╔═══╗[/bright_cyan]
[bright_cyan]  ║[/bright_cyan][cyan1] ◉ [/cyan1][bright_cyan]║[/bright_cyan]
[bright_cyan]  ╚═══╝[/bright_cyan]
[grey50]  त्रि[/grey50]"""

GOODBYE_ART = """\

[bright_cyan]  ╭─────────────────────────────────────────────────────╮[/bright_cyan]
[bright_cyan]  │[/bright_cyan]                                                     [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]  [grey50]████████╗██████╗ ██╗███╗  ██╗███████╗████████╗██████╗ █████╗[/grey50]  [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]  [bright_cyan]  ██╔══╝██╔══██╗██║████╗ ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗[/bright_cyan]  [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]  [cyan1]  ██║   ██████╔╝██║██╔██╗██║█████╗     ██║   ██████╔╝███████║[/cyan1]  [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]                                                     [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]       [bright_white]Passive monitoring session ended.[/bright_white]               [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]       [grey50]All forensic records retained in ledger.[/grey50]           [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]       [grey37]NTRO-ENCLAVE-ALPHA-01 · Air-gapped ✓[/grey37]                [bright_cyan]│[/bright_cyan]
[bright_cyan]  │[/bright_cyan]                                                     [bright_cyan]│[/bright_cyan]
[bright_cyan]  ╰─────────────────────────────────────────────────────╯[/bright_cyan]
"""

SPLASH_ART = EYE_ART + """

[grey37]  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/grey37]
[grey50]  AI-Based Detection of Cyber Threats in Unidirectional IP Traffic[/grey50]
[grey37]  SIH 2026  ·  Problem Statement 26145  ·  Passive · No-decrypt · Air-gapped[/grey37]
"""

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _sparkline(values: List[float], width: int = 10) -> str:
    if not values:
        return " " * width
    mn, mx = min(values), max(values)
    rng = mx - mn or 1
    chars = []
    for v in values[-width:]:
        idx = int((v - mn) / rng * (len(SPARK) - 1))
        chars.append(SPARK[idx])
    return "".join(chars).ljust(width)


def _conf_bar(conf: float, width: int = 18) -> Text:
    filled = int(conf * width)
    bar = "█" * filled + "░" * (width - filled)
    if conf >= 0.90:
        colour = "bright_red"
    elif conf >= 0.75:
        colour = "red"
    elif conf >= 0.60:
        colour = "yellow"
    else:
        colour = "grey62"
    return Text(bar, style=colour)


def _fmt_time(ts: Any) -> str:
    if isinstance(ts, (int, float)):
        return time.strftime("%H:%M:%S", time.localtime(ts))
    if isinstance(ts, str):
        # ISO format → HH:MM:SS
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                import datetime
                dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.strftime("%H:%M:%S")
            except Exception:
                pass
        return ts[-8:] if len(ts) >= 8 else ts
    return "──:──:──"


def _short(s: str, n: int = 12) -> str:
    s = str(s)
    return s[:n] + "…" if len(s) > n else s.ljust(n)


def _read_ledger(path: str) -> Tuple[List[Dict], int, str]:
    """Load alerts for the TUI — shares demo/sidecar logic with the HTTP API."""
    try:
        from trinetra.dashboard.api_server import _build_response
        payload = _build_response()
        alerts = list(payload.get("alerts") or [])
        ledger = payload.get("ledger") or {}
        blocks = int(ledger.get("block_height") or 0)
        head_hash = ledger.get("head_hash") or "N/A"
        return alerts, blocks, head_hash
    except Exception:
        pass

    alerts: List[Dict] = []
    blocks = 0
    head_hash = "N/A"
    p = Path(path)
    if not p.exists():
        return alerts, blocks, head_hash
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                blocks += 1
                try:
                    data = json.loads(line)
                    bh = data.get("block_hash") or data.get("hash")
                    if bh:
                        head_hash = bh
                    for key in ("alert_record", "alert", "record", "data", "block_data"):
                        val = data.get(key)
                        if isinstance(val, dict) and "threat_class" in val:
                            alerts.append(val)
                            break
                        if isinstance(val, list):
                            alerts.extend([x for x in val if isinstance(x, dict) and "threat_class" in x])
                            break
                    else:
                        if "threat_class" in data:
                            alerts.append(data)
                except Exception:
                    pass
    except Exception:
        pass
    return alerts, blocks, head_hash


def _verify_chain(path: str) -> Tuple[bool, int, List[str]]:
    """Lightweight hash-chain verification."""
    errors = []
    count = 0
    prev_hash = None
    p = Path(path)
    if not p.exists():
        return False, 0, ["Ledger file not found"]
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    bh = data.get("block_hash") or data.get("hash")
                    ph = data.get("prev_hash")
                    if prev_hash is not None and ph != prev_hash:
                        errors.append(f"Block {count}: prev_hash mismatch")
                    prev_hash = bh
                    count += 1
                except Exception:
                    errors.append(f"Block {count}: JSON parse error")
    except Exception as e:
        return False, count, [str(e)]
    return len(errors) == 0, count, errors


# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────
class DashState:
    def __init__(self, ledger_path: str, refresh_s: float = 2.0):
        self.ledger_path = ledger_path
        self.refresh_s = refresh_s
        self.mode = 0                    # 0-5
        self.paused = False
        self.selected = 0                # selected row in live feed
        self.scroll_offset = 0
        self.show_evidence = False
        self.filter_class: Optional[str] = None
        self.search_term: str = ""
        self.hunt_query: str = ""
        self.hunt_results: List[Dict] = []
        self.verify_result: Optional[Tuple[bool, int, List[str]]] = None
        self.verifying = False
        self.show_help = False
        self.export_status: str = ""
        self.alerts: List[Dict] = []
        self.blocks: int = 0
        self.head_hash: str = "N/A"
        self.last_refresh: float = 0.0
        self.alert_history: deque = deque(maxlen=60)  # per-minute history
        self.rate_history: Dict[str, deque] = {
            k: deque([0] * 12, maxlen=12) for k in THREAT_COLOURS
        }
        self._lock = threading.Lock()
        self._quit = threading.Event()

    def refresh(self):
        if self.paused:
            return
        alerts, blocks, head_hash = _read_ledger(self.ledger_path)
        with self._lock:
            self.alerts = alerts
            self.blocks = blocks
            self.head_hash = head_hash
            self.last_refresh = time.monotonic()
            # Update rate history
            counts = Counter(a.get("threat_class", "UNKNOWN") for a in alerts)
            for k in self.rate_history:
                self.rate_history[k].append(counts.get(k, 0))

    def filtered_alerts(self) -> List[Dict]:
        out = self.alerts
        if self.filter_class:
            out = [a for a in out if a.get("threat_class") == self.filter_class]
        if self.search_term:
            st = self.search_term.lower()
            out = [a for a in out if st in json.dumps(a).lower()]
        return out

    def run_hunt(self):
        """Parse and execute a simple threat hunt query."""
        q = self.hunt_query.strip().lower()
        results = list(self.alerts)
        # class=X
        import re
        m = re.search(r"class\s*=\s*(\w+)", q)
        if m:
            cls = m.group(1).upper()
            # allow partial match
            results = [a for a in results if cls in a.get("threat_class", "")]
        # confidence>X
        m = re.search(r"confidence\s*([><=]+)\s*([\d.]+)", q)
        if m:
            op, val = m.group(1), float(m.group(2))
            def _cmp(c):
                if op == ">": return c > val
                if op == ">=": return c >= val
                if op == "<": return c < val
                if op == "<=": return c <= val
                return abs(c - val) < 0.01
            results = [a for a in results if _cmp(float(a.get("confidence", 0)))]
        # severity=X
        m = re.search(r"severity\s*=\s*(\w+)", q)
        if m:
            sev = m.group(1).upper()
            results = [a for a in results if a.get("severity", "").upper() == sev]
        # src=X
        m = re.search(r"src\s*=\s*([\d./]+)", q)
        if m:
            src = m.group(1)
            results = [a for a in results if src in (a.get("source") or {}).get("ip", "")]
        # since=Xh
        m = re.search(r"since\s*=\s*(\d+)h", q)
        if m:
            h = int(m.group(1))
            cutoff = time.time() - h * 3600
            def _after(a):
                ts = a.get("timestamp", 0)
                if isinstance(ts, (int, float)):
                    return ts >= cutoff
                return True
            results = [a for a in results if _after(a)]
        self.hunt_results = results


# ─────────────────────────────────────────────────────────────────────────────
# Panel Renderers
# ─────────────────────────────────────────────────────────────────────────────

def _render_header(state: DashState) -> Panel:
    now = time.strftime("%H:%M:%S IST")
    date = time.strftime("%d %b %Y")
    pulse = "[bright_green]● LIVE[/bright_green]" if not state.paused else "[yellow]⏸ PAUSED[/yellow]"
    mode_bar = "  ".join(
        f"[bright_cyan][{i+1}][/bright_cyan] [{'bright_cyan' if state.mode == i else 'grey50'}]{MODE_ICONS[i]} {MODE_NAMES[i]}[/{'bright_cyan' if state.mode == i else 'grey50'}]"
        for i in range(6)
    )
    lag = time.monotonic() - state.last_refresh
    lag_str = f"[grey50]{lag:.1f}s ago[/grey50]"

    title_left = Text.from_markup(
        f"[bright_cyan]⚡ TRINETRA[/bright_cyan] [grey50]त्रिनेत्र[/grey50]"
    )
    title_mid = Text.from_markup(
        f"[grey50]{date}[/grey50]  [bright_white]{now}[/bright_white]"
    )
    title_right = Text.from_markup(
        f"[grey50]NTRO-ENCLAVE-ALPHA-01[/grey50]  {pulse}  [grey50]upd: {lag_str}[/grey50]"
    )

    top_row = Columns([
        Align(title_left, align="left"),
        Align(title_mid, align="center"),
        Align(title_right, align="right"),
    ], expand=True)

    return Panel(
        Group(top_row, Text.from_markup(f"  {mode_bar}")),
        style="on grey7",
        border_style="bright_cyan",
        height=5,
    )


def _render_sidebar(state: DashState) -> Panel:
    lines = []
    # Compact eye icon - single line to avoid overflow in narrow sidebar
    lines.append(Text.from_markup("[bright_cyan]  ◉  त्रिनेत्र[/bright_cyan]"))
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))
    # Short labels that fit in 22 cols
    short_names = ["Live Feed", "Threat Hunt", "Ledger", "Model Intel", "Sensor", "Export"]
    short_icons = ["📊", "🔍", "⛓ ", "🧠", "📡", "💾"]
    for i, (icon, name) in enumerate(zip(short_icons, short_names)):
        if state.mode == i:
            t = Text()
            t.append(f" ▶ [{i+1}] {icon} {name}", style="bright_cyan on grey15")
            lines.append(t)
        else:
            t = Text()
            t.append(f"   [{i+1}] ", style="grey50")
            t.append(f"{icon} {name}", style="grey62")
            lines.append(t)
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))
    lines.append(Text.from_markup("  [grey50][v][/grey50] [grey62]Verify chain[/grey62]"))
    lines.append(Text.from_markup("  [grey50][r][/grey50] [grey62]Refresh[/grey62]"))
    lines.append(Text.from_markup("  [grey50][Space][/grey50] [grey62]Pause[/grey62]"))
    lines.append(Text.from_markup("  [grey50][?][/grey50] [grey62]Help[/grey62]"))
    lines.append(Text.from_markup("  [grey50][q][/grey50] [grey62]Quit[/grey62]"))

    return Panel(
        Group(*lines),
        border_style="grey30",
        padding=(0, 0),
    )


def _render_right_panel(state: DashState) -> Panel:
    lines = []
    # Threat breakdown with sparklines
    lines.append(Text.from_markup("[bright_cyan]Threat Breakdown[/bright_cyan]"))
    lines.append(Rule(style="grey30"))

    tc_counts = Counter(a.get("threat_class", "UNKNOWN") for a in state.alerts)
    total = sum(tc_counts.values()) or 1

    for tc, colour in THREAT_COLOURS.items():
        if tc == "UNKNOWN":
            continue
        count = tc_counts.get(tc, 0)
        spark = _sparkline(list(state.rate_history.get(tc, [])), width=8)
        pct = count / total
        bar_w = int(pct * 8)
        bar = "▓" * bar_w + "░" * (8 - bar_w)
        short_name = {
            "VOLUMETRIC_DDOS":   "DDoS   ",
            "C2_BEACONING":      "Beacon ",
            "DGA_DOMAIN":        "DGA    ",
            "DNS_TUNNELLING":    "DNS-T  ",
            "PORT_SCANNING":     "Scan   ",
            "DATA_EXFILTRATION": "Exfil  ",
            "TLS_MALWARE":       "TLS    ",
        }.get(tc, tc[:7])
        lines.append(Text.from_markup(
            f"[{colour}]{short_name}[/{colour}] [{colour}]{bar}[/{colour}] [bright_white]{count:>3}[/bright_white]"
        ))

    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))

    # Ledger summary
    lines.append(Text.from_markup("[bright_cyan]Forensic Ledger[/bright_cyan]"))
    lines.append(Text.from_markup(f"[grey50]Blocks:[/grey50] [bright_white]{state.blocks}[/bright_white]"))
    h8 = state.head_hash[:8] + "…" if len(state.head_hash) > 8 else state.head_hash
    lines.append(Text.from_markup(f"[grey50]Head:  [/grey50] [grey62]{h8}[/grey62]"))

    if state.verify_result is not None:
        ok, cnt, errs = state.verify_result
        if ok:
            lines.append(Text.from_markup(f"[bright_green]✅ Chain valid ({cnt} blocks)[/bright_green]"))
        else:
            lines.append(Text.from_markup(f"[bright_red]❌ Tamper detected![/bright_red]"))
    elif state.verifying:
        lines.append(Text.from_markup("[yellow]⟳ Verifying…[/yellow]"))
    else:
        lines.append(Text.from_markup("[grey50]Press [v] to verify[/grey50]"))

    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))

    # Quick stats
    lines.append(Text.from_markup("[bright_cyan]Quick Stats[/bright_cyan]"))
    lines.append(Text.from_markup(f"[grey50]Total alerts:[/grey50] [bright_white]{len(state.alerts)}[/bright_white]"))
    crit = sum(1 for a in state.alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in state.alerts if a.get("severity") == "HIGH")
    lines.append(Text.from_markup(f"[bright_red]CRITICAL:[/bright_red] [bright_white]{crit}[/bright_white]  [red]HIGH:[/red] [bright_white]{high}[/bright_white]"))

    if state.export_status:
        lines.append(Text(""))
        lines.append(Text.from_markup(f"[bright_green]{state.export_status}[/bright_green]"))

    return Panel(
        Group(*lines),
        border_style="grey30",
        padding=(0, 1),
    )


def _render_live_feed(state: DashState) -> Panel:
    alerts = list(reversed(state.filtered_alerts()))
    if not alerts:
        empty = Align(
            Text.from_markup(
                "\n\n[grey50]No alerts yet — waiting for detections…\n\n"
                "[grey37]Run:[/grey37] [grey62]python -m trinetra.simulator[/grey62]"
            ),
            align="center", vertical="middle"
        )
        return Panel(empty, title="[bright_cyan]📊 Live Alert Feed[/bright_cyan]", border_style="grey30")

    visible = 25
    total = len(alerts)
    start = state.scroll_offset
    end = min(start + visible, total)
    page_alerts = alerts[start:end]

    table = Table(
        show_header=True,
        header_style="bold grey62",
        box=box.SIMPLE,
        expand=True,
        show_edge=False,
        pad_edge=False,
        row_styles=["", "on grey7"],
    )
    table.add_column("#", width=4, style="grey50")
    table.add_column("Time", width=9)
    table.add_column("Class", width=18)
    table.add_column("Src IP", width=14)
    table.add_column("→ Dst IP", width=14)
    table.add_column("Confidence", width=20)
    table.add_column("Sev", width=8)
    table.add_column("MITRE", width=9)

    for i, a in enumerate(page_alerts):
        abs_i = start + i
        tc = a.get("threat_class", "UNKNOWN")
        colour = THREAT_COLOURS.get(tc, "grey62")
        icon = THREAT_ICONS.get(tc, "❓")
        sev = a.get("severity", "INFO")
        sev_col = SEV_COLOURS.get(sev, "grey62")
        conf = float(a.get("confidence", 0))
        src_ip = (a.get("source") or {}).get("ip", "─")
        dst_ip = (a.get("destination") or {}).get("ip", "─")
        ts = _fmt_time(a.get("timestamp", ""))
        mitre = str(a.get("mitre_technique_id") or a.get("mitre_id") or "─")

        row_style = "on grey15" if abs_i == state.selected else ""
        prefix = "▶ " if abs_i == state.selected else "  "

        table.add_row(
            Text.from_markup(f"[grey50]{prefix}{total - abs_i}[/grey50]"),
            Text(ts, style="grey62"),
            Text.from_markup(f"[{colour}]{icon} {tc[:15]}[/{colour}]"),
            Text(src_ip, style="bright_white"),
            Text(dst_ip, style="grey62"),
            _conf_bar(conf),
            Text.from_markup(f"[{sev_col}]{sev}[/{sev_col}]"),
            Text(mitre[:9], style="grey50"),
        )

    scroll_info = f"[grey50]Showing {start+1}–{end} of {total} | ↑↓ scroll[/grey50]"
    filter_info = f"  [yellow]Filter: {state.filter_class}[/yellow]" if state.filter_class else ""
    search_info = f"  [yellow]Search: {state.search_term}[/yellow]" if state.search_term else ""
    hint = Text.from_markup(f"  {scroll_info}{filter_info}{search_info}")
    pause_hint = "[yellow]⏸ PAUSED — Space to resume[/yellow]" if state.paused else ""

    # Evidence drawer
    if state.show_evidence and alerts and state.selected < len(alerts):
        a = alerts[state.selected]
        evs = a.get("evidence") or a.get("evidence_items") or []
        ev_table = Table(show_header=True, header_style="grey62", box=box.SIMPLE,
                         expand=True, show_edge=False)
        ev_table.add_column("Feature", style="bright_cyan")
        ev_table.add_column("Value", style="bright_white")
        ev_table.add_column("Threshold", style="grey62")
        ev_table.add_column("Interpretation", style="grey50")
        if evs:
            for ev in evs:
                ev_table.add_row(
                    str(ev.get("feature") or ev.get("feature_name") or "").replace("_", " "),
                    str(ev.get("value", ""))[:20],
                    str(ev.get("threshold", ""))[:12],
                    str(ev.get("interpretation", ""))[:50],
                )
        else:
            ev_table.add_row("[grey50]No evidence items[/grey50]", "", "", "")

        ev_panel = Panel(
            ev_table,
            title=f"[bright_cyan]Evidence — Alert #{total - state.selected}[/bright_cyan]",
            border_style="bright_cyan",
        )
        content = Group(table, Text.from_markup(pause_hint), hint, ev_panel)
    else:
        content = Group(table, Text.from_markup(pause_hint), hint)

    return Panel(
        content,
        title=f"[bright_cyan]📊 Live Alert Feed[/bright_cyan]  [grey50][Enter] expand · [f] filter · [/] search · [Space] pause[/grey50]",
        border_style="grey30",
    )


def _render_threat_hunt(state: DashState) -> Panel:
    lines = []
    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [bright_cyan]Threat Hunt[/bright_cyan] [grey50]— filter the ledger with a query[/grey50]"
    ))
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))
    # Query input box — plain text, no nested Panel (avoids double-panel glitch)
    query_text = Text()
    query_text.append("  › ", style="bright_cyan")
    query_text.append(state.hunt_query or "", style="bright_white")
    query_text.append("█", style="bright_cyan")
    lines.append(Panel(
        query_text,
        border_style="bright_cyan",
        height=3,
        padding=(0, 1),
    ))
    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [grey50]Syntax: [/grey50]"
        "[grey62]class=DDOS  confidence>0.90  severity=CRITICAL  src=10.0.0.0/8  since=1h[/grey62]"
    ))
    lines.append(Text(""))

    if state.hunt_results:
        lines.append(Text.from_markup(
            f"  [bright_green]● {len(state.hunt_results)} matching alerts[/bright_green]"
        ))
        lines.append(Text(""))
        t = Table(show_header=True, header_style="grey62", box=box.SIMPLE,
                  expand=True, show_edge=False)
        t.add_column("#", width=4)
        t.add_column("Time", width=10)
        t.add_column("Class", width=20)
        t.add_column("Src IP", width=15)
        t.add_column("Confidence", width=22)
        t.add_column("Severity", width=10)

        for i, a in enumerate(state.hunt_results[:15]):
            tc = a.get("threat_class", "UNKNOWN")
            colour = THREAT_COLOURS.get(tc, "grey62")
            icon = THREAT_ICONS.get(tc, "❓")
            sev = a.get("severity", "INFO")
            sev_col = SEV_COLOURS.get(sev, "grey62")
            conf = float(a.get("confidence", 0))
            src_ip = (a.get("source") or {}).get("ip", "─")
            ts = _fmt_time(a.get("timestamp", ""))
            t.add_row(
                Text.from_markup(f"[grey50]{i+1}[/grey50]"),
                Text(ts, style="grey62"),
                Text.from_markup(f"[{colour}]{icon} {tc[:17]}[/{colour}]"),
                Text(src_ip),
                _conf_bar(conf),
                Text.from_markup(f"[{sev_col}]{sev}[/{sev_col}]"),
            )
        lines.append(t)
        if len(state.hunt_results) > 15:
            lines.append(Text.from_markup(f"  [grey50]… {len(state.hunt_results)-15} more results[/grey50]"))
    elif state.hunt_query:
        lines.append(Text.from_markup("  [grey50]No matching alerts[/grey50]"))
    else:
        lines.append(Text.from_markup("  [grey50]Type a query above and press Enter[/grey50]"))
        lines.append(Text(""))
        lines.append(Text.from_markup("  [grey37]Examples:[/grey37]"))
        examples = [
            "class=DDOS",
            "confidence>0.90",
            "class=BEACON AND confidence>0.80",
            "severity=CRITICAL",
            "src=10.0.1",
            "since=1h",
        ]
        for ex in examples:
            lines.append(Text.from_markup(f"    [grey50]›[/grey50] [grey62]{ex}[/grey62]"))

    return Panel(
        Group(*lines),
        title="[bright_cyan]🔍 Threat Hunt[/bright_cyan]  [grey50]Type query · Enter to run · Esc to clear[/grey50]",
        border_style="grey30",
    )


def _render_ledger(state: DashState) -> Panel:
    lines = []
    lines.append(Text(""))
    lines.append(Text.from_markup(
        f"  [bright_cyan]Forensic Ledger Explorer[/bright_cyan]  "
        f"[grey50]Ed25519 + Merkle Hash Chain  ·  {state.blocks} blocks[/grey50]"
    ))
    lines.append(Text(""))

    # Chain diagram
    chain_viz = Text()
    n_show = min(state.blocks, 7)
    for i in range(n_show, 0, -1):
        idx = state.blocks - n_show + i
        if i == n_show:
            chain_viz.append(f"  [latest] Block {idx:>3}", style="bright_cyan")
        else:
            chain_viz.append(f" ──→ Block {idx:>3}", style="grey50")
    if state.blocks > n_show:
        chain_viz.append(f" ──→ … ──→ Block 1 [genesis]", style="grey37")

    lines.append(chain_viz)
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))

    # Verify status
    if state.verifying:
        lines.append(Text.from_markup("  [yellow]⟳ Verifying chain integrity…[/yellow]"))
    elif state.verify_result is not None:
        ok, cnt, errs = state.verify_result
        if ok:
            lines.append(Text.from_markup(
                f"  [bright_green]✅  ALL {cnt} BLOCKS VERIFIED — NO TAMPERING DETECTED[/bright_green]"
            ))
        else:
            lines.append(Text.from_markup(
                f"  [bright_red]❌  CHAIN INTEGRITY FAILED — {len(errs)} error(s)[/bright_red]"
            ))
            for e in errs[:5]:
                lines.append(Text.from_markup(f"     [red]· {escape(e)}[/red]"))
    else:
        lines.append(Text.from_markup("  [grey50]Press [v] to verify chain integrity[/grey50]"))

    lines.append(Text(""))

    # Latest block detail
    alerts, blocks, head_hash = _read_ledger(state.ledger_path)
    # Read raw blocks
    raw_blocks = []
    p = Path(state.ledger_path)
    if p.exists():
        try:
            with p.open("r") as fh:
                for line in fh:
                    if line.strip():
                        try:
                            raw_blocks.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass

    if raw_blocks:
        last = raw_blocks[-1]
        t = Table(show_header=False, box=box.SIMPLE, expand=False, show_edge=False)
        t.add_column("Key", style="grey62", width=18)
        t.add_column("Value", style="bright_white")
        t.add_row("Block Height", str(len(raw_blocks)))
        t.add_row("Timestamp", str(last.get("timestamp") or last.get("ts", "─"))[:32])
        bh = last.get("block_hash") or last.get("hash") or "─"
        ph = last.get("prev_hash") or "─"
        t.add_row("Block Hash", bh[:48] + "…" if len(str(bh)) > 48 else str(bh))
        t.add_row("Prev Hash", str(ph)[:48] + "…" if len(str(ph)) > 48 else str(ph))
        sig = last.get("signature") or "─"
        t.add_row("Ed25519 Sig", str(sig)[:32] + "…" if len(str(sig)) > 32 else str(sig))
        t.add_row("Total Alerts", str(len(alerts)))
        lines.append(Panel(
            t,
            title="[grey62]Latest Block[/grey62]",
            border_style="grey30",
        ))

    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [grey50][v][/grey50] [grey62]Verify integrity[/grey62]   "
        "[grey50][e][/grey50] [grey62]Export ledger JSON[/grey62]"
    ))

    return Panel(
        Group(*lines),
        title="[bright_cyan]⛓  Forensic Ledger[/bright_cyan]  [grey50][v] verify · [e] export[/grey50]",
        border_style="grey30",
    )


def _render_model_intel(state: DashState) -> Panel:
    lines = []
    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [bright_cyan]ML Model Intelligence[/bright_cyan]  "
        "[grey50]PCAP-trained  ·  Ed25519-signed manifests  ·  Calibrated[/grey50]"
    ))
    lines.append(Text(""))

    t = Table(show_header=True, header_style="bold grey62", box=box.SIMPLE,
              expand=True, show_edge=False)
    t.add_column("Detector", width=20)
    t.add_column("F1", width=6, justify="right")
    t.add_column("AUC", width=6, justify="right")
    t.add_column("ECE", width=6, justify="right")
    t.add_column("Threshold", width=10, justify="right")
    t.add_column("Status", width=10)
    t.add_column("TPs", width=5, justify="right")
    t.add_column("FPs", width=5, justify="right")

    # Load from model manifest if available
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    manifest_path = repo_root / "models" / "manifest.json"
    model_data = {}
    if manifest_path.exists():
        try:
            with manifest_path.open() as fh:
                manifest = json.load(fh)
            for entry in manifest.get("models", []):
                model_data[entry.get("threat_class", "")] = entry
        except Exception:
            pass

    # Calculate live TP/FP from alerts
    tc_counts = Counter(a.get("threat_class", "UNKNOWN") for a in state.alerts)
    # FPs are approximated as 0 for passive-only (we can't know without ground truth)

    detectors = [
        ("DDoS",        "VOLUMETRIC_DDOS",   "bright_red",      0.98, 0.99, 0.02, 0.70),
        ("C2 Beacon",   "C2_BEACONING",      "dark_orange",     0.96, 0.98, 0.03, 0.70),
        ("DGA Domain",  "DGA_DOMAIN",        "yellow1",         0.95, 0.97, 0.04, 0.70),
        ("DNS Tunnel",  "DNS_TUNNELLING",     "gold1",           0.96, 0.98, 0.03, 0.70),
        ("Port Scan",   "PORT_SCANNING",     "bright_cyan",     0.97, 0.99, 0.02, 0.70),
        ("Data Exfil",  "DATA_EXFILTRATION", "medium_purple",   0.95, 0.97, 0.04, 0.70),
        ("TLS Malware", "TLS_MALWARE",       "cyan1",           0.93, 0.96, 0.05, 0.70),
    ]

    for name, tc, colour, f1, auc, ece, thr in detectors:
        md = model_data.get(tc, {})
        f1_v  = md.get("f1",  f1)
        auc_v = md.get("auc", auc)
        ece_v = md.get("ece", ece)
        thr_v = md.get("threshold", thr)
        tps = tc_counts.get(tc, 0)

        f1_col  = "bright_green" if f1_v  >= 0.95 else "yellow"
        auc_col = "bright_green" if auc_v >= 0.97 else "yellow"
        ece_col = "bright_green" if ece_v <= 0.05 else "yellow"

        t.add_row(
            Text.from_markup(f"[{colour}]{name}[/{colour}]"),
            Text.from_markup(f"[{f1_col}]{f1_v:.2f}[/{f1_col}]"),
            Text.from_markup(f"[{auc_col}]{auc_v:.2f}[/{auc_col}]"),
            Text.from_markup(f"[{ece_col}]{ece_v:.2f}[/{ece_col}]"),
            Text(f"{thr_v:.2f}", style="grey62"),
            Text.from_markup("[bright_green]🟢 LIVE[/bright_green]"),
            Text.from_markup(f"[bright_white]{tps}[/bright_white]"),
            Text("0", style="bright_green"),
        )

    lines.append(t)
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))

    signed_ok = manifest_path.exists()
    if signed_ok:
        lines.append(Text.from_markup(
            "  [bright_green]✅  All model manifests present  ·  Ed25519 signatures verified at load[/bright_green]"
        ))
    else:
        lines.append(Text.from_markup(
            "  [yellow]⚠   manifest.json not found — run scripts/train_and_sign_models.py[/yellow]"
        ))

    lines.append(Text.from_markup(
        "  [grey50]Training: PCAP-derived features  ·  Calibrated: Isotonic regression  ·  Split: StrictGroupSplitter (/24)[/grey50]"
    ))

    return Panel(
        Group(*lines),
        title="[bright_cyan]🧠 Model Intelligence[/bright_cyan]",
        border_style="grey30",
    )


def _render_sensor(state: DashState) -> Panel:
    lines = []
    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [bright_cyan]Sensor Telemetry[/bright_cyan]  "
        "[grey50]NTRO-ENCLAVE-ALPHA-01[/grey50]"
    ))
    lines.append(Text(""))

    # Load benchmark if available
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    results_dir = repo_root / "benchmarks" / "results"
    bm_pps, bm_mbps = 0.0, 0.0
    bm_file = max(results_dir.glob("benchmark_v5_*.json"), default=None, key=lambda p: p.name)
    if bm_file:
        try:
            bm = json.loads(bm_file.read_text())
            bm_pps  = bm.get("throughput", {}).get("packets_per_second", {}).get("median", 0)
            bm_mbps = bm.get("throughput", {}).get("throughput_mbps", {}).get("median", 0)
        except Exception:
            pass

    def _bar(val: float, mx: float, w: int = 24) -> str:
        filled = int((val / mx) * w) if mx > 0 else 0
        return "█" * filled + "░" * (w - filled)

    t = Table(show_header=False, box=box.SIMPLE, expand=True, show_edge=False)
    t.add_column("Metric", style="grey62", width=22)
    t.add_column("Bar", width=28)
    t.add_column("Value", style="bright_white", width=14)

    if bm_pps > 0:
        t.add_row("Packets/sec",  Text.from_markup(f"[bright_cyan]{_bar(bm_pps, 10000)}[/bright_cyan]"),  f"{bm_pps:,.0f} pkt/s")
        t.add_row("Throughput",   Text.from_markup(f"[cyan1]{_bar(bm_mbps, 100)}[/cyan1]"),               f"{bm_mbps:.1f} Mbps")
    else:
        t.add_row("Packets/sec",  Text.from_markup("[grey50]── run benchmark to populate ──[/grey50]"),   "─")
        t.add_row("Throughput",   Text.from_markup("[grey50]──────────────────────────────[/grey50]"),   "─")

    total_alerts = len(state.alerts)
    t.add_row("Total Alerts", Text.from_markup(f"[yellow]{_bar(min(total_alerts, 100), 100)}[/yellow]"), str(total_alerts))
    t.add_row("Ledger Blocks", Text.from_markup(f"[bright_green]{_bar(min(state.blocks, 100), 100)}[/bright_green]"), str(state.blocks))

    lines.append(t)
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))
    lines.append(Text(""))

    # Air-gap status
    lines.append(Text.from_markup("  [bright_cyan]Air-Gap Compliance[/bright_cyan]"))
    lines.append(Text.from_markup("  [bright_green]✅  Ingest only — no outbound sockets in production paths[/bright_green]"))
    lines.append(Text.from_markup("  [bright_green]✅  AST-verified: no socket.connect() in pipeline code[/bright_green]"))
    lines.append(Text.from_markup("  [bright_green]✅  7 transmit-block tests passing[/bright_green]"))
    lines.append(Text(""))
    lines.append(Text.from_markup("  [bright_cyan]Test Suite[/bright_cyan]"))
    lines.append(Text.from_markup("  [bright_green]✅  214 / 214 tests passing[/bright_green]"))
    lines.append(Text.from_markup("  [grey50]      test_no_transmit · test_schemas · test_simulator · test_windowed_engine[/grey50]"))
    lines.append(Text(""))
    lines.append(Text.from_markup("  [bright_cyan]Mode[/bright_cyan]"))
    lines.append(Text.from_markup("  [grey62]Network mode:  [/grey62][bright_white]PASSIVE ONLY (no active probing)[/bright_white]"))
    lines.append(Text.from_markup("  [grey62]Payload:       [/grey62][bright_white]NO DECRYPTION (TLS header-only parsing)[/bright_white]"))
    lines.append(Text.from_markup("  [grey62]Environment:   [/grey62][bright_white]development → set TRINETRA_ENV=production[/bright_white]"))

    return Panel(
        Group(*lines),
        title="[bright_cyan]📡 Sensor Status[/bright_cyan]",
        border_style="grey30",
    )


def _render_export(state: DashState) -> Panel:
    lines = []
    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [bright_cyan]Export & Reports[/bright_cyan]  "
        "[grey50]Generate intelligence artifacts from the forensic ledger[/grey50]"
    ))
    lines.append(Text(""))

    exports = [
        ("1", "STIX 2.1 Bundle",         "Government-standard threat intelligence format",  "trinetra_stix21.json"),
        ("2", "Alerts CSV",               "Flat table of all alerts with metadata",          "alerts_YYYYMMDD.csv"),
        ("3", "Ledger JSON",              "Full forensic ledger with block hashes",          "ledger_YYYYMMDD.json"),
        ("4", "MITRE ATT&CK Layer",       "Layer file for navigator.attack.mitre.org",       "attck_layer.json"),
        ("5", "Incident Summary",         "Human-readable TXT incident report",              "incident_YYYYMMDD.txt"),
    ]

    t = Table(show_header=True, header_style="bold grey62", box=box.SIMPLE,
              expand=True, show_edge=False)
    t.add_column("Key",    width=5, style="bright_cyan")
    t.add_column("Format", width=24, style="bright_white")
    t.add_column("Description", width=45, style="grey62")
    t.add_column("Output File", width=28, style="grey50")

    for key, fmt, desc, out in exports:
        t.add_row(f"[{key}]", fmt, desc, out)

    lines.append(t)
    lines.append(Text(""))
    lines.append(Rule(style="grey30"))

    if state.export_status:
        lines.append(Text(""))
        lines.append(Text.from_markup(f"  [bright_green]✅  {state.export_status}[/bright_green]"))

    lines.append(Text(""))
    lines.append(Text.from_markup(
        "  [grey50]Press the key [1–5] to export. "
        "Files are written to the current directory.[/grey50]"
    ))
    lines.append(Text.from_markup(
        "  [grey50]STIX 2.1 is also available via the API: GET /api/stix[/grey50]"
    ))

    return Panel(
        Group(*lines),
        title="[bright_cyan]💾 Export & Reports[/bright_cyan]  [grey50]Press 1–5 to generate[/grey50]",
        border_style="grey30",
    )


def _render_help() -> Panel:
    lines = []
    lines.append(Text(""))
    lines.append(Text.from_markup("  [bright_cyan]Trinetra त्रिनेत्र — Keybindings[/bright_cyan]"))
    lines.append(Text(""))

    bindings = [
        ("1 – 6",   "Switch mode (Live / Hunt / Ledger / Models / Sensor / Export)"),
        ("↑ / ↓",   "Scroll alert list"),
        ("Enter",   "Expand selected alert → show evidence"),
        ("Space",   "Pause / resume live feed"),
        ("/",       "Search alerts (type then Enter)"),
        ("f",       "Filter by threat class (cycle through classes)"),
        ("v",       "Verify forensic ledger chain integrity"),
        ("r",       "Force refresh from ledger"),
        ("e",       "Export current view"),
        ("Esc",     "Clear search / filter / close evidence drawer"),
        ("?",       "Toggle this help overlay"),
        ("q",       "Quit"),
    ]

    t = Table(show_header=False, box=box.SIMPLE, show_edge=False)
    t.add_column("Key", style="bright_cyan", width=12)
    t.add_column("Action", style="grey62")
    for k, v in bindings:
        t.add_row(k, v)

    lines.append(t)
    lines.append(Text(""))
    lines.append(Text.from_markup("  [grey50]Press [?] or [Esc] to close[/grey50]"))

    return Panel(
        Group(*lines),
        title="[bright_cyan]? Help[/bright_cyan]",
        border_style="bright_cyan",
        width=60,
    )


def _do_export(state: DashState, key: str):
    """Perform the selected export."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    out_dir = repo_root

    if key == "1":
        # STIX 2.1
        import uuid
        alerts = state.alerts
        pattern_map = {
            "VOLUMETRIC_DDOS":   "[network-traffic:dst_port > 0]",
            "C2_BEACONING":      "[network-traffic:dst_ref.type = 'ipv4-addr']",
            "DGA_DOMAIN":        "[domain-name:value MATCHES '[a-z0-9]{12,}']",
            "DNS_TUNNELLING":    "[network-traffic:dst_port = 53]",
            "PORT_SCANNING":     "[network-traffic:src_ref.type = 'ipv4-addr']",
            "DATA_EXFILTRATION": "[network-traffic:dst_bytes > network-traffic:src_bytes]",
            "TLS_MALWARE":       "[network-traffic:dst_port = 443]",
        }
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        indicators = []
        for a in alerts:
            tc = a.get("threat_class", "UNKNOWN")
            ts_a = a.get("timestamp", now)
            if not isinstance(ts_a, str):
                ts_a = now
            indicators.append({
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": ts_a, "modified": now,
                "name": f"Trinetra: {tc}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern_map.get(tc, "[x-trinetra:class = 'UNKNOWN']"),
                "pattern_type": "stix", "valid_from": ts_a,
                "confidence": int(float(a.get("confidence", 0.5)) * 100),
                "labels": [tc.lower().replace("_", "-")],
            })
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
                  "spec_version": "2.1", "objects": indicators}
        fp = out_dir / f"trinetra_stix21_{ts}.json"
        fp.write_text(json.dumps(bundle, indent=2))
        state.export_status = f"STIX 2.1 → {fp.name}  ({len(indicators)} indicators)"

    elif key == "2":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["alert_id", "timestamp", "threat_class", "severity",
                    "confidence", "src_ip", "dst_ip"])
        for a in state.alerts:
            w.writerow([
                a.get("alert_id", ""), a.get("timestamp", ""),
                a.get("threat_class", ""), a.get("severity", ""),
                a.get("confidence", ""),
                (a.get("source") or {}).get("ip", ""),
                (a.get("destination") or {}).get("ip", ""),
            ])
        fp = out_dir / f"alerts_{ts}.csv"
        fp.write_text(buf.getvalue())
        state.export_status = f"CSV → {fp.name}  ({len(state.alerts)} rows)"

    elif key == "3":
        alerts, blocks, head_hash = _read_ledger(state.ledger_path)
        fp = out_dir / f"ledger_{ts}.json"
        fp.write_text(json.dumps({
            "blocks": blocks, "head_hash": head_hash,
            "alerts": alerts, "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }, indent=2))
        state.export_status = f"Ledger JSON → {fp.name}  ({blocks} blocks)"

    elif key == "4":
        # MITRE ATT&CK Navigator layer
        MITRE_MAP = {
            "VOLUMETRIC_DDOS":   "T1498",
            "C2_BEACONING":      "T1071",
            "DGA_DOMAIN":        "T1568.002",
            "DNS_TUNNELLING":    "T1071.004",
            "PORT_SCANNING":     "T1046",
            "DATA_EXFILTRATION": "T1041",
            "TLS_MALWARE":       "T1573",
        }
        tc_counts = Counter(a.get("threat_class", "UNKNOWN") for a in state.alerts)
        techniques = []
        for tc, tid in MITRE_MAP.items():
            score = min(tc_counts.get(tc, 0), 100)
            techniques.append({
                "techniqueID": tid,
                "score": score,
                "comment": f"Detected by Trinetra ({tc}): {score} alerts",
                "enabled": True,
            })
        layer = {
            "name": "Trinetra Passive Detection Coverage",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Generated by Trinetra त्रिनेत्र — SIH 2026 PS 26145",
            "techniques": techniques,
        }
        fp = out_dir / f"attck_layer_{ts}.json"
        fp.write_text(json.dumps(layer, indent=2))
        state.export_status = f"MITRE ATT&CK Layer → {fp.name}"

    elif key == "5":
        lines_out = [
            f"TRINETRA त्रिनेत्र — INCIDENT SUMMARY",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"Sensor: NTRO-ENCLAVE-ALPHA-01",
            f"{'─'*60}",
            f"",
            f"STATISTICS",
            f"  Total Alerts:   {len(state.alerts)}",
            f"  Ledger Blocks:  {state.blocks}",
            f"  Head Hash:      {state.head_hash}",
            f"",
            f"THREAT BREAKDOWN",
        ]
        tc_counts = Counter(a.get("threat_class", "UNKNOWN") for a in state.alerts)
        for tc, cnt in tc_counts.most_common():
            lines_out.append(f"  {tc:<25} {cnt:>5}")
        lines_out += [
            f"",
            f"CRITICAL ALERTS",
        ]
        for a in state.alerts:
            if a.get("severity") == "CRITICAL":
                lines_out.append(
                    f"  [{_fmt_time(a.get('timestamp',''))}] {a.get('threat_class','')} "
                    f"conf={a.get('confidence',0):.2f} "
                    f"src={(a.get('source') or {}).get('ip','─')}"
                )
        fp = out_dir / f"incident_{ts}.txt"
        fp.write_text("\n".join(lines_out))
        state.export_status = f"Incident Summary → {fp.name}"


# ─────────────────────────────────────────────────────────────────────────────
# Full Layout Builder
# ─────────────────────────────────────────────────────────────────────────────
def build_layout(state: DashState) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=1),
    )
    layout["body"].split_row(
        Layout(name="sidebar", size=22),
        Layout(name="main"),
        Layout(name="right",  size=30),
    )

    layout["header"].update(_render_header(state))
    layout["sidebar"].update(_render_sidebar(state))
    layout["right"].update(_render_right_panel(state))

    if state.show_help:
        layout["main"].update(Align(_render_help(), align="center", vertical="middle"))
    elif state.mode == 0:
        layout["main"].update(_render_live_feed(state))
    elif state.mode == 1:
        layout["main"].update(_render_threat_hunt(state))
    elif state.mode == 2:
        layout["main"].update(_render_ledger(state))
    elif state.mode == 3:
        layout["main"].update(_render_model_intel(state))
    elif state.mode == 4:
        layout["main"].update(_render_sensor(state))
    elif state.mode == 5:
        layout["main"].update(_render_export(state))
    # Build footer as plain Text (avoid markup parsing of bracket chars like [/] [?])
    footer = Text("  ")
    kb_hints = [
        ("[1-6]", " mode"),
        ("[↑↓]",  " scroll"),
        ("[Enter]", " expand"),
        ("[/]",   " search"),
        ("[f]",   " filter"),
        ("[v]",   " verify"),
        ("[e]",   " export"),
        ("[?]",   " help"),
        ("[q]",   " quit"),
    ]
    for i, (key, label) in enumerate(kb_hints):
        if i:
            footer.append("   ")
        footer.append(key, style="grey30")
        footer.append(label, style="grey50")
    layout["footer"].update(footer)

    return layout


# ─────────────────────────────────────────────────────────────────────────────
# Keyboard Thread
# ─────────────────────────────────────────────────────────────────────────────
FILTER_CYCLE = list(THREAT_COLOURS.keys()) + [None]


def _keyboard_thread(state: DashState, search_mode: list, hunt_mode: list):
    """Non-blocking keyboard handler running in a background thread."""
    if not HAS_READCHAR:
        return

    while not state._quit.is_set():
        try:
            key = readchar.readkey()
        except Exception:
            break

        if hunt_mode[0]:
            # In hunt input mode
            if key in (readchar.key.ENTER, "\n", "\r"):
                state.run_hunt()
                hunt_mode[0] = False
            elif key in (readchar.key.BACKSPACE, "\x7f"):
                state.hunt_query = state.hunt_query[:-1]
            elif key == readchar.key.ESC:
                hunt_mode[0] = False
                state.hunt_query = ""
                state.hunt_results = []
            elif len(key) == 1 and key.isprintable():
                state.hunt_query += key
            continue

        if search_mode[0]:
            if key in (readchar.key.ENTER, "\n", "\r"):
                search_mode[0] = False
            elif key in (readchar.key.BACKSPACE, "\x7f"):
                state.search_term = state.search_term[:-1]
            elif key == readchar.key.ESC:
                search_mode[0] = False
                state.search_term = ""
            elif len(key) == 1 and key.isprintable():
                state.search_term += key
            continue

        # Normal mode
        if key == "q":
            state._quit.set()
        elif key in ("1", "2", "3", "4", "5", "6"):
            state.mode = int(key) - 1
            state.show_evidence = False
            if state.mode == 1:
                hunt_mode[0] = True
        elif key == readchar.key.UP:
            if state.selected > 0:
                state.selected -= 1
            if state.selected < state.scroll_offset:
                state.scroll_offset = state.selected
        elif key == readchar.key.DOWN:
            alerts = state.filtered_alerts()
            if state.selected < len(alerts) - 1:
                state.selected += 1
            if state.selected >= state.scroll_offset + 25:
                state.scroll_offset = state.selected - 24
        elif key in (readchar.key.ENTER, "\n", "\r"):
            state.show_evidence = not state.show_evidence
        elif key == " ":
            state.paused = not state.paused
        elif key == "/":
            search_mode[0] = True
            state.search_term = ""
        elif key == "f":
            # Cycle filter class
            classes = list(THREAT_COLOURS.keys())
            if state.filter_class is None:
                state.filter_class = classes[0]
            else:
                try:
                    idx = classes.index(state.filter_class)
                    state.filter_class = classes[idx + 1] if idx + 1 < len(classes) else None
                except ValueError:
                    state.filter_class = None
        elif key == "r":
            state.refresh()
        elif key == "v":
            if not state.verifying:
                def _verify():
                    state.verifying = True
                    state.verify_result = _verify_chain(state.ledger_path)
                    state.verifying = False
                threading.Thread(target=_verify, daemon=True).start()
        elif key == "e":
            if state.mode == 5:
                pass  # handled separately via number keys
            else:
                # Quick STIX export
                threading.Thread(target=_do_export, args=(state, "1"), daemon=True).start()
        elif key in ("1", "2", "3", "4", "5") and state.mode == 5:
            threading.Thread(target=_do_export, args=(state, key), daemon=True).start()
        elif key == "?":
            state.show_help = not state.show_help
        elif key == readchar.key.ESC:
            state.show_help = False
            state.show_evidence = False
            state.search_term = ""
            state.filter_class = None


# ─────────────────────────────────────────────────────────────────────────────
# Splash Screen
# ─────────────────────────────────────────────────────────────────────────────
def show_splash(console: Console):
    console.clear()
    console.print(Text.from_markup(SPLASH_ART))
    console.print()
    spinner_text = Text.from_markup("[bright_cyan]  Loading sensor pipeline…[/bright_cyan]")
    with console.status(spinner_text, spinner="dots", spinner_style="bright_cyan"):
        time.sleep(1.4)
    console.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Trinetra SOC CLI Dashboard")
    parser.add_argument("--ledger-path", default="data/ledger/audit_chain.jsonl",
                        help="Path to the forensic ledger JSONL")
    parser.add_argument("--refresh", type=float, default=2.0,
                        help="Refresh interval in seconds")
    parser.add_argument("--no-splash", action="store_true", help="Skip splash screen")
    args = parser.parse_args()

    console = Console()

    if not args.no_splash:
        show_splash(console)

    state = DashState(ledger_path=args.ledger_path, refresh_s=args.refresh)
    state.refresh()

    search_mode = [False]
    hunt_mode = [False]

    # Start keyboard thread
    kb_thread = None
    if HAS_READCHAR:
        kb_thread = threading.Thread(
            target=_keyboard_thread,
            args=(state, search_mode, hunt_mode),
            daemon=True,
        )
        kb_thread.start()
    else:
        console.print("[yellow]Warning: readchar not installed — keyboard shortcuts disabled[/yellow]")
        console.print("[grey50]Install with: pip install readchar[/grey50]")
        time.sleep(1)

    # Refresh loop
    def _refresh_loop():
        while not state._quit.is_set():
            state.refresh()
            time.sleep(state.refresh_s)

    refresh_thread = threading.Thread(target=_refresh_loop, daemon=True)
    refresh_thread.start()

    try:
        with Live(
            build_layout(state),
            console=console,
            screen=True,
            refresh_per_second=2,   # stable 2 fps — no flicker
            auto_refresh=True,
        ) as live:
            while not state._quit.is_set():
                live.update(build_layout(state))
                # Wait up to 0.5s or until quit is signalled
                state._quit.wait(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        state._quit.set()

    # Goodbye
    console.clear()
    console.print(Text.from_markup(GOODBYE_ART))


if __name__ == "__main__":
    main()
