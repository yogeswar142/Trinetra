"""
trinetra — Interactive CLI  (v2)

Pattern: claude / opencode — type `trinetra` to open the REPL.

Upgrades over v1:
  • Bottom toolbar  — live clock + sensor status + alert count + ledger hash
  • Threat count in prompt  — ❯ ⚠ 2 CRITICAL  (red if active)
  • Fuzzy slash-command completion  — /al → /alerts
  • Pixel-art ◉ eye welcome graphic
  • Gradient ASCII banner (bright→dim per column)
  • Spinner on every command with output
  • Syntax-highlighted hunt query input
  • Session uptime in right-prompt
  • `/alerts recent` shown automatically on startup if alerts exist
  • Subcommand mode still works for piping: `trinetra stats`
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Rich ──────────────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns
from rich.align import Align
from rich.spinner import Spinner
from rich.live import Live
from rich import box

# ── prompt_toolkit ────────────────────────────────────────────────────────
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion, FuzzyCompleter
from prompt_toolkit.formatted_text import HTML, ANSI
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.document import Document

# ──────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent.parent
LEDGER_PATH = REPO_ROOT / "data" / "ledger" / "audit_chain.jsonl"

# ──────────────────────────────────────────────────────────────────────────
# Threat metadata
# ──────────────────────────────────────────────────────────────────────────
THREAT_COLOURS = {
    "VOLUMETRIC_DDOS":   "bright_red",
    "C2_BEACONING":      "dark_orange",
    "DGA_DOMAIN":        "yellow1",
    "DNS_TUNNELLING":    "gold1",
    "PORT_SCANNING":     "bright_cyan",
    "DATA_EXFILTRATION": "medium_purple",
    "TLS_MALWARE":       "cyan1",
    "UNKNOWN":           "grey62",
}

SEV_ICONS = {
    "CRITICAL": ("🔴", "bright_red"),
    "HIGH":     ("🟠", "red"),
    "MEDIUM":   ("🟡", "yellow"),
    "LOW":      ("🔵", "bright_cyan"),
    "INFO":     ("⚪", "grey70"),
}

MITRE_MAP = {
    "VOLUMETRIC_DDOS":   "T1498",
    "C2_BEACONING":      "T1071",
    "DGA_DOMAIN":        "T1568.002",
    "DNS_TUNNELLING":    "T1071.004",
    "PORT_SCANNING":     "T1046",
    "DATA_EXFILTRATION": "T1041",
    "TLS_MALWARE":       "T1573",
}

console = Console()
err     = Console(stderr=True)

# ──────────────────────────────────────────────────────────────────────────
# Slash commands — /cmd  description
# ──────────────────────────────────────────────────────────────────────────
SLASH_COMMANDS = [
    ("/watch",   "Stream live alerts as they arrive  (Ctrl-C to stop)"),
    ("/alerts",  "Show latest alerts  · /alerts class=DDOS conf>0.9 n=20"),
    ("/hunt",    "DSL query  · /hunt class=DDOS AND confidence>0.90"),
    ("/stats",   "Summary statistics + threat breakdown"),
    ("/verify",  "Verify forensic ledger chain integrity"),
    ("/export",  "Export  · /export stix | csv | attck | incident"),
    ("/clear",   "Clear the screen and re-draw the banner"),
    ("/help",    "Show all commands"),
    ("/quit",    "Exit Trinetra"),
]

# ──────────────────────────────────────────────────────────────────────────
# Fuzzy slash completer
# ──────────────────────────────────────────────────────────────────────────
class SlashCompleter(Completer):
    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        if not text.lstrip().startswith("/"):
            return
        word = text.lstrip()
        for cmd, desc in SLASH_COMMANDS:
            # fuzzy: every char of word must appear in cmd in order
            pattern = ".*".join(re.escape(c) for c in word)
            if re.match(pattern, cmd, re.I):
                yield Completion(
                    cmd,
                    start_position=-len(word),
                    display=HTML(
                        f"<ansicyan>{cmd:<12}</ansicyan>  "
                        f"<ansibrightblack>{desc}</ansibrightblack>"
                    ),
                )

# ──────────────────────────────────────────────────────────────────────────
# Syntax lexer for hunt queries  (highlights keywords in the input box)
# ──────────────────────────────────────────────────────────────────────────
class HuntLexer(Lexer):
    """Colour keywords in /hunt queries while typing."""
    def lex_document(self, document):
        text = document.text
        def get_line(lineno):
            tokens = []
            # cmd part
            if text.startswith("/hunt "):
                tokens.append(("#888888", "/hunt "))
                rest = text[6:]
            elif text.startswith("/"):
                return [("#888888", text)]
            else:
                rest = text
            # tokenise rest
            for word in re.split(r"(\s+)", rest):
                if word.upper() in ("AND", "OR", "NOT"):
                    tokens.append(("#ff79c6", word))
                elif re.match(r"(class|confidence|severity|src|dst|since)", word, re.I):
                    tokens.append(("#8be9fd", word))
                elif re.match(r"[><=!]+", word):
                    tokens.append(("#ffb86c", word))
                elif re.match(r"[\d.]+", word):
                    tokens.append(("#bd93f9", word))
                else:
                    tokens.append(("#f8f8f2", word))
            return tokens
        return get_line

# ──────────────────────────────────────────────────────────────────────────
# prompt_toolkit style
# ──────────────────────────────────────────────────────────────────────────
PROMPT_STYLE = Style.from_dict({
    # prompt
    "prompt":                              "#00d7ff bold",
    "prompt.alert":                        "#ff5555 bold",
    # completion dropdown
    "completion-menu.completion":          "bg:#0d1117 #aaaaaa",
    "completion-menu.completion.current":  "bg:#00d7ff #000000 bold",
    "completion-menu.meta.completion":     "bg:#0d1117 #555555",
    "completion-menu.meta.completion.current": "bg:#00d7ff #222222",
    "scrollbar.background":                "bg:#0d1117",
    "scrollbar.button":                    "bg:#00d7ff",
    # bottom toolbar
    "bottom-toolbar":                      "bg:#0d1117 #555555",
    "bottom-toolbar.text":                 "bg:#0d1117 #00d7ff",
    "bottom-toolbar.sep":                  "bg:#0d1117 #1e2030",
    "bottom-toolbar.ok":                   "bg:#0d1117 #50fa7b",
    "bottom-toolbar.warn":                 "bg:#0d1117 #ff5555",
    # suggestions
    "auto-suggestion":                     "#333355",
    # right prompt
    "rprompt":                             "#333355",
})

# ──────────────────────────────────────────────────────────────────────────
# Ledger helpers
# ──────────────────────────────────────────────────────────────────────────
def _read_ledger(path: Path):
    raw_blocks, alerts = [], []
    if not path.exists():
        return raw_blocks, alerts
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    raw_blocks.append(data)
                    for key in ("alert_record", "alert", "record", "data"):
                        val = data.get(key)
                        if isinstance(val, dict) and "threat_class" in val:
                            alerts.append(val)
                            break
                    else:
                        if "threat_class" in data:
                            alerts.append(data)
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    return raw_blocks, alerts

def _ledger_meta(path: Path):
    blocks, head = 0, "N/A"
    if not path.exists():
        return blocks, head
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    try:
                        data = json.loads(line)
                        blocks += 1
                        h = data.get("block_hash") or data.get("hash")
                        if h:
                            head = str(h)
                    except Exception:
                        pass
    except OSError:
        pass
    return blocks, head

def _fmt_time(ts: Any) -> str:
    if isinstance(ts, (int, float)):
        return time.strftime("%H:%M:%S", time.localtime(ts))
    if isinstance(ts, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.strftime("%H:%M:%S")
            except Exception:
                pass
        return ts[-8:] if len(ts) >= 8 else ts
    return "──:──:──"

# ──────────────────────────────────────────────────────────────────────────
# Pixel-art eye + gradient banner
# ──────────────────────────────────────────────────────────────────────────
# Each row is (style, text) — columns go bright_cyan → cyan1 → grey50 → grey37
BANNER_ROWS = [
    ("#005f87",  "  ████████╗██████╗ ██╗███╗  ██╗███████╗████████╗██████╗  █████╗  "),
    ("#0087af",  "     ██╔══╝██╔══██╗██║████╗ ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ "),
    ("#00afd7",  "     ██║   ██████╔╝██║██╔██╗██║█████╗     ██║   ██████╔╝███████║ "),
    ("#00d7ff",  "     ██║   ██╔══██╗██║██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══██║ "),
    ("#4d4d4d",  "     ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ "),
]

# Small pixel-art eye  (5×5 braille-style)
EYE_ART = [
    ("  [grey37]·[/grey37][bright_cyan]◉◉◉[/bright_cyan][grey37]·[/grey37]  "),
    ("  [bright_cyan]◉[/bright_cyan][cyan1]███[/cyan1][bright_cyan]◉[/bright_cyan]  "),
    ("  [cyan1]▓[/cyan1][bright_white]███[/bright_white][cyan1]▓[/cyan1]  "),
    ("  [bright_cyan]◉[/bright_cyan][cyan1]███[/cyan1][bright_cyan]◉[/bright_cyan]  "),
    ("  [grey37]·[/grey37][bright_cyan]◉◉◉[/bright_cyan][grey37]·[/grey37]  "),
]

def _print_banner(ledger: Path, session_start: float):
    console.clear()

    # Gradient banner — line by line, each slightly delayed for "fade-in"
    for colour, text in BANNER_ROWS:
        console.print(text, style=colour)
        time.sleep(0.03)

    console.print()

    # Two-panel welcome (like Claude)
    _, alerts = _read_ledger(ledger)
    blocks, head = _ledger_meta(ledger)
    sev_counts = Counter(a.get("severity", "INFO") for a in alerts)

    # Left panel — identity
    left = Text()
    for row in EYE_ART:
        left.append_text(Text.from_markup(row + "\n"))
    left.append("\n")
    left.append("  त्रिनेत्र  ·  The Third Eye\n", style="#00d7ff bold")
    left.append("  v0.2.0  ·  SIH 2026  ·  PS-26145\n", style="#555555")
    left.append("  NTRO Enclave  ·  Air-gapped  ·  Passive\n", style="#555555")
    left.append(f"\n  {REPO_ROOT}\n", style="#333355")

    # Right panel — live status
    crit = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    right = Text()
    right.append("  Forensic Ledger\n\n", style="#00d7ff bold")
    right.append("  Blocks:   ", style="#555555"); right.append(f"{blocks}\n",      style="bright_white")
    right.append("  Alerts:   ", style="#555555"); right.append(f"{len(alerts)}\n", style="bright_white")
    right.append("  Critical: ", style="#555555")
    right.append(f"{crit}\n", style="#ff5555" if crit else "bright_white")
    right.append("  High:     ", style="#555555")
    right.append(f"{high}\n",  style="#ff8c00" if high else "bright_white")
    if head != "N/A":
        right.append(f"\n  Head:     ", style="#555555")
        right.append(f"{head[:14]}…\n", style="#333355")
    right.append("\n  Recent activity\n", style="#00d7ff bold")
    if alerts:
        for a in list(reversed(alerts))[:3]:
            tc  = a.get("threat_class","UNKNOWN")
            ts  = _fmt_time(a.get("timestamp",""))
            sev = a.get("severity","INFO")
            ic  = SEV_ICONS.get(sev, ("⚪","grey70"))[0]
            right.append(f"  {ic} [{ts}] ", style="#555555")
            right.append(f"{tc}\n", style=THREAT_COLOURS.get(tc,"grey62"))
    else:
        right.append("  No recent activity\n", style="#333355")

    console.print(Columns([
        Panel(left,  border_style="#00d7ff", width=46, padding=(0,0)),
        Panel(right, border_style="#1e2030", width=38, padding=(0,0)),
    ]))
    console.print()
    console.print(Text.from_markup(
        "  [#555555]Type [/#555555][#00d7ff]/[/#00d7ff][#555555] for commands  "
        "·  [/#555555][#00d7ff]/help[/#00d7ff][#555555] to list all  "
        "·  [/#555555][#00d7ff]/quit[/#00d7ff][#555555] or Ctrl-D to exit[/#555555]"
    ))
    console.print()

# ──────────────────────────────────────────────────────────────────────────
# Bottom toolbar  — live clock, sensor status, alert count
# ──────────────────────────────────────────────────────────────────────────
def _make_toolbar(ledger: Path, session_start: float):
    """Returns an HTML callable for prompt_toolkit bottom_toolbar."""
    def toolbar():
        _, alerts = _read_ledger(ledger)
        sev = Counter(a.get("severity","INFO") for a in alerts)
        crit = sev.get("CRITICAL",0); high = sev.get("HIGH",0)
        now  = time.strftime("%H:%M:%S")
        uptime_s = int(time.time() - session_start)
        uptime = f"{uptime_s//60}m{uptime_s%60:02d}s"
        blocks, head = _ledger_meta(ledger)
        h_short = head[:8] + "…" if len(head) > 8 else head

        crit_part = f'<ansired> ⚠ {crit} CRITICAL </ansired>' if crit else ''
        high_part = f'<ansibrightred> {high} HIGH </ansibrightred>' if high else ''

        return HTML(
            f'<ansibrightblack> NTRO-ENCLAVE-α  </ansibrightblack>'
            f'<ansibrightblack>│</ansibrightblack>'
            f'<ansicyan> ⬡ PASSIVE </ansicyan>'
            f'<ansibrightblack>│</ansibrightblack>'
            f' {len(alerts)} alerts '
            f'{crit_part}{high_part}'
            f'<ansibrightblack>│</ansibrightblack>'
            f' ⛓ {blocks} blocks  {h_short} '
            f'<ansibrightblack>│</ansibrightblack>'
            f'<ansibrightblack> ⏱ {uptime}  {now} </ansibrightblack>'
        )
    return toolbar

# ──────────────────────────────────────────────────────────────────────────
# Dynamic prompt  — shows ⚠ CRITICAL count if non-zero
# ──────────────────────────────────────────────────────────────────────────
def _make_prompt(ledger: Path):
    def prompt():
        _, alerts = _read_ledger(ledger)
        sev = Counter(a.get("severity","INFO") for a in alerts)
        crit = sev.get("CRITICAL",0)
        if crit:
            return HTML(f'<ansired><b> ⚠ {crit} CRITICAL  ❯ </b></ansired>')
        return HTML('<ansicyan><b> ❯ </b></ansicyan>')
    return prompt

# ──────────────────────────────────────────────────────────────────────────
# Spinner wrapper
# ──────────────────────────────────────────────────────────────────────────
def _with_spinner(label: str, fn, *args, **kwargs):
    with Live(
        Spinner("dots2", text=Text(f" {label}…", style="#555555")),
        console=console,
        refresh_per_second=12,
        transient=True,
    ):
        result = fn(*args, **kwargs)
    return result

# ──────────────────────────────────────────────────────────────────────────
# Command handlers
# ──────────────────────────────────────────────────────────────────────────
def _cmd_help(_args, _ledger):
    console.print()
    t = Table(show_header=False, box=box.SIMPLE, show_edge=False, pad_edge=False)
    t.add_column("cmd",  style="#00d7ff", width=14, no_wrap=True)
    t.add_column("desc", style="#555555")
    for cmd, desc in SLASH_COMMANDS:
        t.add_row(cmd, desc)
    console.print(t)
    console.print()


def _cmd_clear(_args, ledger, session_start):
    _print_banner(ledger, session_start)


def _cmd_stats(_args, ledger):
    def _run():
        _, alerts = _read_ledger(ledger)
        blocks, head = _ledger_meta(ledger)
        tc_counts  = Counter(a.get("threat_class","UNKNOWN") for a in alerts)
        sev_counts = Counter(a.get("severity","INFO") for a in alerts)
        return alerts, blocks, head, tc_counts, sev_counts

    alerts, blocks, head, tc_counts, sev_counts = _with_spinner("Loading stats", _run)
    console.print()

    summary = Text()
    summary.append(f"  Alerts:        ", style="#555555"); summary.append(f"{len(alerts)}\n", style="bright_white")
    summary.append(f"  Ledger blocks: ", style="#555555"); summary.append(f"{blocks}\n",      style="bright_white")
    h = head[:16]+"…" if len(head)>16 else head
    summary.append(f"  Head hash:     ", style="#555555"); summary.append(f"{h}\n", style="#333355")
    summary.append(f"  CRITICAL:      ", style="#555555")
    summary.append(f"{sev_counts.get('CRITICAL',0)}\n", style="#ff5555" if sev_counts.get("CRITICAL",0) else "bright_white")
    summary.append(f"  HIGH:          ", style="#555555")
    summary.append(f"{sev_counts.get('HIGH',0)}\n",     style="#ff8c00" if sev_counts.get("HIGH",0)     else "bright_white")
    summary.append(f"  MEDIUM:        ", style="#555555"); summary.append(f"{sev_counts.get('MEDIUM',0)}\n", style="bright_white")
    console.print(Panel(summary, title="[#00d7ff]Stats[/#00d7ff]", border_style="#1e2030", width=52))

    if tc_counts:
        console.print()
        t = Table(show_header=True, header_style="bold #555555", box=box.SIMPLE,
                  show_edge=False, pad_edge=False)
        t.add_column("Threat Class", width=24)
        t.add_column("Count",  width=6,  justify="right")
        t.add_column("Bar",    width=30)
        t.add_column("MITRE",  width=12)
        total = sum(tc_counts.values()) or 1
        for tc, count in tc_counts.most_common():
            col = THREAT_COLOURS.get(tc, "grey62")
            bar = "█" * int(count/total*28) + "░" * (28-int(count/total*28))
            t.add_row(Text(tc, style=col), Text(str(count), style="bright_white"),
                      Text(bar, style=col), Text(MITRE_MAP.get(tc,"─"), style="#555555"))
        console.print(t)
    console.print()


def _cmd_alerts(args, ledger):
    def _run():
        _, alerts = _read_ledger(ledger)
        cls   = re.search(r"class=(\w+)", args, re.I)
        conf  = re.search(r"conf(?:idence)?([><=]+)([\d.]+)", args, re.I)
        sev   = re.search(r"sev(?:erity)?=(\w+)", args, re.I)
        limit = re.search(r"(?:n|limit)\s*=?\s*(\d+)", args, re.I)
        if cls:   alerts = [a for a in alerts if cls.group(1).upper() in a.get("threat_class","").upper()]
        if conf:
            op, val = conf.group(1), float(conf.group(2))
            def _c(c):
                if op==">": return c>val
                if op==">=": return c>=val
                if op=="<": return c<val
                return abs(c-val)<0.01
            alerts = [a for a in alerts if _c(float(a.get("confidence",0)))]
        if sev:   alerts = [a for a in alerts if a.get("severity","").upper()==sev.group(1).upper()]
        n = int(limit.group(1)) if limit else 25
        return list(reversed(alerts)), n

    show, n = _with_spinner("Loading alerts", _run)
    display = show[:n]
    console.print()

    if not display:
        console.print("  [#555555]No alerts found.[/#555555]"); console.print(); return

    t = Table(show_header=True, header_style="bold #555555", box=box.SIMPLE,
              show_edge=False, pad_edge=False, expand=True, row_styles=["","on #0a0a14"])
    t.add_column("Time",  width=9);  t.add_column("Sev",   width=11)
    t.add_column("Class", width=22); t.add_column("Src IP",width=16)
    t.add_column("Dst IP",width=16); t.add_column("Conf",  width=6, justify="right")
    t.add_column("MITRE", width=11)

    for a in display:
        tc = a.get("threat_class","UNKNOWN"); sv = a.get("severity","INFO")
        cf = float(a.get("confidence",0))
        src= (a.get("source") or {}).get("ip","─"); dst=(a.get("destination") or {}).get("ip","─")
        si, sc = SEV_ICONS.get(sv,("⚪","grey70"))
        t.add_row(
            Text(_fmt_time(a.get("timestamp","")), style="#555555"),
            Text(f"{si} {sv}", style=sc),
            Text(tc, style=THREAT_COLOURS.get(tc,"grey62")),
            Text(src, style="bright_white"), Text(dst, style="#555555"),
            Text(f"{cf:.2f}", style="bright_white"),
            Text(MITRE_MAP.get(tc,"─"), style="#555555"),
        )
    console.print(t)
    if len(show) > n:
        console.print(f"  [#555555]… {len(show)-n} more · add n=N to show more[/#555555]")
    console.print(f"\n  [#555555]Total: {len(show)}  "
                  f"[/#555555][#ff5555]CRIT: {sum(1 for a in show if a.get('severity')=='CRITICAL')}  "
                  f"[/#ff5555][#ff8c00]HIGH: {sum(1 for a in show if a.get('severity')=='HIGH')}[/#ff8c00]")
    console.print()


def _cmd_hunt(args, ledger):
    if not args.strip():
        console.print("\n  [#555555]Usage:[/#555555] /hunt class=DDOS AND confidence>0.90\n"); return

    def _run():
        _, alerts = _read_ledger(ledger)
        q = args.lower(); results = list(alerts)
        m = re.search(r"class=(\w+)", q)
        if m: results = [a for a in results if m.group(1).upper() in a.get("threat_class","")]
        m = re.search(r"confidence([><=]+)([\d.]+)", q)
        if m:
            op, val = m.group(1), float(m.group(2))
            def _cmp(c):
                if op==">": return c>val
                if op==">=": return c>=val
                if op=="<": return c<val
                return abs(c-val)<0.01
            results = [a for a in results if _cmp(float(a.get("confidence",0)))]
        m = re.search(r"severity=(\w+)", q)
        if m: results=[a for a in results if a.get("severity","").upper()==m.group(1).upper()]
        m = re.search(r"src=([\d./\w]+)", q)
        if m: results=[a for a in results if m.group(1) in (a.get("source") or {}).get("ip","")]
        m = re.search(r"since=(\d+)h", q)
        if m:
            cutoff = time.time()-int(m.group(1))*3600
            results=[a for a in results if isinstance(a.get("timestamp"),(int,float)) and a["timestamp"]>=cutoff]
        return results

    results = _with_spinner("Running hunt query", _run)
    console.print()
    console.print(f"  [#555555]Query:[/#555555] [bright_white]{args}[/bright_white]  [#555555]→[/#555555]  "
                  f"[{'#50fa7b' if results else '#ff5555'}]{len(results)} matching[/]")
    console.print()
    if not results:
        console.print("  [#555555]No matching alerts.[/#555555]"); console.print(); return

    t = Table(show_header=True, header_style="bold #555555", box=box.SIMPLE,
              show_edge=False, pad_edge=False, expand=True, row_styles=["","on #0a0a14"])
    t.add_column("Time",  width=9); t.add_column("Sev",width=11)
    t.add_column("Class", width=22); t.add_column("Src IP",width=16)
    t.add_column("Conf",  width=6, justify="right"); t.add_column("Evidence",width=38)
    for a in results[:20]:
        tc=a.get("threat_class","UNKNOWN"); sv=a.get("severity","INFO")
        si,sc=SEV_ICONS.get(sv,("⚪","grey70"))
        evs=a.get("evidence") or a.get("evidence_items") or []
        ev=" · ".join(f"{e.get('feature_name','?')}={e.get('value','?')}" for e in evs[:2]) if evs else "─"
        t.add_row(
            Text(_fmt_time(a.get("timestamp","")),style="#555555"),
            Text(f"{si} {sv}",style=sc),
            Text(tc,style=THREAT_COLOURS.get(tc,"grey62")),
            Text((a.get("source") or {}).get("ip","─"),style="bright_white"),
            Text(f"{float(a.get('confidence',0)):.2f}",style="bright_white"),
            Text(ev,style="#555555"),
        )
    console.print(t)
    if len(results)>20: console.print(f"  [#555555]… {len(results)-20} more[/#555555]")
    console.print()


def _cmd_verify(_args, ledger):
    def _run():
        errors,count,prev_hash,ok=[],0,None,True
        if not ledger.exists(): return False,0,["Ledger file not found"]
        try:
            with ledger.open("r") as fh:
                for line in fh:
                    if not line.strip(): continue
                    try:
                        data=json.loads(line)
                        bh=data.get("block_hash") or data.get("hash")
                        ph=data.get("prev_hash")
                        if prev_hash and ph!=prev_hash:
                            errors.append(f"Block {count}: prev_hash mismatch"); ok=False
                        prev_hash=bh; count+=1
                    except Exception: errors.append(f"Block {count}: parse error"); ok=False
        except OSError as e: ok=False; errors.append(str(e))
        return ok, count, errors

    ok, count, errors = _with_spinner("Verifying ledger chain", _run)
    console.print()
    if ok:
        console.print(f"  [#50fa7b]✅  ALL {count} BLOCKS VERIFIED — chain intact[/#50fa7b]")
    else:
        console.print(f"  [#ff5555]❌  CHAIN INTEGRITY FAILED — {len(errors)} error(s)[/#ff5555]")
        for e in errors[:5]: console.print(f"     [#ff5555]· {e}[/#ff5555]")
    console.print()


def _cmd_watch(_args, ledger):
    console.print()
    console.print(f"  [#555555]Streaming[/#555555] [bright_white]{ledger.name}[/bright_white] "
                  f"[#555555]— Ctrl-C to stop[/#555555]")
    console.print()
    seen: set = set()
    _, existing = _read_ledger(ledger)
    for a in existing: seen.add(a.get("alert_id", id(a)))
    console.print(f"  [#555555]{len(seen)} existing alerts loaded. Waiting for new detections…[/#555555]\n")
    counter = {"total": 0}
    try:
        while True:
            _, alerts = _read_ledger(ledger)
            for a in alerts:
                aid = a.get("alert_id", id(a))
                if aid not in seen:
                    seen.add(aid); counter["total"] += 1
                    tc=a.get("threat_class","UNKNOWN"); sv=a.get("severity","INFO")
                    cf=float(a.get("confidence",0))
                    src=(a.get("source") or {}).get("ip","─")
                    dst=(a.get("destination") or {}).get("ip","─")
                    si,sc=SEV_ICONS.get(sv,("⚪","grey70"))
                    line=Text()
                    line.append(f"[{_fmt_time(a.get('timestamp',''))}] ",style="#555555")
                    line.append(f"{si} ")
                    line.append(f"{sv:<8} ",style=sc)
                    line.append(f"{tc:<22}",style=THREAT_COLOURS.get(tc,"grey62"))
                    line.append(f" {src:<16}",style="bright_white")
                    line.append("→ ",style="#555555")
                    line.append(f"{dst:<16}",style="#555555")
                    line.append(f"  conf={cf:.2f}  [{MITRE_MAP.get(tc,'─')}]",style="#333355")
                    console.print(line)
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    console.print()
    console.print(f"  [#555555]Stopped. {counter['total']} new alerts received this session.[/#555555]\n")


def _cmd_export(args, ledger):
    fmt = args.strip().lower().split()[0] if args.strip() else ""
    _, alerts = _read_ledger(ledger)
    ts_str = time.strftime("%Y%m%d_%H%M%S")
    out = REPO_ROOT

    def _stix():
        now=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
        pat={"VOLUMETRIC_DDOS":"[network-traffic:dst_port > 0]","C2_BEACONING":"[network-traffic:dst_ref.type = 'ipv4-addr']","DGA_DOMAIN":"[domain-name:value MATCHES '[a-z0-9]{12,}']","DNS_TUNNELLING":"[network-traffic:dst_port = 53]","PORT_SCANNING":"[network-traffic:src_ref.type = 'ipv4-addr']","DATA_EXFILTRATION":"[network-traffic:dst_bytes > network-traffic:src_bytes]","TLS_MALWARE":"[network-traffic:dst_port = 443]"}
        inds=[{"type":"indicator","spec_version":"2.1","id":f"indicator--{uuid.uuid4()}","created":a.get("timestamp",now),"modified":now,"name":f"Trinetra: {a.get('threat_class','')}","indicator_types":["malicious-activity"],"pattern":pat.get(a.get("threat_class",""),f"[x-trinetra:class='{a.get('threat_class','')}']"),"pattern_type":"stix","valid_from":a.get("timestamp",now),"confidence":int(float(a.get("confidence",0.5))*100),"labels":[a.get("threat_class","").lower().replace("_","-")]} for a in alerts]
        bundle={"type":"bundle","id":f"bundle--{uuid.uuid4()}","spec_version":"2.1","objects":inds}
        fp=out/f"trinetra_stix21_{ts_str}.json"; fp.write_text(json.dumps(bundle,indent=2))
        return fp, len(inds)

    def _csv():
        import csv,io; buf=io.StringIO(); w=csv.writer(buf)
        w.writerow(["alert_id","timestamp","threat_class","severity","confidence","src_ip","dst_ip","mitre"])
        for a in alerts:
            w.writerow([a.get("alert_id",""),a.get("timestamp",""),a.get("threat_class",""),a.get("severity",""),a.get("confidence",""),(a.get("source") or {}).get("ip",""),(a.get("destination") or {}).get("ip",""),MITRE_MAP.get(a.get("threat_class",""),""),])
        fp=out/f"trinetra_alerts_{ts_str}.csv"; fp.write_text(buf.getvalue()); return fp

    def _attck():
        tc=Counter(a.get("threat_class","UNKNOWN") for a in alerts)
        layer={"name":"Trinetra Passive Detection Coverage","versions":{"attack":"14","navigator":"4.9.1","layer":"4.5"},"domain":"enterprise-attack","description":"Generated by Trinetra — SIH 2026 PS-26145","techniques":[{"techniqueID":tid,"score":min(tc.get(t,0),100),"enabled":True} for t,tid in MITRE_MAP.items()],"gradient":{"colors":["#ffffff","#ff6666"],"minValue":0,"maxValue":100}}
        fp=out/f"trinetra_attck_{ts_str}.json"; fp.write_text(json.dumps(layer,indent=2)); return fp

    console.print()
    if fmt == "stix":
        fp, n = _with_spinner("Building STIX 2.1 bundle", _stix)
        console.print(f"  [#50fa7b]✅  STIX 2.1[/#50fa7b]  [#555555]→[/#555555]  [bright_white]{fp}[/bright_white]  [#555555]({n} indicators)[/#555555]")
    elif fmt == "csv":
        fp = _with_spinner("Writing CSV", _csv)
        console.print(f"  [#50fa7b]✅  CSV[/#50fa7b]  [#555555]→[/#555555]  [bright_white]{fp}[/bright_white]  [#555555]({len(alerts)} rows)[/#555555]")
    elif fmt == "attck":
        fp = _with_spinner("Building MITRE ATT&CK layer", _attck)
        console.print(f"  [#50fa7b]✅  MITRE ATT&CK Layer[/#50fa7b]  [#555555]→[/#555555]  [bright_white]{fp}[/bright_white]")
        console.print("  [#555555]     navigator.attack.mitre.org → Open Existing Layer → Upload File[/#555555]")
    elif fmt == "incident":
        console.print("  [yellow]Incident report:[/yellow] use  [bright_white]trinetra export incident[/bright_white]  (subcommand mode)")
    else:
        console.print("  [yellow]Usage:[/yellow] /export [bright_white]stix[/bright_white] | [bright_white]csv[/bright_white] | [bright_white]attck[/bright_white] | [bright_white]incident[/bright_white]")
    console.print()

# ──────────────────────────────────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────────────────────────────────
def _dispatch(raw: str, ledger: Path, session_start: float) -> bool:
    raw = raw.strip()
    if not raw: return True
    cmd  = raw.split()[0].lower()
    args = raw[len(cmd):].strip()

    if cmd in ("/quit","/exit","/q"): return False

    table = {
        "/help":   lambda: _cmd_help(args, ledger),
        "/clear":  lambda: _cmd_clear(args, ledger, session_start),
        "/stats":  lambda: _cmd_stats(args, ledger),
        "/alerts": lambda: _cmd_alerts(args, ledger),
        "/hunt":   lambda: _cmd_hunt(args, ledger),
        "/verify": lambda: _cmd_verify(args, ledger),
        "/watch":  lambda: _cmd_watch(args, ledger),
        "/export": lambda: _cmd_export(args, ledger),
    }

    fn = table.get(cmd)
    if fn:
        fn()
    else:
        console.print(f"\n  [yellow]Unknown:[/yellow] [bright_white]{cmd}[/bright_white]  "
                      f"[#555555]— type [/#555555][#00d7ff]/[/#00d7ff][#555555] for commands[/#555555]\n")
    return True

# ──────────────────────────────────────────────────────────────────────────
# REPL
# ──────────────────────────────────────────────────────────────────────────
def _repl(ledger: Path):
    session_start = time.time()
    _print_banner(ledger, session_start)

    # Show recent alerts automatically if any exist
    _, alerts = _read_ledger(ledger)
    if alerts:
        _cmd_alerts("n=5", ledger)

    session: PromptSession = PromptSession(
        completer=SlashCompleter(),
        lexer=HuntLexer(),
        style=PROMPT_STYLE,
        history=InMemoryHistory(),
        auto_suggest=AutoSuggestFromHistory(),
        complete_while_typing=True,
        complete_in_thread=True,
        mouse_support=False,
        bottom_toolbar=_make_toolbar(ledger, session_start),
        refresh_interval=1.0,    # toolbar refreshes every second
    )

    prompt_fn  = _make_prompt(ledger)

    while True:
        try:
            raw = session.prompt(
                prompt_fn,
                rprompt=lambda: HTML(
                    f'<ansibrightblack>{time.strftime("%H:%M:%S")}</ansibrightblack>'
                ),
            )
        except (KeyboardInterrupt, EOFError):
            break

        raw = raw.strip()
        if not raw: continue

        # Auto-normalise: bare DSL queries get /hunt prefix
        if not raw.startswith("/"):
            if re.search(r"(class|confidence|severity|src|dst|since)\s*[=><!]", raw, re.I):
                raw = "/hunt " + raw
            else:
                console.print(f"\n  [#555555]Type [/#555555][#00d7ff]/[/#00d7ff][#555555] for commands[/#555555]\n")
                continue

        if not _dispatch(raw, ledger, session_start):
            break

    console.print()
    console.print(Text.from_markup(
        "[#00d7ff]  त्रिनेत्र[/#00d7ff] [#555555]— session ended. Forensic records retained.[/#555555]"
    ))
    console.print()

# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) > 1:
        _subcommand_main()
        return
    ledger_env = os.environ.get("TRINETRA_LEDGER_PATH")
    ledger = Path(ledger_env) if ledger_env else LEDGER_PATH
    try:
        _repl(ledger)
    except Exception as e:
        err.print(f"[red]Error: {e}[/red]")
        import traceback; traceback.print_exc()


def _subcommand_main():
    import argparse
    parser = argparse.ArgumentParser(prog="trinetra",
        description="Trinetra त्रिनेत्र — Passive threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `trinetra` (no args) for the interactive CLI.")
    parser.add_argument("--ledger","-l",default=str(LEDGER_PATH),metavar="FILE")
    sub = parser.add_subparsers(dest="cmd",metavar="<command>")
    sub.required = True
    p=sub.add_parser("watch");   p.add_argument("--json",action="store_true"); p.add_argument("--interval",type=float,default=1.0)
    p=sub.add_parser("alerts");  p.add_argument("--class",dest="cls"); p.add_argument("--min-conf",type=float); p.add_argument("--severity"); p.add_argument("--limit","-n",type=int); p.add_argument("--json",action="store_true")
    p=sub.add_parser("hunt");    p.add_argument("query"); p.add_argument("--json",action="store_true")
    p=sub.add_parser("stats");   p.add_argument("--json",action="store_true")
    p=sub.add_parser("verify");  p.add_argument("--json",action="store_true")
    p=sub.add_parser("export");  p.add_argument("format",choices=["stix","csv","attck","incident"]); p.add_argument("--out","-o",default="."); p.add_argument("--json",action="store_true")
    args   = parser.parse_args()
    ledger = Path(args.ledger)
    if args.cmd=="watch":    _cmd_watch("",ledger)
    elif args.cmd=="alerts":
        filt=""
        if getattr(args,"cls",None):      filt+=f" class={args.cls}"
        if getattr(args,"min_conf",None): filt+=f" conf>={args.min_conf}"
        if getattr(args,"severity",None): filt+=f" severity={args.severity}"
        if getattr(args,"limit",None):    filt+=f" n={args.limit}"
        _cmd_alerts(filt,ledger)
    elif args.cmd=="hunt":    _cmd_hunt(args.query,ledger)
    elif args.cmd=="stats":   _cmd_stats("",ledger)
    elif args.cmd=="verify":  _cmd_verify("",ledger)
    elif args.cmd=="export":  _cmd_export(args.format,ledger)


if __name__ == "__main__":
    main()
