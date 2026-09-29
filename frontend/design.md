# Trinetra SOC UI — Design Spec

**Status:** APPROVED + implementing (Geist Dark Ops · 6-route IA)  
**Product:** Trinetra (ThreatNexus) · SIH 26145 · NTRO diode enclave  
**Inspired by:** Vercel Geist · production SOC consoles (Elastic / Splunk-style IA) · modern investigation workbenches  

---

## 1. What production SOC dashboards actually look like

Real SOC UIs are **not** neon cyberpunk marketing pages. Patterns that recur across Elastic Security, Splunk ES, Microsoft Sentinel, Chronicle, and modern AI-SOC consoles:

| Pattern | Why it exists |
|---------|----------------|
| **Alert queue is home** | Analysts answer “what do I work next?” — not stare at wallpaper charts |
| **Two-pane investigate** | List left + context rail right (summary, entities, evidence, actions) |
| **Severity + recency sort** | Critical/High rise; noise is filtered, not celebrated |
| **Lean sidebar (≤ 6–8 items)** | Cognitive load kills triage speed |
| **Dark, low-chroma chrome** | Hours of screen time; color reserved for *state* |
| **Dense tables, sparse decoration** | Data density beats card spam |
| **Hunt is a mode, not a mascot page** | Query/filter lives on Alerts |
| **Health/sensor is secondary** | Ops need it; it is not the hero |
| **Exports are actions** | Buttons on Ledger/Alerts — not a nav destination |

**Trinetra-specific twist (keep):** Merkle ledger + air-gap / no-TX posture are our differentiators vs generic SIEM clones. They deserve a first-class **Ledger** route, not a gimmick panel.

---

## 2. Vercel / Geist inspiration (adapted, not copied)

From [Geist Colors](https://vercel.com/geist/colors) and [Typography](https://vercel.com/geist/typography):

### Principles we adopt
1. **Monochrome chrome first** — gray scale does layout; color = meaning only  
2. **High contrast text** — step 1000 primary / 900 secondary  
3. **Hairline borders** — gray-400 default, not glowing neon frames  
4. **Geist Sans + Geist Mono** — sans for UI; mono *only* for IPs, hashes, timestamps, IDs  
5. **Restraint** — no decorative glow bars, no purple gradients, no emoji nav  
6. **Grid + whitespace** — calm density; one clear page job  

### Principles we do *not* copy blindly
- Marketing-hero display sizes (SOC needs `heading-24` / `heading-20`, not 72)  
- Light-theme default (SOC stays dark)  
- Generic SaaS “violet CTA”  

---

## 3. Proposed palette — **Geist Dark Ops**

Semantic tokens mapped to Geist-like steps (dark theme). Hex are implementation targets.

### Surfaces (gray scale)
| Token | Hex | Use |
|-------|-----|-----|
| `--bg-0` | `#000000` | App canvas |
| `--bg-1` | `#0A0A0A` | Sidebar / header |
| `--bg-2` | `#111111` | Panels / cards |
| `--bg-3` | `#1A1A1A` | Hover / elevated |
| `--border` | `#333333` | Default border (`gray-400` role) |
| `--border-hover` | `#444444` | Hover border |
| `--text-primary` | `#EDEDED` | Primary text (`gray-1000`) |
| `--text-secondary` | `#A1A1A1` | Secondary (`gray-900`) |
| `--text-dim` | `#666666` | Meta / captions |

### State color (meaning only)
| Token | Hex | Use |
|-------|-----|-----|
| `--blue` | `#0070F3` | Primary interactive / focus (Geist blue-700 role) |
| `--red` | `#EE0000` | Critical / breach |
| `--amber` | `#F5A623` | High / warning |
| `--green` | `#0C8C4A` or `#50E3C2`-muted `#00C48C` | Verified / nominal / ok |
| `--teal` | `#00ACB5` | TLS / intel secondary (optional) |

### Threat accents (badges only — not page chrome)
| Threat | Color |
|--------|-------|
| DDoS / Critical | `--red` |
| C2 / High | `--amber` |
| DGA / DNS | `#C9A227` |
| Exfil | soft purple `#8B5CF6` *only on badge* |
| Scan | `--text-secondary` |
| TLS | `--teal` |

### Materials
- Radius: `6px` controls, `8px` panels (Geist-like, not 20px pills everywhere)  
- Shadow: single soft `0 1px 0 rgba(255,255,255,0.04) inset` + optional `0 8px 24px rgba(0,0,0,0.4)`  
- **No** multi-layer neon glows on cards  

### Typography
| Role | Font | Size / weight |
|------|------|----------------|
| Page title | Geist Sans | 24 / 600 |
| Section | Geist Sans | 16–20 / 600 |
| Body / labels | Geist Sans | 13–14 / 400–500 |
| Nav item | Geist Sans | 13–14 / 500 |
| IP, hash, ts, IDs | Geist Mono | 12–13 / 400 |

Load via `next/font` (`Geist`, `Geist_Mono`) — drop Manrope / IBM Plex for one coherent system.

---

## 4. Layout system

```
┌──────────────────────────────────────────────────────────┐
│ Top bar: mark · sensor id · live · clock · air-gap chip  │
├────────────┬─────────────────────────────────────────────┤
│ Sidebar    │ Page header (title + 1-line job)            │
│ ~220px     ├─────────────────────────────────────────────┤
│            │ Main workbench (route-specific)             │
│            │                                             │
└────────────┴─────────────────────────────────────────────┘
```

- Sticky header + sticky sidebar  
- Content max readable width for prose; full bleed for tables / globe  
- Shared `PageHeader`: **title + one sentence job** (no duplicate H1s)  

---

## 5. Sidebar IA — what to keep (proposal)

Today we have **too many** peer routes. Production SOCs keep nav lean.

### Proposed primary nav (6 items)

| # | Label | Route | Job (one sentence) | Decision |
|---|-------|-------|--------------------|----------|
| 1 | **Overview** | `/` | Shift snapshot: KPIs, mini-globe, top critical alerts | **KEEP** (rename from Command Center) |
| 2 | **Alerts** | `/alerts` | Triage queue + filters + hunt DSL + open investigation | **KEEP** — merge `/threats` + `/hunt` |
| 3 | **Globe** | `/globe` | Interactive situational map of active vectors | **KEEP** (full-page focus) |
| 4 | **Ledger** | `/ledger` | Merkle / Ed25519 chain of custody | **KEEP** (theme differentiator) |
| 5 | **Sensor** | `/sensor` | Throughput, latency, no-TX posture, detector arming | **KEEP** — absorb `/detectors` + `/models` as tabs/sections |
| 6 | **Settings** | `/settings` | Enclave posture & config summary | **KEEP** |

### Contextual (not sidebar)
| Route | How you get there |
|-------|-------------------|
| `/forensics/[alertId]` | Click alert row / globe focus |
| `/api/docs` | Footer link “API” under sidebar |

### Remove from sidebar (fold elsewhere)

| Current | Action |
|---------|--------|
| `/threats` | → rename/redirect to `/alerts` |
| `/hunt` | → filter bar / mode on `/alerts` |
| `/detectors` | → section/tab on `/sensor` |
| `/models` | → section/tab on `/sensor` |
| `/exports` | → action buttons on Ledger + Alerts (STIX / CSV / verify) |
| API Docs in main nav | → sidebar footer only |

### Suggested sidebar chrome
```
TRINETRA
SOC ENCLAVE

Overview
Alerts          [badge: N]
Globe
Ledger
Sensor
Settings

────────────
API  ·  v0.2
READ-ONLY · AIR-GAP
```

---

## 6. Page jobs (continuity checklist)

Every page must answer one question:

| Page | Question |
|------|----------|
| Overview | Is the enclave healthy, and what is on fire *now*? |
| Alerts | What should I triage next? |
| Globe | Where are vectors concentrating (offline geo)? |
| Ledger | Can I prove the alert chain was not tampered? |
| Sensor | Is ingest/detection meeting measured targets? |
| Settings | What posture is this enclave running under? |
| Forensics | Why did *this* alert fire, with evidence? |

If a widget does not serve that question, it does not belong on the page.

---

## 7. Alerts workbench shape (target)

Inspired by modern SOC investigation rails:

```
┌─────────────────────────┬──────────────────────────┐
│ Filters + hunt query    │                          │
├─────────────────────────┤  Investigation rail      │
│ Alert rows (dense)      │  - summary               │
│ severity · class · conf │  - src/dst · MITRE       │
│                         │  - evidence              │
│                         │  - ledger leaf           │
│                         │  - Open full forensics   │
└─────────────────────────┴──────────────────────────┘
```

Overview keeps a **short** critical queue + KPIs + compact globe — not a second full alerts page.

---

## 8. Globe rules

- Interactive: orbit / zoom / pause / focus (already started)  
- Markers/arcs use **state colors**, not decorative rainbow  
- Selection updates the rail; deep link to forensics  
- No external GeoIP (air-gap) — keep deterministic IP→lat/lng  

---

## 9. Implementation phases (after approval)

1. **Tokens + fonts** — Geist Dark Ops in `globals.css` + `layout.tsx`  
2. **IA cut** — redirects, merge pages, sidebar = 6 items  
3. **Alerts workbench** — two-pane queue + rail  
4. **Sensor consolidation** — detectors + models as sections  
5. **Visual QA** — every route shares header/sidebar continuity  

---

## 10. Explicit non-goals

- Purple neon “AI cyber” look  
- Sidebar with 10+ peers  
- Exports / API docs as primary destinations  
- Light theme for SIH demo (optional later)  
- Fake 99.9% accuracy widgets  

---

## Decision needed from you

Please confirm or adjust:

1. **Palette:** Geist Dark Ops (black/gray + blue focus + red/amber/green state) — yes / tweak?  
2. **Fonts:** Geist Sans + Geist Mono — yes / keep Manrope?  
3. **Sidebar 6:** Overview · Alerts · Globe · Ledger · Sensor · Settings — yes / change list?  
4. **Merge:** Hunt into Alerts; Detectors+Models into Sensor; Exports as actions — yes / no?

Once you say go, implementation follows this file only.
