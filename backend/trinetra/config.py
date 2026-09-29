"""
Trinetra Enclave Configuration System.

All detection thresholds are labeled "initial heuristics — calibrate on data."
Thresholds are NEVER hard-coded elsewhere in the codebase; they always read from
EnclaveConfig (which is loaded from a TOML file or environment variables).

Per-scenario overrides: each synthetic or lab scenario supplies its own
INTERNAL_NETWORKS list so that attacker/victim IPs in private ranges are still
classified correctly (not falsely LATERAL).
"""
from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
FIXTURES_DIR = DATA_DIR / "fixtures"
SIGNATURES_DIR = DATA_DIR / "signatures"
LEDGER_DIR = DATA_DIR / "ledger"
CONFIG_DIR = BASE_DIR / "config"

for _d in (FIXTURES_DIR, SIGNATURES_DIR, LEDGER_DIR, CONFIG_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Enclave configuration
# ---------------------------------------------------------------------------
@dataclass
class EnclaveConfig:
    """
    All tuneable parameters for the Trinetra enclave sensor.

    Threshold fields are initial heuristics and MUST be calibrated on real
    labelled traffic (CTU-13, CIC-IDS2017, or your own capture) before
    citing detection performance numbers.
    """

    # ---- Sensor identity -----------------------------------------------
    sensor_id: str = "NTRO-ENCLAVE-ALPHA-01"
    environment: str = "development"          # development | production

    # ---- Network topology -----------------------------------------------
    # Default internal subnets (RFC-1918). Override per scenario.
    # IMPORTANT: In lab/synthetic scenarios where attacker & victim share
    # private ranges, supply a per-scenario override so direction labels are
    # correct (see ScenarioTopology below).
    internal_subnets_str: list[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ])

    # ---- Ingest settings -----------------------------------------------
    ring_buffer_size: int = 100_000
    micro_window_seconds: float = 1.0
    sliding_window_seconds: float = 10.0
    flow_idle_timeout_seconds: float = 30.0

    # ---- T-a: DDoS detection thresholds --------------------------------
    # Initial heuristics — calibrate on CIC-IDS2017 DDoS capture.
    ddos_syn_ratio_threshold: float = 0.80
    ddos_rate_threshold_pps: float = 5000.0
    udp_amplification_ratio_threshold: float = 20.0
    slowloris_duration_threshold_sec: float = 25.0
    slowloris_max_bps: float = 20.0

    # ---- T-b: Botnet C2 beaconing thresholds ---------------------------
    # Initial heuristics — calibrate on CTU-13 Botnet scenarios.
    beacon_min_contacts: int = 8
    beacon_max_cv: float = 0.22           # Coefficient of Variation — periodic beacons
    beacon_jitter_max_cv: float = 0.38    # CV upper bound for jittered C2 (Cobalt Strike)
    beacon_autocorr_threshold: float = 0.65  # Autocorrelation peak to flag periodicity

    # ---- T-c: DGA / DNS tunnelling thresholds --------------------------
    # Initial heuristics — calibrate on DGArchive / Tranco training splits.
    # Inspired by Leon et al. 2014 (EXPOSURE) and Schiavoni et al. 2014 (Phoenix);
    # exact values require recalibration on our own training data.
    dns_entropy_dga_threshold: float = 3.4
    dns_tunnel_length_threshold: int = 35
    dns_tunnel_entropy_threshold: float = 3.7
    dns_tunnel_txt_ratio_threshold: float = 0.25
    dns_tunnel_subdomain_cardinality_per_30s: int = 50  # Initial heuristic

    # ---- T-d: Malware in encrypted TLS sessions ------------------------
    tls_check_ja3: bool = True
    tls_pst_sequence_length: int = 10

    # ---- T-e: Recon / port scanning thresholds -------------------------
    # Initial heuristics — calibrate on CIC-IDS2017 Port Scan capture.
    scan_horizontal_dst_count: int = 15
    scan_vertical_port_count: int = 20
    scan_window_seconds: float = 10.0

    # ---- T-f: Data exfiltration thresholds -----------------------------
    # Initial heuristics — no published peer-reviewed source for these
    # exact values; calibrate on CIC-IDS2017 Infiltration scenarios.
    exfil_byte_ratio_threshold: float = 3.5
    exfil_min_outbound_bytes: int = 2 * 1024 * 1024   # 2 MB in sliding window

    # ---- Forensic ledger -----------------------------------------------
    ledger_file_path: Path = field(default_factory=lambda: LEDGER_DIR / "audit_chain.jsonl")
    blocks_per_merkle_commit: int = 10
    # Path to Ed25519 private key PEM file (generated at sensor init if absent).
    ledger_privkey_path: Path = field(default_factory=lambda: SIGNATURES_DIR / "enclave_ed25519.key")
    ledger_pubkey_path: Path = field(default_factory=lambda: SIGNATURES_DIR / "enclave_ed25519.pub")

    # ---- LLM narration -------------------------------------------------
    ollama_enabled: bool = False
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:1.5b-instruct"
    ollama_timeout_seconds: float = 10.0

    # ---- Dashboard WebSocket ------------------------------------------
    dashboard_ws_host: str = "127.0.0.1"
    dashboard_ws_port: int = 8765

    # =========================================================================
    # Helper methods — topology classification
    # =========================================================================

    def _parse_networks(
        self,
        subnets: list[str],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse subnet strings into network objects."""
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for s in subnets:
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid subnet in config: {s!r}") from exc
        return nets

    def internal_networks(
        self,
        override: Optional[list[str]] = None,
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """
        Return parsed internal networks.

        Args:
            override: Per-scenario subnet list. Overrides the global default
                      when provided. Use this for lab/synthetic scenarios where
                      attacker and victim share private IP ranges.
        """
        return self._parse_networks(override if override is not None else self.internal_subnets_str)

    def is_internal(
        self,
        ip_str: str,
        override: Optional[list[str]] = None,
    ) -> bool:
        """Return True if the IP is within the (optionally overridden) internal networks."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in self.internal_networks(override))

    def classify_direction(
        self,
        src_ip: str,
        dst_ip: str,
        override: Optional[list[str]] = None,
    ) -> str:
        """
        Classify traffic direction.

        Args:
            src_ip: Source IP address string.
            dst_ip: Destination IP address string.
            override: Per-scenario internal subnet list (e.g. victim-only
                      subnet in a lab scenario).

        Returns:
            One of: "OUTBOUND", "INBOUND", "LATERAL", "TRANSIT".
        """
        src_int = self.is_internal(src_ip, override)
        dst_int = self.is_internal(dst_ip, override)

        if src_int and not dst_int:
            return "OUTBOUND"
        elif not src_int and dst_int:
            return "INBOUND"
        elif src_int and dst_int:
            return "LATERAL"
        else:
            return "TRANSIT"


# ---------------------------------------------------------------------------
# Per-scenario topology (for lab / synthetic scenarios)
# ---------------------------------------------------------------------------
@dataclass
class ScenarioTopology:
    """
    Topology overrides for a specific test scenario.

    In lab/synthetic data, attacker and victim are often both in private IP
    ranges. Without this override, both would be classified as INTERNAL and
    all traffic would be labelled LATERAL, breaking DDoS/exfil/scan detection.

    Usage:
        topo = ScenarioTopology(
            scenario_name="ddos_syn_flood",
            internal_networks=["10.0.1.0/24"],   # victim subnet only
            attacker_networks=["10.0.2.0/24"],   # treated as external threats
        )
        direction = config.classify_direction(src, dst, topo.internal_networks)
    """
    scenario_name: str
    internal_networks: list[str]       # Victim/protected subnets only
    attacker_networks: list[str] = field(default_factory=list)  # For documentation only
    description: str = ""


# ---------------------------------------------------------------------------
# Config loader (from TOML file or defaults)
# ---------------------------------------------------------------------------
def load_config(config_file: Optional[Path] = None) -> EnclaveConfig:
    """
    Load EnclaveConfig from a TOML file.

    Falls back to default values if no file is provided or the file is absent.
    The TOML file may override any field. Unknown keys are silently ignored.

    Example TOML:
        sensor_id = "NTRO-ENCLAVE-PROD-01"
        environment = "production"
        internal_subnets_str = ["10.10.0.0/16"]
        ollama_enabled = true
    """
    if config_file is None:
        config_file = CONFIG_DIR / "enclave.toml"

    cfg = EnclaveConfig()

    if config_file.exists():
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        for key, val in data.items():
            if hasattr(cfg, key):
                object.__setattr__(cfg, key, val)

    _validate_config(cfg)
    return cfg


def _validate_config(cfg: EnclaveConfig) -> None:
    """Raise ValueError if any config field has an obviously invalid value."""
    if cfg.beacon_max_cv < 0 or cfg.beacon_max_cv > 1:
        raise ValueError(f"beacon_max_cv must be in [0, 1], got {cfg.beacon_max_cv}")
    if cfg.ddos_syn_ratio_threshold < 0 or cfg.ddos_syn_ratio_threshold > 1:
        raise ValueError(f"ddos_syn_ratio_threshold must be in [0, 1], got {cfg.ddos_syn_ratio_threshold}")
    if cfg.dns_entropy_dga_threshold < 0:
        raise ValueError(f"dns_entropy_dga_threshold must be non-negative, got {cfg.dns_entropy_dga_threshold}")
    if cfg.exfil_byte_ratio_threshold <= 0:
        raise ValueError(f"exfil_byte_ratio_threshold must be positive, got {cfg.exfil_byte_ratio_threshold}")
    if cfg.blocks_per_merkle_commit < 1:
        raise ValueError(f"blocks_per_merkle_commit must be >= 1, got {cfg.blocks_per_merkle_commit}")
    if cfg.ring_buffer_size < 100:
        raise ValueError(f"ring_buffer_size must be >= 100, got {cfg.ring_buffer_size}")
    if cfg.dns_tunnel_subdomain_cardinality_per_30s < 1:
        raise ValueError(
            f"dns_tunnel_subdomain_cardinality_per_30s must be >= 1, "
            f"got {cfg.dns_tunnel_subdomain_cardinality_per_30s}"
        )


# ---------------------------------------------------------------------------
# Module-level default instance (for convenience in tests and development)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: EnclaveConfig = load_config()
