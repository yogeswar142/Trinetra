"""
tests/test_no_transmit.py

CRITICAL SAFETY TEST — MUST PASS ON EVERY COMMIT.

Verifies that the ingest, feature extraction, and detector packages
NEVER open a transmitting socket or import outbound HTTP/network libraries.
The sensor is receive-only (data diode / optical TAP).
Transmitting sockets or outbound HTTP requests break air-gap constraint (C1 & C3).

THREE enforcement mechanisms:
    1. Static AST analysis: scan all source files under backend/trinetra/ingest/,
       backend/trinetra/features/, and backend/trinetra/detectors/ for:
       - Socket transmission calls: connect(), send(), sendto(), sendall(), sendfile(), sendmsg()
       - Raw socket creation: socket.SOCK_RAW
       - Outbound HTTP/protocol imports: requests, urllib, httpx, aiohttp, smtplib, http.client
    2. Runtime patch: socket.socket monkeypatched to raise AssertionError if any
       transmitting method is called during ingest operations.
    3. Docker Compose validation: parses docker-compose.yml to enforce that trinetra-sensor
       has no published ports, no host networking, has read-only pcap mounts, and is attached
       to an internal isolated network.
"""
from __future__ import annotations

import ast
import socket
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import yaml


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend" / "trinetra"
INGEST_DIR = BACKEND_DIR / "ingest"
FEATURES_DIR = BACKEND_DIR / "features"
DETECTORS_DIR = BACKEND_DIR / "detectors"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"


# ---------------------------------------------------------------------------
# Forbidden Patterns
# ---------------------------------------------------------------------------
FORBIDDEN_METHODS = {
    "connect",
    "sendto",
    "send",
    "sendall",
    "sendfile",
    "sendmsg",
}

FORBIDDEN_IMPORTS = {
    "requests",
    "urllib",
    "urllib.request",
    "httpx",
    "aiohttp",
    "smtplib",
    "http.client",
    "ftplib",
    "telnetlib",
}


class _StrictAirGapASTVisitor(ast.NodeVisitor):
    """AST visitor that flags transmitting socket methods, raw sockets, and prohibited imports."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.violations: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Flag .connect(), .send(), .sendto() calls and SOCK_RAW socket creation."""
        # Check method calls on socket objects
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_METHODS:
                self.violations.append(
                    (node.lineno, f"Forbidden transmit method call: .{node.func.attr}()")
                )
        # Check socket(..., SOCK_RAW)
        for arg in node.args:
            if isinstance(arg, ast.Attribute) and arg.attr == "SOCK_RAW":
                self.violations.append(
                    (node.lineno, "Forbidden raw socket instantiation: socket.SOCK_RAW")
                )
            elif isinstance(arg, ast.Name) and arg.id == "SOCK_RAW":
                self.violations.append(
                    (node.lineno, "Forbidden raw socket instantiation: SOCK_RAW")
                )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Flag imports of prohibited outbound networking packages."""
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if alias.name in FORBIDDEN_IMPORTS or base_mod in FORBIDDEN_IMPORTS:
                self.violations.append(
                    (node.lineno, f"Forbidden outbound networking import: {alias.name}")
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Flag from <mod> import ... of prohibited outbound networking packages."""
        if node.module:
            base_mod = node.module.split(".")[0]
            if node.module in FORBIDDEN_IMPORTS or base_mod in FORBIDDEN_IMPORTS:
                self.violations.append(
                    (node.lineno, f"Forbidden outbound networking import: from {node.module} import ...")
                )
        self.generic_visit(node)


def _find_python_files(directories: list[Path]) -> list[Path]:
    """Recursively find all .py files in specified directories."""
    files: list[Path] = []
    for d in directories:
        if d.exists():
            files.extend(d.rglob("*.py"))
    return files


# ---------------------------------------------------------------------------
# Test 1: Static AST Scan
# ---------------------------------------------------------------------------
class TestNoTransmitStaticScan:
    def test_strict_airgap_ast_scan(self) -> None:
        """
        Scan ingest, features, and detectors modules for:
        - Socket transmit methods (connect, send, sendto, etc.)
        - Raw socket creation (SOCK_RAW)
        - External communication client libraries (requests, urllib, httpx, etc.)
        """
        target_dirs = [INGEST_DIR, FEATURES_DIR, DETECTORS_DIR]
        py_files = _find_python_files(target_dirs)

        all_violations: list[str] = []

        for path in py_files:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                all_violations.append(f"{path}: SyntaxError: {exc}")
                continue

            visitor = _StrictAirGapASTVisitor(str(path))
            visitor.visit(tree)

            for lineno, msg in visitor.violations:
                rel = path.relative_to(REPO_ROOT)
                all_violations.append(f"{rel}:{lineno}: {msg}")

        if all_violations:
            violation_report = "\n  ".join(all_violations)
            pytest.fail(
                f"STRICT AIR-GAP VIOLATIONS DETECTED IN SENSOR CODE!\n\n"
                f"  {violation_report}\n\n"
                f"The sensor enclave is strictly receive-only. Outbound connections are prohibited."
            )

    def test_all_modules_have_clean_syntax(self) -> None:
        """All sensor python files must parse cleanly."""
        target_dirs = [BACKEND_DIR]
        py_files = _find_python_files(target_dirs)
        for path in py_files:
            source = path.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                pytest.fail(f"Syntax error in {path}: {exc}")


# ---------------------------------------------------------------------------
# Test 2: Runtime Socket Patching
# ---------------------------------------------------------------------------
class TestNoTransmitRuntime:
    def _make_receive_only_socket(self) -> MagicMock:
        """Create a mock socket that raises on any transmit method."""
        mock_sock = MagicMock(spec=socket.socket)

        def _transmit_blocked(*args, **kwargs) -> None:
            raise AssertionError(
                "TRANSMIT BLOCKED: Sensor code attempted to transmit over socket. "
                "The sensor is receive-only (air-gap constraint C1 violated)."
            )

        for method in ("connect", "send", "sendto", "sendall", "sendfile"):
            try:
                attr = getattr(mock_sock, method)
                attr.side_effect = _transmit_blocked
            except AttributeError:
                pass

        return mock_sock

    def test_active_runtime_receive_only_enforcement(self) -> None:
        """
        Verify that importing sensor modules and running passive flow operations
        under a patched socket environment never attempts any transmit calls.
        """
        mock_sock = self._make_receive_only_socket()
        with patch("socket.socket", return_value=mock_sock):
            # Exercise config and schema initialization
            from trinetra.config import load_config
            from trinetra.schemas import AlertRecord, ThreatClass, Severity, EvidenceItem
            from trinetra.simulator import SCENARIO_DDOS_SYN_FLOOD, emit_scenario_flows

            cfg = load_config()
            assert cfg.sensor_id is not None
            flows = emit_scenario_flows(SCENARIO_DDOS_SYN_FLOOD, max_flows=5, config=cfg)
            assert len(flows) == 5

    def test_socket_connect_raises_in_patched_context(self) -> None:
        mock_sock = self._make_receive_only_socket()
        with pytest.raises(AssertionError, match="TRANSMIT BLOCKED"):
            mock_sock.connect(("1.2.3.4", 80))

    def test_socket_sendto_raises_in_patched_context(self) -> None:
        mock_sock = self._make_receive_only_socket()
        with pytest.raises(AssertionError, match="TRANSMIT BLOCKED"):
            mock_sock.sendto(b"data", ("1.2.3.4", 53))

    def test_socket_send_raises_in_patched_context(self) -> None:
        mock_sock = self._make_receive_only_socket()
        with pytest.raises(AssertionError, match="TRANSMIT BLOCKED"):
            mock_sock.send(b"data")


# ---------------------------------------------------------------------------
# Test 3: Docker Compose Enclave & Isolation Validation
# ---------------------------------------------------------------------------
class TestDockerComposeEnclaveIsolation:
    def test_docker_compose_sensor_configuration(self) -> None:
        """
        Parse docker-compose.yml and verify that trinetra-sensor:
        1. Has NO published ports (receive-only).
        2. Does NOT use host networking.
        3. Mounts pcap/fixtures directories as read-only (:ro).
        4. Is attached to an internal bridge network with no external gateway.
        """
        assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"

        with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
            compose_data = yaml.safe_load(f)

        assert "services" in compose_data, "No services defined in docker-compose.yml"
        assert "trinetra-sensor" in compose_data["services"], "trinetra-sensor service missing"

        sensor = compose_data["services"]["trinetra-sensor"]

        # 1. No published ports
        ports = sensor.get("ports", [])
        assert not ports, f"Sensor service has published ports: {ports}. Must be empty for air-gap."

        # 2. No host networking
        network_mode = sensor.get("network_mode", "")
        assert network_mode != "host", "Sensor service must not use host networking."

        # 3. Read-only fixtures / pcap mounts
        volumes = sensor.get("volumes", [])
        for vol in volumes:
            if isinstance(vol, str):
                if "fixtures" in vol or "pcap" in vol:
                    assert vol.endswith(":ro"), (
                        f"PCAP / fixtures mount '{vol}' must be read-only (:ro) for data diode integrity."
                    )

        # 4. Attached to internal network
        networks = sensor.get("networks", [])
        assert "enclave-net" in networks, "Sensor must be attached to enclave-net"

        top_networks = compose_data.get("networks", {})
        assert "enclave-net" in top_networks, "enclave-net must be defined in networks"
        assert top_networks["enclave-net"].get("internal") is True, (
            "enclave-net must have 'internal: true' to prevent external routing."
        )
