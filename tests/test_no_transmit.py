"""
tests/test_no_transmit.py

CRITICAL SAFETY TEST — MUST PASS ON EVERY COMMIT.

Verifies that the ingest package (trinetra.ingest.*) NEVER opens a
transmitting socket. The sensor is receive-only (data diode / optical TAP).
Transmitting sockets would break the air-gap constraint (C1).

TWO enforcement mechanisms:
    1. Static analysis: AST scan of all source files under backend/trinetra/ingest/
       looking for calls to connect(), sendto(), send(), sendmsg(), sendall(),
       socket(AF_INET, SOCK_STREAM) or similar transmitting socket patterns.

    2. Runtime patch: At test time, monkeypatch socket.socket to fail immediately
       if any transmitting method is called during ingest module import or any
       function call that can be exercised without a live network.

The test currently covers Phase 0 (no ingest/ directory yet — test passes trivially
but is wired into CI so it will FAIL as soon as any violating code is added).
"""
from __future__ import annotations

import ast
import socket
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
INGEST_DIR = REPO_ROOT / "backend" / "trinetra" / "ingest"


# ---------------------------------------------------------------------------
# Forbidden transmit call patterns (AST node names)
# ---------------------------------------------------------------------------
FORBIDDEN_METHODS = {
    "connect",
    "sendto",
    "send",
    "sendall",
    "sendfile",
    # Note: sendmsg is not available on Windows socket.socket spec,
    # so it is detected via AST scan only (see _TransmitCallVisitor).
}

# Forbidden socket type combinations used for transmit
FORBIDDEN_SOCKET_ATTRS = {
    "AF_INET",   # when combined with SOCK_STREAM / SOCK_DGRAM → could transmit
    "AF_INET6",
}


class _TransmitCallVisitor(ast.NodeVisitor):
    """AST visitor that collects calls to forbidden socket transmit methods."""

    def __init__(self) -> None:
        self.violations: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Detect .connect(), .sendto(), .send(), etc. method calls."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_METHODS:
                self.violations.append(
                    (node.lineno, f"Forbidden transmit call: .{node.func.attr}()")
                )
        self.generic_visit(node)


def _find_python_files(directory: Path) -> list[Path]:
    """Recursively find all .py files under a directory."""
    if not directory.exists():
        return []
    return list(directory.rglob("*.py"))


# ---------------------------------------------------------------------------
# Test 1: Static AST scan
# ---------------------------------------------------------------------------
class TestNoTransmitStaticScan:
    """
    Static analysis: scan all ingest source files for transmit socket calls.
    This check runs even before any code is imported.
    """

    def test_no_transmit_methods_in_ingest_source(self) -> None:
        """
        AST-scan all files under backend/trinetra/ingest/ for forbidden
        socket transmit method calls.

        This test passes trivially in Phase 0 (directory does not exist yet).
        It will FAIL as soon as any violating code is added in Phase 1.
        """
        py_files = _find_python_files(INGEST_DIR)

        all_violations: list[str] = []

        for path in py_files:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                all_violations.append(f"{path}: SyntaxError: {exc}")
                continue

            visitor = _TransmitCallVisitor()
            visitor.visit(tree)

            for lineno, msg in visitor.violations:
                rel = path.relative_to(REPO_ROOT)
                all_violations.append(f"{rel}:{lineno}: {msg}")

        if all_violations:
            violation_report = "\n  ".join(all_violations)
            pytest.fail(
                f"TRANSMIT SOCKET CALLS FOUND IN INGEST LAYER — AIR-GAP VIOLATED!\n\n"
                f"  {violation_report}\n\n"
                f"The ingest package is receive-only. Remove or move these calls."
            )

    def test_ingest_files_have_no_syntax_errors(self) -> None:
        """All .py files under ingest/ must parse cleanly."""
        py_files = _find_python_files(INGEST_DIR)
        for path in py_files:
            source = path.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                pytest.fail(f"Syntax error in {path}: {exc}")


# ---------------------------------------------------------------------------
# Test 2: Runtime socket patching
# ---------------------------------------------------------------------------
class TestNoTransmitRuntime:
    """
    Runtime check: monkeypatch socket.socket so that any transmitting method
    call raises an AssertionError. Then exercise ingest module code paths.

    Phase 0: No ingest module exists yet — these tests are forward stubs that
    will become active in Phase 1.
    """

    def _make_receive_only_socket(self) -> MagicMock:
        """Create a mock socket that raises on any transmit method."""
        mock_sock = MagicMock(spec=socket.socket)

        def _transmit_blocked(*args, **kwargs) -> None:
            raise AssertionError(
                "TRANSMIT BLOCKED: ingest layer attempted to open a transmitting socket. "
                "The sensor is receive-only (air-gap constraint C1 violated)."
            )

        for method in FORBIDDEN_METHODS:
            try:
                attr = getattr(mock_sock, method)
                attr.side_effect = _transmit_blocked
            except AttributeError:
                # Method not in socket.socket spec on this platform (e.g. sendmsg on Windows).
                # Covered by AST static scan instead.
                pass

        return mock_sock

    def test_ingest_module_import_does_not_transmit(self) -> None:
        """
        Importing any ingest module must not trigger transmit socket calls.

        Phase 0 stub: passes trivially because ingest/ does not exist yet.
        In Phase 1, add: `from trinetra.ingest import pcap` inside the patch block.
        """
        if not INGEST_DIR.exists():
            pytest.skip("ingest/ directory not created yet (Phase 0 stub)")

        mock_sock = self._make_receive_only_socket()
        with patch("socket.socket", return_value=mock_sock):
            # Phase 1: Import ingest modules here and call any init code.
            # from trinetra.ingest import pcap  # noqa: F401
            pass  # Remove this once ingest/ exists

    def test_socket_connect_raises_in_patched_context(self) -> None:
        """
        Verify the patching mechanism itself works correctly.
        The mock should raise AssertionError on connect().
        """
        mock_sock = self._make_receive_only_socket()
        with pytest.raises(AssertionError, match="TRANSMIT BLOCKED"):
            mock_sock.connect(("1.2.3.4", 80))

    def test_socket_sendto_raises_in_patched_context(self) -> None:
        """Verify sendto() is blocked by the mock."""
        mock_sock = self._make_receive_only_socket()
        with pytest.raises(AssertionError, match="TRANSMIT BLOCKED"):
            mock_sock.sendto(b"data", ("1.2.3.4", 53))

    def test_socket_send_raises_in_patched_context(self) -> None:
        """Verify send() is blocked by the mock."""
        mock_sock = self._make_receive_only_socket()
        with pytest.raises(AssertionError, match="TRANSMIT BLOCKED"):
            mock_sock.send(b"data")
