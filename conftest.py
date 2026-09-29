"""
conftest.py — pytest configuration and shared fixtures.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend is on the Python path for all tests
backend_dir = Path(__file__).resolve().parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
