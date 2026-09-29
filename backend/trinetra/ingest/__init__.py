"""
Trinetra Ingest Subsystem.

Contains receive-only network packet and binary flow ingest modules:
- pcap.py: dpkt-based raw packet parser for classic pcap & pcapng with VLAN/IPv6 support
- netflow.py: RFC 3954 NetFlow v9 binary parser with out-of-order template caching
- flow_table.py: Bidirectional stateful flow tracking with deterministic timestamp expiry
- tcp_tracker.py: Passive TCP state machine for mirrored optical TAP links
"""
from __future__ import annotations
