"""
backend/trinetra/ingest/argus.py

Parser for Argus Binetflow records (CTU-13 dataset format).

Provides a streaming reader that converts Argus binetflow CSV records
into Trinetra FlowEvent objects, enabling unified training and evaluation
on CTU-13 benchmark traces.

Reference:
    Garcia, S., Grill, M., Stiborek, J., & Zunino, A. (2014).
    An empirical comparison of botnet detection methods.
    Computers & Security, 45, 100-123.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
from pathlib import Path
from typing import Generator, Iterator, Optional, TextIO, Tuple, Union

from trinetra.schemas import Direction, FlowEvent


def _parse_argus_port(raw_port: str) -> int:
    """Parses port string which can be decimal integer, hex (0x...), or service name."""
    raw = raw_port.strip().lower()
    if not raw:
        return 0
    if raw.startswith("0x"):
        try:
            return int(raw, 16)
        except ValueError:
            return 0
    try:
        return int(raw)
    except ValueError:
        # Standard well-known service fallbacks
        service_map = {"http": 80, "https": 443, "domain": 53, "dns": 53, "ssh": 22, "ntp": 123}
        return service_map.get(raw, 0)


def _parse_argus_state(state: str) -> dict[str, bool]:
    """Infers TCP flag indicators from Argus state string (e.g. SR, CON, EST, RST, S_RA)."""
    s = state.upper()
    flags = {
        "SYN": "S" in s,
        "ACK": "A" in s or "CON" in s or "EST" in s,
        "FIN": "F" in s,
        "RST": "RST" in s or "R" in s,
        "PSH": "P" in s,
        "URG": "U" in s,
    }
    return flags


def _parse_argus_timestamp(ts_str: str) -> float:
    """Parses Argus timestamp format: '2011-08-10 11:04:00.000' or ISO."""
    clean = ts_str.strip()
    try:
        dt = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        try:
            dt = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            try:
                dt = datetime.fromisoformat(clean)
                return dt.timestamp()
            except ValueError:
                return 0.0


class ArgusBinetflowParser:
    """
    Streaming parser for Argus .binetflow / CSV files.
    """

    def parse_stream(
        self, stream: TextIO
    ) -> Generator[tuple[FlowEvent, str], None, None]:
        """
        Parses text stream row-by-row and yields (FlowEvent, ground_truth_label).
        """
        reader = csv.DictReader(stream)
        for row in reader:
            ts = _parse_argus_timestamp(row.get("StartTime", ""))
            proto = row.get("Proto", "tcp").upper()
            src_ip = row.get("SrcAddr", "").strip()
            dst_ip = row.get("DstAddr", "").strip()
            src_port = _parse_argus_port(row.get("Sport", "0"))
            dst_port = _parse_argus_port(row.get("Dport", "0"))
            state = row.get("State", "")
            tcp_flags = _parse_argus_state(state) if proto == "TCP" else None
            
            try:
                tot_bytes = int(row.get("TotBytes", 0))
            except ValueError:
                tot_bytes = 0
            
            try:
                tot_pkts = int(row.get("TotPkts", 1))
            except ValueError:
                tot_pkts = 1
                
            label = row.get("Label", "Normal").strip()
            direction = Direction.OUTBOUND if "->" in row.get("Dir", "") else Direction.LATERAL

            event = FlowEvent.model_construct(
                timestamp=ts,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                length=tot_bytes // max(tot_pkts, 1),
                tcp_flags=tcp_flags,
                direction=direction,
                ingest_source="argus_binetflow",
            )
            yield event, label

    def parse_file(
        self, file_path: Union[str, Path]
    ) -> Generator[tuple[FlowEvent, str], None, None]:
        """Convenience method to stream parse from file path."""
        p = Path(file_path)
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            yield from self.parse_stream(f)
