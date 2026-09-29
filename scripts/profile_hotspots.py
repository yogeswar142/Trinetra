"""
Profile the full pipeline on realistic_mixed_500k.pcap to identify top 10 CPU hotspots.
"""
from __future__ import annotations

import cProfile
import io
import pstats
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from trinetra.config import EnclaveConfig
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest

PCAP_PATH = REPO_ROOT / "data" / "fixtures" / "realistic_mixed_500k.pcap"


def run_pipeline(max_packets: int = 50_000) -> None:
    ingest = PcapIngest()
    cfg = EnclaveConfig()
    table = FlowTable(config=cfg, idle_timeout_seconds=30.0, max_flows=100_000)

    count = 0
    with open(PCAP_PATH, "rb") as f:
        for event in ingest.parse_stream(f):
            table.process_event(event)
            count += 1
            if count >= max_packets:
                break
    table.flush_all()
    print(f"Processed {count:,} packets through full pipeline.")


if __name__ == "__main__":
    profiler = cProfile.Profile()
    profiler.enable()
    run_pipeline(50_000)
    profiler.disable()

    s = io.StringIO()
    ps = pstats.Stats(profiler, stream=s).sort_stats(pstats.SortKey.CUMULATIVE)
    ps.print_stats(25)
    print("=== TOP 25 HOTSPOTS (CUMULATIVE TIME) ===")
    print(s.getvalue())

    s_tot = io.StringIO()
    ps_tot = pstats.Stats(profiler, stream=s_tot).sort_stats(pstats.SortKey.TIME)
    ps_tot.print_stats(25)
    print("=== TOP 25 HOTSPOTS (TOTAL TIME / INTERNAL) ===")
    print(s_tot.getvalue())
