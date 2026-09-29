"""
tests/test_determinism.py

Determinism Acceptance Test (Scope Item E):
Guarantees that replaying the identical PCAP capture multiple times through the
ingest and flow table pipeline produces 100% byte-identical normalized flow outputs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from trinetra.config import EnclaveConfig
from trinetra.ingest.flow_table import FlowTable
from trinetra.ingest.pcap import PcapIngest
from trinetra.simulator import SCENARIO_DDOS_SYN_FLOOD, emit_scenario_pcap


def _run_pipeline(pcap_path: Path) -> str:
    """Run ingest + flow table pipeline and compute SHA-256 of all serialized flow outputs."""
    cfg = EnclaveConfig()
    ingest = PcapIngest()
    table = FlowTable(config=cfg, idle_timeout_seconds=2.0)

    serialized_flows: list[dict] = []

    for event in ingest.parse_file(pcap_path):
        record, expired = table.process_event(event)
        for exp in expired:
            serialized_flows.append({
                "flow_id": exp.flow_id,
                "dir": exp.direction.value,
                "fwd_pkts": exp.forward_packets,
                "fwd_bytes": exp.forward_bytes,
                "rev_pkts": exp.reverse_packets,
                "rev_bytes": exp.reverse_bytes,
                "start": exp.start_time,
                "last": exp.last_time,
                "sizes": exp.packet_sizes,
            })

    # Flush all remaining flows
    for remaining in table.flush_all():
        serialized_flows.append({
            "flow_id": remaining.flow_id,
            "dir": remaining.direction.value,
            "fwd_pkts": remaining.forward_packets,
            "fwd_bytes": remaining.forward_bytes,
            "rev_pkts": remaining.reverse_packets,
            "rev_bytes": remaining.reverse_bytes,
            "start": remaining.start_time,
            "last": remaining.last_time,
            "sizes": remaining.packet_sizes,
        })

    # Sort deterministically by flow_id + start_time
    serialized_flows.sort(key=lambda x: (x["flow_id"], x["start"]))
    canonical_json = json.dumps(serialized_flows, sort_keys=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class TestPipelineDeterminism:
    def test_pcap_replay_is_byte_identical(self, tmp_path: Path) -> None:
        """
        Verify that running the same PCAP twice produces identical SHA-256
        hashes of all aggregated flow records.
        """
        pcap_file = tmp_path / "replay_test.pcap"
        emit_scenario_pcap(SCENARIO_DDOS_SYN_FLOOD, pcap_file, max_packets=50, base_time=1700000000.0)

        hash_run_1 = _run_pipeline(pcap_file)
        hash_run_2 = _run_pipeline(pcap_file)

        assert hash_run_1 == hash_run_2, (
            f"Non-deterministic pipeline output detected!\nRun 1: {hash_run_1}\nRun 2: {hash_run_2}"
        )
