"""
tests/test_argus_ingest.py

Tests for CTU-13 Argus binetflow parser.
"""
from pathlib import Path
from trinetra.ingest.argus import ArgusBinetflowParser

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PATH = REPO_ROOT / "data" / "baselines" / "ctu13_sample_flows.csv"


def test_parse_ctu13_sample_binetflow() -> None:
    parser = ArgusBinetflowParser()
    records = list(parser.parse_file(SAMPLE_PATH))
    assert len(records) == 6
    
    # Check first record (Benign)
    ev0, label0 = records[0]
    assert ev0.src_ip == "147.32.84.165"
    assert ev0.dst_ip == "147.32.80.9"
    assert ev0.dst_port == 53
    assert ev0.protocol == "TCP"
    assert label0 == "Flow-Benign"
    assert ev0.ingest_source == "argus_binetflow"

    # Check botnet record
    ev3, label3 = records[3]
    assert ev3.src_ip == "147.32.84.165"
    assert ev3.dst_ip == "199.59.148.10"
    assert ev3.dst_port == 80
    assert label3 == "Botnet-C2-Beacon"
