"""
backend/trinetra/detectors/base.py

Base detector architecture and incident-level alert deduplicator.

ARCHITECTURAL INVARIANTS:
1. Every emitted alert is an aggregated incident (deduplicated across a 60-second sliding window).
2. Alerts MUST include at least one valid, interpretable EvidenceItem.
3. Zero network sockets, zero transmit capabilities.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from trinetra.schemas import (
    AlertRecord,
    Endpoint,
    EvidenceItem,
    MitreAttackRef,
    Severity,
    ThreatClass,
    ThreatIntelRef,
)


@dataclass(slots=True)
class IncidentState:
    """State of an ongoing detected incident across the sliding aggregation window."""
    threat_class: ThreatClass
    entity_id: str
    first_seen_ts: float
    last_seen_ts: float
    detection_count: int
    peak_confidence: float
    aggregated_evidence: dict[str, EvidenceItem] = field(default_factory=dict)
    primary_alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: Optional[Endpoint] = None
    destination: Optional[Endpoint] = None
    protocol: Optional[str] = None
    flow_id: Optional[str] = None
    mitre_attack: Optional[MitreAttackRef] = None
    threat_intel: Optional[ThreatIntelRef] = None
    severity: Severity = Severity.HIGH
    model_version: str = "trinetra-v2b-phase2"


class IncidentDeduplicator:
    """
    Groups raw detector firings into deduplicated incident clusters.
    
    In high-throughput optical tap feeds, raw per-flow triggers cause severe alert
    fatigue. This deduplicator clusters detections for the same entity within
    `window_seconds` into a single incident, tracking peak confidence and
    accumulated evidence items.
    """

    def __init__(self, window_seconds: float = 60.0, max_active_incidents: int = 5000) -> None:
        self.window_seconds = window_seconds
        self.max_active_incidents = max_active_incidents
        # Key: (ThreatClass, entity_id) -> IncidentState
        self.active_incidents: OrderedDict[tuple[ThreatClass, str], IncidentState] = OrderedDict()
        self.total_deduplicated_count: int = 0

    def register_detection(
        self,
        threat_class: ThreatClass,
        entity_id: str,
        timestamp: float,
        confidence: float,
        evidence: list[EvidenceItem],
        severity: Severity = Severity.HIGH,
        source: Optional[Endpoint] = None,
        destination: Optional[Endpoint] = None,
        protocol: Optional[str] = None,
        flow_id: Optional[str] = None,
        mitre_attack: Optional[MitreAttackRef] = None,
        threat_intel: Optional[ThreatIntelRef] = None,
        model_version: str = "trinetra-v2b-phase2",
    ) -> Optional[AlertRecord]:
        """
        Registers a raw detection.
        Returns an AlertRecord if this is the start of a NEW incident cluster.
        If it belongs to an existing ongoing incident within window_seconds,
        updates internal incident telemetry and returns None (deduplicated).
        """
        key = (threat_class, entity_id)

        if key in self.active_incidents:
            inc = self.active_incidents[key]
            # Check if incident is still within active window
            if timestamp - inc.last_seen_ts <= self.window_seconds:
                # Update existing incident
                self.active_incidents.move_to_end(key)
                inc.last_seen_ts = max(inc.last_seen_ts, timestamp)
                inc.detection_count += 1
                inc.peak_confidence = max(inc.peak_confidence, confidence)
                for ev in evidence:
                    inc.aggregated_evidence[ev.feature] = ev
                self.total_deduplicated_count += 1
                return None
            else:
                # Window expired, purge previous and start fresh incident
                self.active_incidents.pop(key)

        # Enforce LRU capacity bound
        if len(self.active_incidents) >= self.max_active_incidents:
            self.active_incidents.popitem(last=False)

        # Start new incident
        ev_dict = {ev.feature: ev for ev in evidence}
        # Add deduplication tracking evidence
        ev_dict["incident_cluster_size"] = EvidenceItem(
            feature="incident_cluster_size",
            value=1,
            threshold=1,
            interpretation="Initial trigger of deduplicated incident cluster",
            source="rule",
        )

        new_inc = IncidentState(
            threat_class=threat_class,
            entity_id=entity_id,
            first_seen_ts=timestamp,
            last_seen_ts=timestamp,
            detection_count=1,
            peak_confidence=confidence,
            aggregated_evidence=ev_dict,
            source=source,
            destination=destination,
            protocol=protocol,
            flow_id=flow_id,
            mitre_attack=mitre_attack,
            threat_intel=threat_intel,
            severity=severity,
            model_version=model_version,
        )
        self.active_incidents[key] = new_inc

        # Emit initial AlertRecord
        return AlertRecord(
            alert_id=new_inc.primary_alert_id,
            timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            threat_class=threat_class,
            severity=severity,
            evidence=list(ev_dict.values()),
            confidence=confidence,
            flow_id=flow_id,
            source=source,
            destination=destination,
            protocol=protocol,
            mitre_attack=mitre_attack,
            threat_intel=threat_intel,
            model_version=model_version,
        )


class BaseDetector(ABC):
    """Abstract base class for all Trinetra threat detectors."""

    def __init__(
        self,
        detector_id: str,
        threat_class: ThreatClass,
        model_version: str = "trinetra-v2b-phase2",
        confidence_threshold: float = 0.70,
        deduplicator: Optional[IncidentDeduplicator] = None,
    ) -> None:
        self.detector_id = detector_id
        self.threat_class = threat_class
        self.model_version = model_version
        self.confidence_threshold = confidence_threshold
        self.deduplicator = deduplicator or IncidentDeduplicator()

    @abstractmethod
    def evaluate(self, *args: Any, **kwargs: Any) -> Optional[AlertRecord]:
        """Evaluates extracted statistical features and emits an AlertRecord if detected."""
        raise NotImplementedError
