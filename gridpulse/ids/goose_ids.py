import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from .rules import Alert, AlertSeverity, RuleRegistry, DetectionRule
from .mitre_mapper import MITREMapper

@dataclass
class IDSConfig:
    burst_threshold_pps: int = 1000
    max_sqnum_gap: int = 10
    max_timestamp_drift_sec: float = 5.0
    max_state_changes_per_sec: int = 10
    known_publishers: List[str] = field(default_factory=list)

@dataclass
class IDSStats:
    frames_processed: int = 0
    alerts_generated: int = 0
    alerts_by_severity: Dict[AlertSeverity, int] = field(default_factory=lambda: {sev: 0 for sev in AlertSeverity})
    alerts_by_rule: Dict[str, int] = field(default_factory=dict)

@dataclass
class PublisherState:
    last_stNum: int = 0
    last_sqNum: int = 0
    last_timestamp: float = 0.0
    last_confRev: int = 0
    retransmission_intervals: List[float] = field(default_factory=list)
    frame_count: int = 0
    burst_start_time: float = 0.0
    burst_count: int = 0
    state_change_count: int = 0
    state_change_start_time: float = 0.0

class GOOSEIDSEngine:
    def __init__(self, config: Optional[IDSConfig] = None) -> None:
        self.config = config or IDSConfig()
        self.stats = IDSStats()
        self.publisher_states: Dict[str, PublisherState] = {}
        self.mitre_mapper = MITREMapper()
        
        # Pre-register known publishers
        self.known_publishers = set(self.config.known_publishers)

    def _create_alert(self, rule_id: str, severity: AlertSeverity, source_mac: str, description: str, frame_snapshot: Optional[Dict[str, Any]] = None) -> Alert:
        technique = self.mitre_mapper.map_alert(rule_id)
        mitre_id = technique.technique_id if technique else None
        
        alert = Alert(
            rule_id=rule_id,
            severity=severity,
            source_mac=source_mac,
            description=description,
            timestamp=time.time(),
            frame_snapshot=frame_snapshot,
            mitre_technique=mitre_id
        )
        
        self.stats.alerts_generated += 1
        self.stats.alerts_by_severity[severity] += 1
        self.stats.alerts_by_rule[rule_id] = self.stats.alerts_by_rule.get(rule_id, 0) + 1
        
        return alert

    def process_frame(self, frame: Any, raw_bytes: bytes) -> List[Alert]:
        """
        Process a GOOSEFrame (duck-typed as Any here to avoid circular imports 
        if GOOSEFrame is defined elsewhere).
        """
        self.stats.frames_processed += 1
        alerts = []
        
        # Extract fields assuming frame object has these attributes
        src_mac = getattr(frame, "eth_src", "00:00:00:00:00:00")
        st_num = getattr(frame, "stNum", 0)
        sq_num = getattr(frame, "sqNum", 0)
        timestamp = getattr(frame, "timestamp", time.time())
        conf_rev = getattr(frame, "confRev", 0)
        
        frame_snapshot = {
            "stNum": st_num,
            "sqNum": sq_num,
            "timestamp": timestamp,
            "confRev": conf_rev
        }
        
        current_time = time.time()
        
        # Rule 4: UNKNOWN_SOURCE
        if self.known_publishers and src_mac not in self.known_publishers:
            alerts.append(self._create_alert(
                "UNKNOWN_SOURCE", AlertSeverity.HIGH, src_mac,
                f"Unknown source MAC detected: {src_mac}", frame_snapshot
            ))

        if src_mac not in self.publisher_states:
            self.publisher_states[src_mac] = PublisherState(
                last_stNum=st_num,
                last_sqNum=sq_num,
                last_timestamp=timestamp,
                last_confRev=conf_rev,
                burst_start_time=current_time,
                state_change_start_time=current_time
            )
            return alerts
            
        state = self.publisher_states[src_mac]
        state.frame_count += 1
        
        # Rule 1: STNUM_REGRESSION
        if st_num < state.last_stNum:
            alerts.append(self._create_alert(
                "STNUM_REGRESSION", AlertSeverity.HIGH, src_mac,
                f"stNum regressed from {state.last_stNum} to {st_num}", frame_snapshot
            ))
            
        # Rule 2: SQNUM_ANOMALY
        if st_num == state.last_stNum:
            if sq_num < state.last_sqNum and sq_num != 0:
                alerts.append(self._create_alert(
                    "SQNUM_ANOMALY", AlertSeverity.MEDIUM, src_mac,
                    f"sqNum regressed without stNum change: {state.last_sqNum} -> {sq_num}", frame_snapshot
                ))
            elif sq_num > state.last_sqNum + self.config.max_sqnum_gap:
                alerts.append(self._create_alert(
                    "SQNUM_ANOMALY", AlertSeverity.MEDIUM, src_mac,
                    f"sqNum gap > {self.config.max_sqnum_gap}: {state.last_sqNum} -> {sq_num}", frame_snapshot
                ))
                
        # Rule 3: BURST_FLOOD
        if current_time - state.burst_start_time > 1.0:
            state.burst_start_time = current_time
            state.burst_count = 1
        else:
            state.burst_count += 1
            if state.burst_count > self.config.burst_threshold_pps:
                alerts.append(self._create_alert(
                    "BURST_FLOOD", AlertSeverity.CRITICAL, src_mac,
                    f"Burst flood detected: > {self.config.burst_threshold_pps} pps", frame_snapshot
                ))

        # Rule 5: TIMESTAMP_ANOMALY
        if timestamp > current_time + self.config.max_timestamp_drift_sec:
            alerts.append(self._create_alert(
                "TIMESTAMP_ANOMALY", AlertSeverity.MEDIUM, src_mac,
                f"Future timestamp detected: {timestamp}", frame_snapshot
            ))
        elif timestamp < state.last_timestamp - self.config.max_timestamp_drift_sec:
            alerts.append(self._create_alert(
                "TIMESTAMP_ANOMALY", AlertSeverity.MEDIUM, src_mac,
                f"Timestamp jumped backwards by > {self.config.max_timestamp_drift_sec}s", frame_snapshot
            ))

        # Rule 6: CONFREV_MISMATCH
        if conf_rev != state.last_confRev and state.last_confRev != 0:
            alerts.append(self._create_alert(
                "CONFREV_MISMATCH", AlertSeverity.LOW, src_mac,
                f"confRev changed unexpectedly: {state.last_confRev} -> {conf_rev}", frame_snapshot
            ))
            
        # Rule 7: RAPID_STATE_CHANGE
        if st_num > state.last_stNum:
            if current_time - state.state_change_start_time > 1.0:
                state.state_change_start_time = current_time
                state.state_change_count = 1
            else:
                state.state_change_count += 1
                if state.state_change_count > self.config.max_state_changes_per_sec:
                    alerts.append(self._create_alert(
                        "RAPID_STATE_CHANGE", AlertSeverity.HIGH, src_mac,
                        f"Rapid state change: > {self.config.max_state_changes_per_sec} stNum changes/sec", frame_snapshot
                    ))

        # Update state
        state.last_stNum = st_num
        state.last_sqNum = sq_num
        state.last_timestamp = timestamp
        state.last_confRev = conf_rev
        
        return alerts
