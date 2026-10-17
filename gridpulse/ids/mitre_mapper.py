from dataclasses import dataclass
from typing import Optional

@dataclass
class MITREMapping:
    """Represents a MITRE ATT&CK for ICS technique."""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    reference_url: str

# Pre-defined mappings for ICS-relevant techniques
PREDEFINED_MAPPINGS = {
    "T0855": MITREMapping(
        technique_id="T0855",
        technique_name="Unauthorized Command Message",
        tactic="Execution",
        description="Adversaries may send unauthorized command messages to control systems.",
        reference_url="https://attack.mitre.org/techniques/T0855/"
    ),
    "T0843": MITREMapping(
        technique_id="T0843",
        technique_name="Program Download",
        tactic="Execution",
        description="Adversaries may download programs to control systems devices.",
        reference_url="https://attack.mitre.org/techniques/T0843/"
    ),
    "T0836": MITREMapping(
        technique_id="T0836",
        technique_name="Modify Parameter",
        tactic="Impair Process Control",
        description="Adversaries may modify parameters to manipulate control system behavior.",
        reference_url="https://attack.mitre.org/techniques/T0836/"
    ),
    "T0831": MITREMapping(
        technique_id="T0831",
        technique_name="Manipulation of Control",
        tactic="Impair Process Control",
        description="Adversaries may manipulate control processes to cause physical damage or disruption.",
        reference_url="https://attack.mitre.org/techniques/T0831/"
    ),
    "T0882": MITREMapping(
        technique_id="T0882",
        technique_name="Theft of Operational Information",
        tactic="Collection",
        description="Adversaries may steal operational information.",
        reference_url="https://attack.mitre.org/techniques/T0882/"
    ),
    "T0803": MITREMapping(
        technique_id="T0803",
        technique_name="Block Command Message",
        tactic="Impair Process Control",
        description="Adversaries may block command messages from reaching their destination.",
        reference_url="https://attack.mitre.org/techniques/T0803/"
    ),
    "T0814": MITREMapping(
        technique_id="T0814",
        technique_name="Denial of Service",
        tactic="Inhibit Response Function",
        description="Adversaries may cause a denial of service (DoS) on control systems.",
        reference_url="https://attack.mitre.org/techniques/T0814/"
    ),
    "T0840": MITREMapping(
        technique_id="T0840",
        technique_name="Network Connection Enumeration",
        tactic="Discovery",
        description="Adversaries may enumerate network connections to find control systems.",
        reference_url="https://attack.mitre.org/techniques/T0840/"
    )
}

# Mapping from rule ID to MITRE Technique ID
RULE_TO_MITRE_MAP = {
    "STNUM_REGRESSION": "T0855",
    "SQNUM_ANOMALY": "T0855",
    "BURST_FLOOD": "T0814",
    "UNKNOWN_SOURCE": "T0840",
    "TIMESTAMP_ANOMALY": "T0855",
    "CONFREV_MISMATCH": "T0836",
    "RAPID_STATE_CHANGE": "T0831",
}

class MITREMapper:
    """Maps alerts and rules to MITRE ATT&CK for ICS techniques."""
    
    def __init__(self) -> None:
        self.mappings = PREDEFINED_MAPPINGS
        self.rule_map = RULE_TO_MITRE_MAP
        
    def get_technique(self, technique_id: str) -> Optional[MITREMapping]:
        """Retrieves a MITRE technique by its ID."""
        return self.mappings.get(technique_id)
        
    def get_all_mappings(self) -> list[MITREMapping]:
        """Returns all registered MITRE techniques."""
        return list(self.mappings.values())
        
    def map_alert(self, alert_rule_id: str) -> Optional[MITREMapping]:
        """Maps an alert rule ID to a MITRE technique."""
        technique_id = self.rule_map.get(alert_rule_id)
        if technique_id:
            return self.get_technique(technique_id)
        return None
