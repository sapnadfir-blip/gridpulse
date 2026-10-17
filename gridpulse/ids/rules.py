from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass
from enum import Enum

class AlertSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Alert:
    rule_id: str
    severity: AlertSeverity
    source_mac: str
    description: str
    timestamp: float
    frame_snapshot: Optional[Dict[str, Any]] = None
    mitre_technique: Optional[str] = None

@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: AlertSeverity
    enabled: bool
    check_function: Callable

class RuleRegistry:
    def __init__(self) -> None:
        self.rules: Dict[str, DetectionRule] = {}
        
    def register(self, rule: DetectionRule) -> None:
        self.rules[rule.rule_id] = rule
        
    def unregister(self, rule_id: str) -> None:
        if rule_id in self.rules:
            del self.rules[rule_id]
            
    def enable_rule(self, rule_id: str) -> None:
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            
    def disable_rule(self, rule_id: str) -> None:
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            
    def get_active_rules(self) -> list[DetectionRule]:
        return [rule for rule in self.rules.values() if rule.enabled]
        
    @classmethod
    def create_default_registry(cls) -> "RuleRegistry":
        registry = cls()
        
        # Default rules will be injected or called from the engine directly
        # based on the requested logic. The check functions are typically
        # bound to the engine's state. 
        
        return registry
