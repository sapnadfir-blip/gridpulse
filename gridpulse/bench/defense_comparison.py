"""
defense_comparison.py - Defense Approach Comparison for CIL-DoS Attacks

This module compares different defense approaches against CIL-DoS (Computationally Intensive
Logic Denial of Service) attacks targeting GOOSE implementations in digital substations.

Designed for the GridPulse Black Hat Briefings presentation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import math
import csv
import sys


@dataclass
class DefenseProfile:
    """Represents a specific defense mechanism and its operational characteristics."""
    name: str
    layer: str  # "L2", "L3", "L7", "NIC"
    processing_latency_us: float
    max_filter_rate_pps: int
    can_inspect_goose: bool
    bypass_methods: List[str]
    false_positive_risk: str  # "none", "low", "medium", "high"
    requires_linux: bool
    requires_hardware: bool
    effectiveness_vs_cil_dos: float  # 0.0 to 1.0
    operational_complexity: str  # "low", "medium", "high"
    description: str = ""


# Pre-defined defense profiles for the Black Hat presentation
DEFENSES = [
    DefenseProfile(
        name="No Defense (Baseline)",
        layer="N/A",
        processing_latency_us=0.0,
        max_filter_rate_pps=0,
        can_inspect_goose=False,
        bypass_methods=["N/A"],
        false_positive_risk="none",
        requires_linux=False,
        requires_hardware=False,
        effectiveness_vs_cil_dos=0.0,
        operational_complexity="low",
        description="All traffic reaches verification queue. Full attack rate hits service rate."
    ),
    DefenseProfile(
        name="Switch ACL (MAC-based)",
        layer="L2",
        processing_latency_us=0.0,  # hardware TCAM
        max_filter_rate_pps=100000000,  # wire speed
        can_inspect_goose=False,
        bypass_methods=["MAC spoofing"],
        false_positive_risk="low",
        requires_linux=False,
        requires_hardware=True,
        effectiveness_vs_cil_dos=0.2,
        operational_complexity="medium",
        description="Layer 2 MAC address filtering on the switch."
    ),
    DefenseProfile(
        name="VLAN Isolation",
        layer="L2",
        processing_latency_us=0.0,
        max_filter_rate_pps=100000000,  # wire speed
        can_inspect_goose=False,
        bypass_methods=["Compromised IED on same VLAN"],
        false_positive_risk="none",
        requires_linux=False,
        requires_hardware=True,
        effectiveness_vs_cil_dos=0.4,
        operational_complexity="medium",
        description="GOOSE publishers/subscribers on separate VLANs."
    ),
    DefenseProfile(
        name="Firewall (L3-4)",
        layer="L3-4",
        processing_latency_us=150.0,
        max_filter_rate_pps=0,  # N/A for GOOSE
        can_inspect_goose=False,
        bypass_methods=["Bypasses completely (EtherType 0x88B8)"],
        false_positive_risk="none",
        requires_linux=False,
        requires_hardware=True,
        effectiveness_vs_cil_dos=0.0,
        operational_complexity="high",
        description="Stateful firewall inspection. Cannot inspect Layer 2 GOOSE traffic."
    ),
    DefenseProfile(
        name="IDS/IPS (Snort/Suricata)",
        layer="L7",
        processing_latency_us=300.0,
        max_filter_rate_pps=300000,
        can_inspect_goose=True,
        bypass_methods=["Overwhelming IDS CPU", "Fragmentation/Evasion"],
        false_positive_risk="medium",
        requires_linux=True,
        requires_hardware=False,
        effectiveness_vs_cil_dos=0.5,
        operational_complexity="high",
        description="Deep packet inspection with GOOSE rules. Inline IPS adds significant latency."
    ),
    DefenseProfile(
        name="GridPulse GOOSE IDS",
        layer="L7",
        processing_latency_us=10.0,
        max_filter_rate_pps=50000,
        can_inspect_goose=True,
        bypass_methods=["High rate DDoS (Detection only)"],
        false_positive_risk="low",
        requires_linux=True,
        requires_hardware=False,
        effectiveness_vs_cil_dos=0.6,
        operational_complexity="medium",
        description="Protocol-aware stateful anomaly detection. Detection only (unless paired with XDP)."
    ),
    DefenseProfile(
        name="Software Rate Limiter",
        layer="L7",
        processing_latency_us=5.0,
        max_filter_rate_pps=200000,
        can_inspect_goose=True,
        bypass_methods=["Distributed spoofing", "Kernel stack exhaustion"],
        false_positive_risk="medium",
        requires_linux=True,
        requires_hardware=False,
        effectiveness_vs_cil_dos=0.7,
        operational_complexity="medium",
        description="Per-source rate limiting in userspace. Can still be overwhelmed."
    ),
    DefenseProfile(
        name="eBPF/XDP (GridPulse)",
        layer="NIC",
        processing_latency_us=0.3,
        max_filter_rate_pps=15000000,  # 15M pps
        can_inspect_goose=True,
        bypass_methods=["Zero-day token bucket evasion", "Line rate exhaustion (unlikely)"],
        false_positive_risk="low",
        requires_linux=True,
        requires_hardware=False,
        effectiveness_vs_cil_dos=0.99,
        operational_complexity="high",
        description="NIC driver-level filtering. MAC allowlist + token bucket + sqNum validation."
    )
]


class ComparisonTable:
    """Handles formatting and output of defense comparison results."""
    
    def __init__(self, attack_rate: float, service_rate: float, deadline_us: float):
        self.attack_rate = attack_rate
        self.service_rate = service_rate
        self.deadline_us = deadline_us
        self.results = []
        
    def add_result(self, result: Dict[str, Any]):
        self.results.append(result)
        
    def print_table(self):
        """Prints a nicely formatted ASCII table of the results."""
        print(f"\n--- GridPulse Defense Comparison ---")
        print(f"Attack Rate: {self.attack_rate:,.0f} pps | Service Rate: {self.service_rate:,.0f} pps | Deadline: {self.deadline_us} µs")
        print("-" * 125)
        
        headers = [
            "Defense Mechanism", "Layer", "Lat. (µs)", "Max Rate (pps)", 
            "Eff. Attack", "Queue Util", "P(Violate)", "Assessment"
        ]
        
        row_format = "{:<26} | {:<5} | {:>9} | {:>14} | {:>11} | {:>10} | {:>10} | {:<12}"
        print(row_format.format(*headers))
        print("-" * 125)
        
        for r in self.results:
            eff_att_str = f"{r['effective_attack_rate']:,.0f}"
            util_str = f"{r['queue_utilization'] * 100:.1f}%"
            
            p_viol_str = "100.0%" if r['prob_violation'] >= 0.999 else f"{r['prob_violation'] * 100:.2f}%"
            
            print(row_format.format(
                r['defense'].name,
                r['defense'].layer,
                f"{r['defense'].processing_latency_us:.1f}",
                f"{r['defense'].max_filter_rate_pps:,.0f}" if r['defense'].max_filter_rate_pps > 0 else "N/A",
                eff_att_str,
                util_str,
                p_viol_str,
                r['assessment']
            ))
            
        print("-" * 125)
        
    def export_csv(self, filename: str):
        """Exports results to a CSV file."""
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = [
                    'Defense Name', 'Layer', 'Processing Latency (us)', 'Max Filter Rate (pps)',
                    'Effectiveness vs CIL-DoS', 'Effective Attack Rate (pps)', 'Queue Utilization',
                    'Prob Deadline Violation', 'Assessment', 'Operational Complexity'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for r in self.results:
                    writer.writerow({
                        'Defense Name': r['defense'].name,
                        'Layer': r['defense'].layer,
                        'Processing Latency (us)': r['defense'].processing_latency_us,
                        'Max Filter Rate (pps)': r['defense'].max_filter_rate_pps,
                        'Effectiveness vs CIL-DoS': r['defense'].effectiveness_vs_cil_dos,
                        'Effective Attack Rate (pps)': r['effective_attack_rate'],
                        'Queue Utilization': r['queue_utilization'],
                        'Prob Deadline Violation': r['prob_violation'],
                        'Assessment': r['assessment'],
                        'Operational Complexity': r['defense'].operational_complexity
                    })
            print(f"Results exported to {filename}")
        except Exception as e:
            print(f"Error exporting to CSV: {e}", file=sys.stderr)


class DefenseComparison:
    """Core logic for evaluating different defense approaches."""
    
    def __init__(self, defenses: List[DefenseProfile]):
        self.defenses = defenses
        
    def compare_all(self, attack_rate: float, service_rate: float, deadline_us: float) -> ComparisonTable:
        """
        Runs the comparison for all defenses under a specific scenario.
        
        Uses an M/M/1 queue model approximation to calculate probabilities.
        """
        table = ComparisonTable(attack_rate, service_rate, deadline_us)
        
        for d in self.defenses:
            # 1. Calculate effective attack rate reaching verification queue
            # If attack rate exceeds max_filter_rate, the filter drops packets or crashes
            if d.max_filter_rate_pps > 0 and attack_rate > d.max_filter_rate_pps:
                # Filter is overwhelmed. In reality, it might fail open or closed.
                # Assuming it fails open or degrades, allowing some traffic through.
                # For simplicity, let's say it just limits to its max capacity but with poor effectiveness.
                effective_attack = attack_rate * (1.0 - (d.effectiveness_vs_cil_dos * 0.2))
            else:
                effective_attack = attack_rate * (1.0 - d.effectiveness_vs_cil_dos)
                
            # If the defense doesn't filter GOOSE, effective attack is the full attack
            if not d.can_inspect_goose and d.layer not in ["L2", "NIC"]:
                effective_attack = attack_rate
                
            # 2. Calculate resulting queue utilization (rho = lambda / mu)
            rho = effective_attack / service_rate if service_rate > 0 else float('inf')
            
            # 3. Calculate P(deadline violation)
            # Time spent in system for M/M/1: W = 1 / (mu - lambda)
            # P(W > t) = exp(-(mu - lambda) * t)
            
            if rho >= 1.0:
                prob_violation = 1.0
            else:
                mu_sec = service_rate
                lambda_sec = effective_attack
                deadline_sec = deadline_us / 1000000.0
                
                # Adjust deadline by subtracting defense processing latency
                adjusted_deadline_sec = deadline_sec - (d.processing_latency_us / 1000000.0)
                
                if adjusted_deadline_sec <= 0:
                    prob_violation = 1.0
                else:
                    prob_violation = math.exp(-(mu_sec - lambda_sec) * adjusted_deadline_sec)
                    
            # Bound probability between 0 and 1
            prob_violation = max(0.0, min(1.0, prob_violation))
            
            # 4. Assessment
            if prob_violation < 0.05:
                assessment = "EFFECTIVE"
            elif prob_violation < 0.5:
                assessment = "PARTIAL"
            else:
                assessment = "INEFFECTIVE"
                
            # Overrides based on defense specific limits
            if d.name == "Firewall (L3-4)":
                assessment = "INEFFECTIVE"
                
            table.add_result({
                'defense': d,
                'effective_attack_rate': effective_attack,
                'queue_utilization': min(1.0, rho),
                'prob_violation': prob_violation,
                'assessment': assessment
            })
            
        return table


def run_comparison(service_rates: Dict[str, float], attack_rates: List[float], deadline_us: float = 3000.0) -> Dict[str, Any]:
    """Runs a full comparison matrix."""
    comp = DefenseComparison(DEFENSES)
    results = {}
    
    for algo, service_rate in service_rates.items():
        algo_results = []
        for rate in attack_rates:
            table = comp.compare_all(rate, service_rate, deadline_us)
            algo_results.append({
                'attack_rate': rate,
                'table': table
            })
        results[algo] = algo_results
        
    return results


def generate_defense_recommendation(scenario: str):
    """Generates a practical recommendation based on deployment constraints."""
    print(f"\n[+] Defense Recommendation: {scenario.upper()}")
    print("=" * 60)
    
    if scenario == "legacy_substation":
        print("- Context: Older IEDs, strict vendor support limits, no Linux OS access.")
        print("- Primary Threat: Broadcast storms, basic replay attacks.")
        print("- Recommendation:")
        print("  1. VLAN Isolation (Mandatory): Separate GOOSE streams.")
        print("  2. Switch-level MAC ACLs: Drop unapproved MACs at wire speed.")
        print("  3. Out-of-band GridPulse IDS: Tap the SPAN port for visibility (no blocking).")
        print("- Warning: Remains vulnerable to CIL-DoS from a compromised IED on the same VLAN.")
        
    elif scenario == "modern_digital_substation":
        print("- Context: Standardized IEC 61850 process bus, high GOOSE volume.")
        print("- Primary Threat: State-sponsored CIL-DoS, protocol fuzzing.")
        print("- Recommendation:")
        print("  1. Switch-level MAC filtering + VLAN segmentation.")
        print("  2. GridPulse GOOSE IDS (Monitoring mode) for baseline establishment.")
        print("  3. eBPF/XDP Rate Limiting on critical publisher/subscriber gateways.")
        print("- Rationale: eBPF provides the only viable defense against line-rate CIL-DoS")
        print("  without adding unacceptable latency to the 3ms IEC 61850 budget.")
        
    elif scenario == "software_defined_grid":
        print("- Context: Virtualized IEDs (vIEDs) running on COTS Linux servers.")
        print("- Primary Threat: Cross-VM DoS, CPU exhaustion.")
        print("- Recommendation:")
        print("  1. eBPF/XDP Filtering (Mandatory): Drop invalid GOOSE frames in NIC driver")
        print("     before they reach the hypervisor/vSwitch.")
        print("  2. Software Rate Limiting: Secondary defense in userspace.")
        
    else:
        print("Unknown scenario.")
    
    print("=" * 60)


def print_lessons_for_defenders():
    """Prints the operational takeaways for the Black Hat audience."""
    print("\n" + "#" * 60)
    print("           BLACK HAT 2026: LESSONS FOR DEFENDERS")
    print("#" * 60)
    
    lessons = [
        "1. LAYER 3/4 FIREWALLS ARE BLIND: Standard IT firewalls do not inspect",
        "   Layer 2 EtherType 0x88B8 (GOOSE). They provide 0% defense against CIL-DoS.",
        "",
        "2. LATENCY IS THE ENEMY: Inline IPS (Snort/Suricata) adds 100-500µs of latency.",
        "   In a 3ms deadline environment, this consumes up to 16% of the budget just",
        "   for inspection, risking operational stability during normal conditions.",
        "",
        "3. CRYPTO IS THE BOTTLENECK: Verification (RSA/ECDSA) is computationally",
        "   expensive. CIL-DoS exploits this asymmetry. Defenses MUST drop spoofed",
        "   traffic BEFORE the cryptographic verification step.",
        "",
        "4. eBPF/XDP IS THE FUTURE OF OT SECURITY: By pushing packet filtering into",
        "   the NIC driver via XDP, we can perform stateful GOOSE inspection (MAC,",
        "   AppID, sqNum/stNum) at 10M+ pps with <1µs latency.",
        "",
        "5. DEFENSE IN DEPTH: Combine Switch MAC ACLs (dumb, fast) with XDP (smart,",
        "   fast) and hardware acceleration (FPGA/ASIC) for RSA verification."
    ]
    
    for line in lessons:
        print(line)
        
    print("#" * 60 + "\n")


if __name__ == "__main__":
    # Example usage for standalone testing
    print("Running GridPulse Defense Comparison Module")
    
    # 5,000 pps attack vs slow RSA verification (2,000 ops/sec)
    comp = DefenseComparison(DEFENSES)
    table = comp.compare_all(attack_rate=5000, service_rate=2000, deadline_us=3000)
    table.print_table()
    
    generate_defense_recommendation("modern_digital_substation")
    print_lessons_for_defenders()
