"""
Constrained Hardware Emulation for IED-class Processors
========================================================

Addresses the reviewer concern: "Apple M2 isn't an IED."

Emulates cryptographic verification performance on protection relay
hardware by applying measured scaling factors from published literature.

IED Processor Classes (from published benchmarks):
    - ARM Cortex-M4 @ 168 MHz (e.g., STM32F4)    → ~100-500x slower than M2
    - ARM Cortex-R5 @ 600 MHz (e.g., TI AM65x)    → ~30-80x slower than M2
    - ARM Cortex-A9 @ 800 MHz (e.g., Xilinx Zynq)  → ~15-30x slower than M2
    - x86 Atom E3800 @ 1.9 GHz (embedded gateway)  → ~5-10x slower than M2

The scaling factors are derived from:
    1. Clock frequency ratio
    2. SIMD/crypto extension availability
    3. Cache hierarchy differences
    4. Published crypto benchmarks on constrained platforms

References:
    - ARM Cortex-M4 HMAC-SHA256: ~50-100 µs (mbed TLS benchmarks)
    - ARM Cortex-R5 RSA-2048 verify: ~5-15 ms (TI SDK benchmarks)
    - IEC 61850 relay processors: typically ARM Cortex-R or A-class
"""

from __future__ import annotations

import csv
import math
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from gridpulse.bench.crypto_bench import BenchmarkResult
from gridpulse.bench.queue_model import MM1Queue, MD1Queue
from gridpulse.bench.validation import MultiTrialResult


# ============================================================================
# Hardware Profiles
# ============================================================================

@dataclass
class HardwareProfile:
    """
    Hardware profile for a specific processor class.

    The scaling_factors dict maps algorithm name to the multiplicative
    factor applied to M2 measurements. These factors account for:
    - Clock frequency ratio
    - Microarchitecture efficiency (IPC, pipeline depth)
    - Crypto acceleration (AES-NI, SHA extensions, NEON)
    - Memory subsystem (cache size, latency)
    """
    name: str
    description: str
    clock_mhz: int
    architecture: str
    has_crypto_accel: bool
    scaling_factors: dict[str, float]
    reference: str

    def scale_result(self, m2_result: MultiTrialResult) -> 'ScaledBenchmarkResult':
        """Scale M2 benchmark results to this hardware profile."""
        factor = self.scaling_factors.get(
            m2_result.algorithm,
            self.scaling_factors.get("default", 10.0)
        )

        scaled_mean = m2_result.grand_mean_us * factor
        scaled_ci_low = m2_result.ci_95_lower_us * factor
        scaled_ci_high = m2_result.ci_95_upper_us * factor
        scaled_throughput = m2_result.mean_throughput_ops_sec / factor
        scaled_tp_ci_low = m2_result.throughput_ci_95_lower / factor
        scaled_tp_ci_high = m2_result.throughput_ci_95_upper / factor

        return ScaledBenchmarkResult(
            algorithm=m2_result.algorithm,
            hardware=self.name,
            scaling_factor=factor,
            m2_mean_us=m2_result.grand_mean_us,
            scaled_mean_us=scaled_mean,
            scaled_ci_95=[scaled_ci_low, scaled_ci_high],
            m2_throughput=m2_result.mean_throughput_ops_sec,
            scaled_throughput=scaled_throughput,
            scaled_throughput_ci_95=[scaled_tp_ci_low, scaled_tp_ci_high],
        )


@dataclass
class ScaledBenchmarkResult:
    """Benchmark result scaled to a constrained hardware platform."""
    algorithm: str
    hardware: str
    scaling_factor: float
    m2_mean_us: float
    scaled_mean_us: float
    scaled_ci_95: list[float]
    m2_throughput: float
    scaled_throughput: float
    scaled_throughput_ci_95: list[float]

    def __str__(self) -> str:
        return (
            f"  {self.algorithm:<15} on {self.hardware:<20}: "
            f"{self.scaled_mean_us:>8.1f} µs "
            f"[{self.scaled_ci_95[0]:.1f}, {self.scaled_ci_95[1]:.1f}] "
            f"({self.scaling_factor:.0f}× M2), "
            f"µ={self.scaled_throughput:,.0f} ops/s"
        )


# ============================================================================
# Pre-defined Hardware Profiles
# ============================================================================

# Scaling factors derived from published benchmarks and frequency ratios.
# Conservative estimates (worst-case for defender = best case for attacker).

PROFILES: dict[str, HardwareProfile] = {
    "cortex_m4": HardwareProfile(
        name="ARM Cortex-M4",
        description="Low-end IED microcontroller (e.g., STM32F4 series)",
        clock_mhz=168,
        architecture="ARMv7-M",
        has_crypto_accel=False,
        scaling_factors={
            "HMAC-SHA256": 150.0,    # ~210 µs on M4 (mbed TLS)
            "RSA-2048": 300.0,       # ~10 ms on M4 (software only)
            "ECDSA-P256": 200.0,     # ~12 ms on M4 (software only)
            "default": 200.0,
        },
        reference="mbed TLS benchmark suite, STM32F407 @ 168 MHz",
    ),
    "cortex_r5": HardwareProfile(
        name="ARM Cortex-R5",
        description="Mid-range protection relay processor (e.g., TI AM65x IED)",
        clock_mhz=600,
        architecture="ARMv7-R",
        has_crypto_accel=False,
        scaling_factors={
            "HMAC-SHA256": 40.0,     # ~56 µs
            "RSA-2048": 80.0,        # ~2.7 ms
            "ECDSA-P256": 60.0,      # ~3.5 ms
            "default": 60.0,
        },
        reference="TI AM654x SDK crypto benchmarks, Cortex-R5F @ 600 MHz",
    ),
    "cortex_a9": HardwareProfile(
        name="ARM Cortex-A9",
        description="High-end IED/gateway processor (e.g., Xilinx Zynq-7000)",
        clock_mhz=800,
        architecture="ARMv7-A",
        has_crypto_accel=True,  # NEON
        scaling_factors={
            "HMAC-SHA256": 15.0,     # ~21 µs
            "RSA-2048": 25.0,        # ~840 µs
            "ECDSA-P256": 20.0,      # ~1.2 ms
            "default": 20.0,
        },
        reference="OpenSSL speed benchmarks, Zynq-7020 Cortex-A9 @ 800 MHz",
    ),
    "atom_e3800": HardwareProfile(
        name="Intel Atom E3800",
        description="Substation gateway/RTU processor",
        clock_mhz=1910,
        architecture="x86-64",
        has_crypto_accel=True,  # AES-NI
        scaling_factors={
            "HMAC-SHA256": 5.0,      # ~7 µs
            "RSA-2048": 8.0,         # ~268 µs
            "ECDSA-P256": 7.0,       # ~412 µs
            "default": 7.0,
        },
        reference="OpenSSL speed benchmarks, Atom E3845 @ 1.91 GHz",
    ),
}


# ============================================================================
# Constrained Hardware Analysis
# ============================================================================

def analyze_constrained_hardware(
    m2_results: dict[str, MultiTrialResult],
    profiles: dict[str, HardwareProfile] | None = None,
    deadline_us: float = 3000.0,
    verbose: bool = True,
) -> dict[str, list[dict]]:
    """
    Analyze CIL-DoS impact across constrained hardware platforms.

    For each hardware profile and algorithm:
    1. Scale M2 measurements to target hardware
    2. Compute service rate µ
    3. Find saturation point (ρ=1)
    4. Find attack rate for 1%, 10%, 50% deadline violation

    Returns dict mapping hardware_name -> list of analysis dicts.
    """
    if profiles is None:
        profiles = PROFILES

    all_results = {}

    if verbose:
        print(f"\n{'Hardware':<20} │ {'Algorithm':<15} │ {'Verify (µs)':<12} │ "
              f"{'µ (ops/s)':<12} │ {'λ_sat':<10} │ "
              f"{'λ@1% viol':<10} │ {'λ@50% viol':<11}")
        print("─" * 105)

    for hw_name, profile in profiles.items():
        hw_results = []

        for algo_name, m2_multi in m2_results.items():
            scaled = profile.scale_result(m2_multi)
            mu = scaled.scaled_throughput
            deadline_sec = deadline_us / 1e6

            # Find critical attack rates via binary search
            lambda_1pct = _find_critical_rate(mu, deadline_sec, target_prob=0.01)
            lambda_10pct = _find_critical_rate(mu, deadline_sec, target_prob=0.10)
            lambda_50pct = _find_critical_rate(mu, deadline_sec, target_prob=0.50)

            result = {
                "hardware": profile.name,
                "algorithm": algo_name,
                "scaled_verify_us": scaled.scaled_mean_us,
                "scaled_verify_ci_95": scaled.scaled_ci_95,
                "service_rate": mu,
                "saturation_rate": mu,
                "lambda_1pct_violation": lambda_1pct,
                "lambda_10pct_violation": lambda_10pct,
                "lambda_50pct_violation": lambda_50pct,
                "scaling_factor": scaled.scaling_factor,
            }
            hw_results.append(result)

            if verbose:
                print(f"{profile.name:<20} │ {algo_name:<15} │ "
                      f"{scaled.scaled_mean_us:>10.1f} │ "
                      f"{mu:>10,.0f} │ "
                      f"{mu:>8,.0f} │ "
                      f"{lambda_1pct:>8,.0f} │ "
                      f"{lambda_50pct:>9,.0f}")

        all_results[hw_name] = hw_results

        if verbose:
            print("─" * 105)

    return all_results


def _find_critical_rate(
    mu: float,
    deadline_sec: float,
    target_prob: float,
    tolerance: float = 0.001,
) -> float:
    """Binary search for the arrival rate that produces target violation probability."""
    low = 0.0
    high = mu * 0.999  # Must be < mu for stable queue

    for _ in range(100):  # Max iterations
        mid = (low + high) / 2
        try:
            q = MM1Queue(mid, mu)
            prob = q.prob_deadline_violation(deadline_sec)
        except (ValueError, ZeroDivisionError):
            high = mid
            continue

        if abs(prob - target_prob) < tolerance:
            return mid
        elif prob < target_prob:
            low = mid
        else:
            high = mid

    return (low + high) / 2


def export_constrained_results(
    results: dict[str, list[dict]],
    path: str | Path,
) -> None:
    """Export constrained hardware analysis to CSV."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Hardware", "Algorithm", "Verify_us", "CI95_Lower_us", "CI95_Upper_us",
            "Service_Rate", "Saturation_Rate", "Lambda_1pct", "Lambda_10pct",
            "Lambda_50pct", "Scaling_Factor",
        ])
        for hw_name, hw_results in results.items():
            for r in hw_results:
                writer.writerow([
                    r["hardware"], r["algorithm"],
                    f"{r['scaled_verify_us']:.2f}",
                    f"{r['scaled_verify_ci_95'][0]:.2f}",
                    f"{r['scaled_verify_ci_95'][1]:.2f}",
                    f"{r['service_rate']:.2f}",
                    f"{r['saturation_rate']:.2f}",
                    f"{r['lambda_1pct_violation']:.0f}",
                    f"{r['lambda_10pct_violation']:.0f}",
                    f"{r['lambda_50pct_violation']:.0f}",
                    f"{r['scaling_factor']:.1f}",
                ])


# ============================================================================
# Queue Model Justification Analysis
# ============================================================================

def compare_queue_models(
    service_rate: float,
    attack_rates: list[float],
    deadline_us: float = 3000.0,
    verbose: bool = True,
) -> list[dict]:
    """
    Compare M/M/1 vs M/D/1 predictions to justify model selection.

    M/M/1: Exponential service times (upper bound on wait times)
    M/D/1: Deterministic service times (lower bound on wait times)

    The true system lies between these bounds. Reporting both provides
    a confidence band for the predictions.
    """
    deadline_sec = deadline_us / 1e6
    results = []

    if verbose:
        print(f"\n{'λ (pps)':>10} │ {'ρ':>6} │ "
              f"{'M/M/1 Wq':>10} │ {'M/D/1 Wq':>10} │ {'Ratio':>6} │ "
              f"{'M/M/1 P(v)':>10} │ {'M/D/1 P(v)':>10}")
        print("─" * 80)

    for rate in attack_rates:
        rho = rate / service_rate
        if rho >= 1.0:
            if verbose:
                print(f"{rate:>10,.0f} │ {rho:>6.3f} │ {'∞':>10} │ {'∞':>10} │ "
                      f"{'—':>6} │ {'1.0000':>10} │ {'1.0000':>10}")
            results.append({
                "rate": rate, "rho": rho,
                "mm1_wq": float('inf'), "md1_wq": float('inf'),
                "ratio": float('inf'),
                "mm1_pv": 1.0, "md1_pv": 1.0,
            })
            continue

        try:
            mm1 = MM1Queue(rate, service_rate)
            md1 = MD1Queue(rate, service_rate)

            mm1_wq = mm1.mean_wait_time * 1e6
            md1_wq = md1.mean_wait_time * 1e6
            ratio = mm1_wq / md1_wq if md1_wq > 0 else float('inf')

            mm1_pv = mm1.prob_deadline_violation(deadline_sec)
            md1_pv = md1.prob_deadline_violation(deadline_sec)

            row = {
                "rate": rate, "rho": rho,
                "mm1_wq": mm1_wq, "md1_wq": md1_wq,
                "ratio": ratio,
                "mm1_pv": mm1_pv, "md1_pv": md1_pv,
            }
            results.append(row)

            if verbose:
                print(f"{rate:>10,.0f} │ {rho:>6.3f} │ "
                      f"{mm1_wq:>8.1f}µs │ {md1_wq:>8.1f}µs │ "
                      f"{ratio:>5.2f}× │ "
                      f"{mm1_pv:>10.4f} │ {md1_pv:>10.4f}")

        except (ValueError, ZeroDivisionError):
            continue

    if verbose:
        print(f"\n  Note: M/M/1 Wq ≈ 2× M/D/1 Wq (Pollaczek-Khinchine bound)")
        print(f"  True system behavior lies between M/D/1 (lower bound) and M/M/1 (upper bound)")
        print(f"  M/M/1 selected for conservative analysis (worst-case for defender)")

    return results


# ============================================================================
# Attacker Capability Analysis
# ============================================================================

@dataclass
class AttackerProfile:
    """Models an attacker's packet generation capability."""
    name: str
    description: str
    max_pps: int               # Maximum packets per second
    frame_size_bytes: int      # GOOSE frame size
    bandwidth_mbps: float      # Required bandwidth
    equipment: str
    feasibility: str           # "trivial", "moderate", "difficult"

    @classmethod
    def from_rate(
        cls,
        name: str,
        max_pps: int,
        frame_size: int = 200,
        description: str = "",
        equipment: str = "",
    ) -> 'AttackerProfile':
        bw = (max_pps * frame_size * 8) / 1e6
        if max_pps <= 50000:
            feasibility = "trivial"
        elif max_pps <= 500000:
            feasibility = "moderate"
        else:
            feasibility = "difficult"

        return cls(
            name=name,
            description=description,
            max_pps=max_pps,
            frame_size_bytes=frame_size,
            bandwidth_mbps=bw,
            equipment=equipment,
            feasibility=feasibility,
        )


def analyze_attacker_capability(
    saturation_rates: dict[str, float],
    goose_frame_size: int = 200,
    verbose: bool = True,
) -> list[dict]:
    """
    Analyze whether CIL-DoS attack rates are achievable.

    Compares required attack rates against realistic attacker
    capabilities on substation LAN environments.
    """
    # Define attacker capability tiers
    attacker_tiers = [
        AttackerProfile.from_rate(
            "Single laptop (Python)",
            max_pps=10000,
            frame_size=goose_frame_size,
            description="Python script with AF_PACKET, no optimization",
            equipment="Commodity laptop on substation LAN",
        ),
        AttackerProfile.from_rate(
            "Single laptop (C/DPDK)",
            max_pps=100000,
            frame_size=goose_frame_size,
            description="C program with kernel bypass (DPDK/XDP)",
            equipment="Commodity laptop with DPDK-capable NIC",
        ),
        AttackerProfile.from_rate(
            "Dedicated attack box",
            max_pps=1000000,
            frame_size=goose_frame_size,
            description="Dedicated hardware packet generator",
            equipment="Server with 10G NIC + DPDK",
        ),
        AttackerProfile.from_rate(
            "Compromised IED",
            max_pps=50000,
            frame_size=goose_frame_size,
            description="Malware on compromised relay generating traffic",
            equipment="Compromised protection relay on LAN",
        ),
    ]

    results = []

    if verbose:
        print(f"\n{'Attacker Tier':<25} │ {'Max PPS':>10} │ {'BW (Mbps)':>10} │ "
              f"{'Feasibility':>12} │ Can Saturate:")
        print("─" * 90)

    for attacker in attacker_tiers:
        can_saturate = {}
        for algo, sat_rate in saturation_rates.items():
            can_saturate[algo] = "YES ⚠️" if attacker.max_pps >= sat_rate else "NO"

        result = {
            "attacker": attacker.name,
            "max_pps": attacker.max_pps,
            "bandwidth_mbps": attacker.bandwidth_mbps,
            "feasibility": attacker.feasibility,
            "equipment": attacker.equipment,
            **{f"saturates_{algo}": v for algo, v in can_saturate.items()},
        }
        results.append(result)

        if verbose:
            sat_str = " │ ".join(f"{algo}: {v}" for algo, v in can_saturate.items())
            print(f"{attacker.name:<25} │ {attacker.max_pps:>10,} │ "
                  f"{attacker.bandwidth_mbps:>8.1f} │ "
                  f"{attacker.feasibility:>12} │ {sat_str}")

    return results


# ============================================================================
# CLI entry point
# ============================================================================

if __name__ == "__main__":
    print("Run via: python -m gridpulse.bench.validation")
