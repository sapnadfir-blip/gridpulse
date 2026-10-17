"""
Extended Validation — Addresses All Reviewer Concerns
======================================================

Run this to produce all data needed for the paper.

Generates:
    results/constrained_hardware.csv    Scaled results for IED processors
    results/model_comparison.csv        M/M/1 vs M/D/1 justification
    results/attacker_capability.csv     Threat model grounding
    results/data_provenance.json        Labels for all data sources
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from gridpulse.bench.validation import (
    ExperimentEnvironment,
    run_multi_trial_benchmark,
    validate_queue_model,
    run_ablation_study,
    run_full_validation,
)
from gridpulse.bench.constrained_hw import (
    PROFILES,
    analyze_constrained_hardware,
    export_constrained_results,
    compare_queue_models,
    analyze_attacker_capability,
)


def run_extended_validation(
    output_dir: str | Path = "results",
    num_trials: int = 10,
    iterations: int = 10000,
    sim_duration: float = 10.0,
    verbose: bool = True,
):
    """Run the complete extended validation addressing all reviewer concerns."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Base validation (env + benchmarks + queue + ablation) ──
    if verbose:
        print("╔" + "═" * 58 + "╗")
        print("║   GRIDPULSE EXTENDED EXPERIMENTAL VALIDATION              ║")
        print("║   Addressing: Hardware, Model, Provenance, Threat Model   ║")
        print("╚" + "═" * 58 + "╝")

    base_results = run_full_validation(
        output_dir=output_dir,
        num_trials=num_trials,
        iterations=iterations,
        sim_duration=sim_duration,
        verbose=verbose,
    )

    # Get multi-trial results again for downstream analysis
    multi_results = run_multi_trial_benchmark(
        num_trials=num_trials,
        iterations=iterations,
        verbose=False,
    )

    # ── Step 2: Constrained Hardware Analysis ────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  REVIEWER CONCERN 1: Apple M2 isn't an IED")
        print("  → Scaling to constrained hardware platforms")
        print("=" * 60)

    hw_results = analyze_constrained_hardware(
        m2_results=multi_results,
        verbose=verbose,
    )
    export_constrained_results(hw_results, output_dir / "constrained_hardware.csv")

    # ── Step 3: Queue Model Justification ────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  REVIEWER CONCERN 2: Why M/M/1?")
        print("  → Comparing M/M/1 vs M/D/1 as confidence bounds")
        print("=" * 60)

    rsa_mu = multi_results["RSA-2048"].mean_throughput_ops_sec
    comparison_rates = [
        rsa_mu * f for f in [0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 0.98]
    ]

    model_comparison = compare_queue_models(
        service_rate=rsa_mu,
        attack_rates=comparison_rates,
        verbose=verbose,
    )

    with open(output_dir / "model_comparison.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Arrival_Rate", "Utilization", "MM1_Wq_us", "MD1_Wq_us",
            "Ratio", "MM1_P_violation", "MD1_P_violation"
        ])
        for row in model_comparison:
            wq1 = f"{row['mm1_wq']:.2f}" if row['mm1_wq'] < 1e6 else "inf"
            wq2 = f"{row['md1_wq']:.2f}" if row['md1_wq'] < 1e6 else "inf"
            writer.writerow([
                f"{row['rate']:.0f}", f"{row['rho']:.4f}",
                wq1, wq2,
                f"{row['ratio']:.2f}" if row['ratio'] < 1e6 else "inf",
                f"{row['mm1_pv']:.6f}", f"{row['md1_pv']:.6f}",
            ])

    # ── Step 4: Attacker Capability ──────────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  REVIEWER CONCERN 4: Attacker capability grounding")
        print("  → Analyzing feasibility across threat model tiers")
        print("=" * 60)

    saturation_rates = {
        algo: multi.mean_throughput_ops_sec
        for algo, multi in multi_results.items()
    }

    attacker_results = analyze_attacker_capability(
        saturation_rates=saturation_rates,
        verbose=verbose,
    )

    with open(output_dir / "attacker_capability.csv", "w", newline="") as f:
        writer = csv.writer(f)
        headers = ["Attacker_Tier", "Max_PPS", "Bandwidth_Mbps", "Feasibility"]
        for algo in saturation_rates:
            headers.append(f"Saturates_{algo}")
        writer.writerow(headers)
        for row in attacker_results:
            vals = [row["attacker"], row["max_pps"],
                    f"{row['bandwidth_mbps']:.1f}", row["feasibility"]]
            for algo in saturation_rates:
                vals.append(row.get(f"saturates_{algo}", ""))
            writer.writerow(vals)

    # ── Step 5: Data Provenance ──────────────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  REVIEWER CONCERN 3: Data provenance (measured vs modeled)")
        print("  → Generating provenance labels for all results")
        print("=" * 60)

    provenance = {
        "_description": "Data provenance labels for all experimental results",
        "_generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "crypto_benchmark.csv": {
            "type": "MEASURED",
            "method": "Direct measurement using time.perf_counter_ns()",
            "hardware": "Apple M2 (see environment.json)",
            "library": "cryptography 49.0.0 (OpenSSL 4.0.1)",
            "notes": "Single-run benchmark, 10K iterations per algorithm",
        },
        "multi_trial_crypto.csv": {
            "type": "MEASURED",
            "method": "Multiple independent benchmark trials",
            "trials": num_trials,
            "iterations_per_trial": iterations,
            "statistical_method": "95% CI via z=1.96, CV computed per trial",
            "hardware": "Apple M2 (see environment.json)",
        },
        "multi_trial_summary.csv": {
            "type": "DERIVED (from measurements)",
            "method": "Aggregated statistics across trials",
            "source": "multi_trial_crypto.csv",
        },
        "queue_validation.csv": {
            "type": "ANALYTICAL + SIMULATED",
            "analytical_model": "M/M/1 (Markov arrival, Markov service)",
            "simulation_type": "Discrete-event Monte Carlo simulation",
            "simulation_seeds": [42, 123, 456, 789, 1024],
            "simulation_duration_sec": sim_duration,
            "service_rate_source": "MEASURED (from multi_trial_crypto.csv)",
            "notes": "Service rate µ derived from measured verification latency",
        },
        "model_comparison.csv": {
            "type": "ANALYTICAL",
            "models": ["M/M/1 (exponential service)", "M/D/1 (deterministic service)"],
            "justification": (
                "M/M/1 provides upper bound on wait times (conservative). "
                "M/D/1 provides lower bound. True system lies between these bounds. "
                "M/M/1 selected as primary model for worst-case analysis."
            ),
            "service_rate_source": "MEASURED",
        },
        "constrained_hardware.csv": {
            "type": "ESTIMATED (scaled from measurements)",
            "method": "M2 measurements × hardware-specific scaling factors",
            "scaling_source": "Published benchmarks (mbed TLS, TI SDK, OpenSSL speed)",
            "hardware_profiles": {
                "ARM_Cortex-M4": "168 MHz, no crypto accel, mbed TLS benchmarks",
                "ARM_Cortex-R5": "600 MHz, no crypto accel, TI AM65x SDK benchmarks",
                "ARM_Cortex-A9": "800 MHz, NEON, Zynq-7020 OpenSSL benchmarks",
                "Intel_Atom_E3800": "1.91 GHz, AES-NI, OpenSSL speed benchmarks",
            },
            "limitation": (
                "Scaling factors are estimates based on published benchmarks. "
                "Actual IED performance should be measured on target hardware "
                "for publication-grade results."
            ),
        },
        "ablation_study.csv": {
            "type": "ANALYTICAL (modeled from measurements)",
            "method": "M/M/1 queueing model with measured service rates",
            "defense_modes": {
                "none": "No defense — all attack traffic reaches verifier",
                "rate_limit_1k": "Per-source rate limiter at 1,000 pps",
                "rate_limit_5k": "Per-source rate limiter at 5,000 pps",
                "mac_filter": "MAC allowlist — drops 100% of unknown sources",
                "full_xdp": "Combined XDP defense (MAC + rate limit + sequence validation)",
            },
            "xdp_note": (
                "XDP defense effectiveness values are MODELED (not measured on live XDP). "
                "The model assumes XDP drops packets before they reach the verification queue. "
                "This assumption is valid because XDP operates at NIC driver level, "
                "before any application processing."
            ),
        },
        "attacker_capability.csv": {
            "type": "ESTIMATED (literature-based)",
            "method": "Attacker capability tiers based on published packet generation benchmarks",
            "assumptions": [
                "Attacker has physical or logical access to substation LAN",
                "GOOSE is multicast over Ethernet (no routing/firewall between attacker and IED)",
                "Packet rates based on AF_PACKET (Python), DPDK (C), and hardware generators",
            ],
        },
    }

    with open(output_dir / "data_provenance.json", "w") as f:
        json.dump(provenance, f, indent=2)

    if verbose:
        print("\n  Data provenance labels:")
        for fname, info in provenance.items():
            if fname.startswith("_"):
                continue
            print(f"    {fname:<35} → {info['type']}")

    # ── Summary ──────────────────────────────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  EXTENDED VALIDATION COMPLETE")
        print("=" * 60)
        print(f"\n  All output files in {output_dir}/:")
        for f in sorted(output_dir.glob("*")):
            size = f.stat().st_size
            print(f"    {f.name:<35} {size:>8,} bytes")
        print(f"\n  Total: {sum(f.stat().st_size for f in output_dir.glob('*')):,} bytes")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GridPulse Extended Validation")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--sim-duration", type=float, default=10.0)
    parser.add_argument("--output", type=str, default="results")
    args = parser.parse_args()

    run_extended_validation(
        output_dir=args.output,
        num_trials=args.trials,
        iterations=args.iterations,
        sim_duration=args.sim_duration,
    )
