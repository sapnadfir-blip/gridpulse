"""
GridPulse Experimental Validation Suite
========================================

Rigorous experimental methodology for CIL-DoS research. Produces
publication-ready results with:

  1. Multi-trial benchmarks with 95% confidence intervals
  2. Hardware & software environment documentation
  3. Queueing model validation against discrete-event simulation
  4. Ablation studies (algorithm × rate × defense)
  5. End-to-end verification queue simulation under flood

This module generates all data needed for the Results section of
the research paper.

Usage:
    python -m gridpulse.bench.validation --trials 10 --iterations 10000
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import os
import platform
import statistics
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from gridpulse.bench.crypto_bench import CryptoBenchmark, BenchmarkResult
from gridpulse.bench.queue_model import MM1Queue, MD1Queue


# ============================================================================
# 1. Hardware & Environment Documentation
# ============================================================================

@dataclass
class ExperimentEnvironment:
    """Captures complete experimental environment for reproducibility."""
    timestamp: str
    hostname: str
    os_name: str
    os_version: str
    os_release: str
    architecture: str
    cpu_model: str
    cpu_cores_physical: int
    cpu_cores_logical: int
    ram_total_gb: float
    python_version: str
    python_implementation: str
    cryptography_version: str
    openssl_version: str

    @classmethod
    def capture(cls) -> 'ExperimentEnvironment':
        """Capture current environment details."""
        cpu_model = "Unknown"
        ram_gb = 0.0
        cores_phys = os.cpu_count() or 0
        cores_logical = os.cpu_count() or 0

        try:
            if platform.system() == "Darwin":
                cpu_model = subprocess.check_output(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    text=True, timeout=5
                ).strip()
                ram_bytes = int(subprocess.check_output(
                    ["sysctl", "-n", "hw.memsize"],
                    text=True, timeout=5
                ).strip())
                ram_gb = ram_bytes / (1024**3)
                cores_phys = int(subprocess.check_output(
                    ["sysctl", "-n", "hw.physicalcpu"],
                    text=True, timeout=5
                ).strip())
                cores_logical = int(subprocess.check_output(
                    ["sysctl", "-n", "hw.logicalcpu"],
                    text=True, timeout=5
                ).strip())
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if "model name" in line:
                            cpu_model = line.split(":")[1].strip()
                            break
                with open("/proc/meminfo") as f:
                    for line in f:
                        if "MemTotal" in line:
                            ram_kb = int(line.split()[1])
                            ram_gb = ram_kb / (1024**2)
                            break
        except Exception:
            pass

        crypto_ver = "Not installed"
        openssl_ver = "Unknown"
        try:
            import cryptography
            crypto_ver = cryptography.__version__
            from cryptography.hazmat.backends.openssl import backend
            openssl_ver = backend.openssl_version_text()
        except Exception:
            pass

        return cls(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            hostname=platform.node(),
            os_name=platform.system(),
            os_version=platform.version(),
            os_release=platform.release(),
            architecture=platform.machine(),
            cpu_model=cpu_model,
            cpu_cores_physical=cores_phys,
            cpu_cores_logical=cores_logical,
            ram_total_gb=round(ram_gb, 2),
            python_version=platform.python_version(),
            python_implementation=platform.python_implementation(),
            cryptography_version=crypto_ver,
            openssl_version=openssl_ver,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def __str__(self) -> str:
        return (
            f"╔══════════════════════════════════════════════════╗\n"
            f"║         Experiment Environment                   ║\n"
            f"╠══════════════════════════════════════════════════╣\n"
            f"║  Timestamp:   {self.timestamp:<35}║\n"
            f"║  Hostname:    {self.hostname:<35}║\n"
            f"║  OS:          {self.os_name} {self.os_release:<27}║\n"
            f"║  CPU:         {self.cpu_model[:35]:<35}║\n"
            f"║  Cores:       {self.cpu_cores_physical}P / {self.cpu_cores_logical}L"
            f"{'':>{35 - len(str(self.cpu_cores_physical)) - len(str(self.cpu_cores_logical)) - 6}}║\n"
            f"║  RAM:         {self.ram_total_gb:.1f} GB"
            f"{'':>{31 - len(f'{self.ram_total_gb:.1f}')}}║\n"
            f"║  Python:      {self.python_version} ({self.python_implementation})"
            f"{'':>{21 - len(self.python_implementation)}}║\n"
            f"║  Crypto Lib:  {self.cryptography_version:<35}║\n"
            f"║  OpenSSL:     {self.openssl_version[:35]:<35}║\n"
            f"╚══════════════════════════════════════════════════╝"
        )


# ============================================================================
# 2. Multi-Trial Benchmark with Confidence Intervals
# ============================================================================

@dataclass
class TrialResult:
    """Result of a single benchmark trial."""
    trial_number: int
    mean_us: float
    median_us: float
    p95_us: float
    p99_us: float
    min_us: float
    max_us: float
    std_dev_us: float
    throughput_ops_sec: float


@dataclass
class MultiTrialResult:
    """Aggregated result across multiple independent trials."""
    algorithm: str
    num_trials: int
    iterations_per_trial: int
    trials: list[TrialResult]

    # Aggregated statistics across trials
    grand_mean_us: float = 0.0
    grand_median_us: float = 0.0
    grand_std_dev_us: float = 0.0
    ci_95_lower_us: float = 0.0
    ci_95_upper_us: float = 0.0
    ci_99_lower_us: float = 0.0
    ci_99_upper_us: float = 0.0
    mean_throughput_ops_sec: float = 0.0
    throughput_ci_95_lower: float = 0.0
    throughput_ci_95_upper: float = 0.0
    coefficient_of_variation: float = 0.0

    def __post_init__(self):
        if self.trials:
            self._compute_aggregates()

    def _compute_aggregates(self):
        means = [t.mean_us for t in self.trials]
        throughputs = [t.throughput_ops_sec for t in self.trials]
        n = len(means)

        self.grand_mean_us = statistics.mean(means)
        self.grand_median_us = statistics.median(means)
        self.grand_std_dev_us = statistics.stdev(means) if n > 1 else 0.0

        # 95% CI: mean ± t_{0.025, n-1} * (s / √n)
        # For simplicity, use z=1.96 for 95% and z=2.576 for 99%
        se = self.grand_std_dev_us / math.sqrt(n) if n > 1 else 0.0
        self.ci_95_lower_us = self.grand_mean_us - 1.96 * se
        self.ci_95_upper_us = self.grand_mean_us + 1.96 * se
        self.ci_99_lower_us = self.grand_mean_us - 2.576 * se
        self.ci_99_upper_us = self.grand_mean_us + 2.576 * se

        self.mean_throughput_ops_sec = statistics.mean(throughputs)
        tp_std = statistics.stdev(throughputs) if n > 1 else 0.0
        tp_se = tp_std / math.sqrt(n) if n > 1 else 0.0
        self.throughput_ci_95_lower = self.mean_throughput_ops_sec - 1.96 * tp_se
        self.throughput_ci_95_upper = self.mean_throughput_ops_sec + 1.96 * tp_se

        self.coefficient_of_variation = (
            (self.grand_std_dev_us / self.grand_mean_us * 100)
            if self.grand_mean_us > 0 else 0.0
        )

    def __str__(self) -> str:
        return (
            f"┌─────────────────────────────────────────────────┐\n"
            f"│  {self.algorithm:^46} │\n"
            f"│  {self.num_trials} trials × {self.iterations_per_trial:,} iterations"
            f"{'':>{27 - len(str(self.num_trials)) - len(f'{self.iterations_per_trial:,}')}}│\n"
            f"├─────────────────────────────────────────────────┤\n"
            f"│  Grand Mean:       {self.grand_mean_us:>8.2f} µs"
            f"{'':>18}│\n"
            f"│  95% CI:           [{self.ci_95_lower_us:.2f}, {self.ci_95_upper_us:.2f}] µs"
            f"{'':>{10 - max(0, len(f'{self.ci_95_upper_us:.2f}') - 5)}}│\n"
            f"│  Std Dev:          {self.grand_std_dev_us:>8.4f} µs"
            f"{'':>18}│\n"
            f"│  CV:               {self.coefficient_of_variation:>8.2f} %"
            f"{'':>19}│\n"
            f"│  Throughput:       {self.mean_throughput_ops_sec:>8.0f} ops/sec"
            f"{'':>13}│\n"
            f"│  Throughput 95%CI: [{self.throughput_ci_95_lower:.0f}, "
            f"{self.throughput_ci_95_upper:.0f}]"
            f"{'':>{14 - max(0, len(f'{self.throughput_ci_95_upper:.0f}') - 5)}}│\n"
            f"└─────────────────────────────────────────────────┘"
        )


def run_multi_trial_benchmark(
    num_trials: int = 10,
    iterations: int = 10000,
    verbose: bool = True,
) -> dict[str, MultiTrialResult]:
    """
    Run multiple independent benchmark trials for each algorithm.

    Each trial is a complete, independent benchmark run. Statistics
    are computed across trials to produce confidence intervals.
    """
    benchmark = CryptoBenchmark()
    results: dict[str, MultiTrialResult] = {}

    algorithms = [
        ("HMAC-SHA256", lambda n: benchmark.benchmark_hmac_sha256(n)),
        ("RSA-2048", lambda n: benchmark.benchmark_rsa_2048(n)),
        ("ECDSA-P256", lambda n: benchmark.benchmark_ecdsa_p256(n)),
    ]

    for algo_name, bench_fn in algorithms:
        if verbose:
            print(f"\n  Benchmarking {algo_name} ({num_trials} trials × {iterations:,} iterations)...")

        trials = []
        for trial in range(num_trials):
            # Run one full benchmark
            result = bench_fn(iterations)
            tr = TrialResult(
                trial_number=trial + 1,
                mean_us=result.mean_us,
                median_us=result.median_us,
                p95_us=result.p95_us,
                p99_us=result.p99_us,
                min_us=result.min_us,
                max_us=result.max_us,
                std_dev_us=result.std_dev_us,
                throughput_ops_sec=result.throughput_ops_per_sec,
            )
            trials.append(tr)

            if verbose:
                print(f"    Trial {trial+1:>2}/{num_trials}: "
                      f"mean={tr.mean_us:.2f}µs, "
                      f"ops/s={tr.throughput_ops_sec:,.0f}")

        multi = MultiTrialResult(
            algorithm=algo_name,
            num_trials=num_trials,
            iterations_per_trial=iterations,
            trials=trials,
        )
        results[algo_name] = multi

        if verbose:
            print(str(multi))

    return results


# ============================================================================
# 3. Discrete-Event Queue Simulation (Model Validation)
# ============================================================================

@dataclass
class SimulationResult:
    """Result of a discrete-event queue simulation."""
    arrival_rate: float
    service_rate: float
    duration_seconds: float
    total_arrivals: int
    total_served: int
    total_dropped: int      # Dropped due to queue overflow
    mean_wait_us: float
    median_wait_us: float
    p95_wait_us: float
    p99_wait_us: float
    max_wait_us: float
    deadline_violations: int
    deadline_violation_ratio: float
    mean_queue_length: float
    max_queue_length: int
    utilization: float


def simulate_verification_queue(
    arrival_rate_pps: float,
    service_rate_ops: float,
    duration_seconds: float = 10.0,
    deadline_us: float = 3000.0,
    max_queue_size: int = 100000,
    seed: int = 42,
) -> SimulationResult:
    """
    Discrete-event simulation of the GOOSE verification queue.

    Simulates arrivals (Poisson process) and service (exponential or
    deterministic) to validate the M/M/1 and M/D/1 analytical models.

    This is crucial for validating the queueing model predictions
    against actual queue behavior.

    Args:
        arrival_rate_pps: Packet arrival rate (λ) in packets/sec
        service_rate_ops: Verification service rate (µ) in ops/sec
        duration_seconds: Simulation duration
        deadline_us: Safety deadline in microseconds
        max_queue_size: Maximum queue depth before dropping
        seed: Random seed for reproducibility
    """
    import random
    rng = random.Random(seed)

    mean_interarrival = 1.0 / arrival_rate_pps if arrival_rate_pps > 0 else float('inf')
    mean_service = 1.0 / service_rate_ops if service_rate_ops > 0 else float('inf')

    # Event-driven simulation
    clock = 0.0
    server_busy_until = 0.0
    queue: list[float] = []  # Arrival times of queued packets

    wait_times: list[float] = []
    queue_lengths: list[int] = []
    deadline_violations = 0
    total_arrivals = 0
    total_served = 0
    total_dropped = 0

    # Schedule first arrival
    next_arrival = rng.expovariate(1.0 / mean_interarrival)

    while next_arrival < duration_seconds:
        clock = next_arrival
        total_arrivals += 1

        # Process completed services
        while queue and server_busy_until <= clock:
            arrival_time = queue.pop(0)
            wait = (server_busy_until - arrival_time) * 1e6  # Convert to µs
            if wait < 0:
                wait = 0
            service_time = rng.expovariate(1.0 / mean_service)
            server_busy_until = max(server_busy_until, arrival_time) + service_time
            total_wait = wait + service_time * 1e6
            wait_times.append(total_wait)
            total_served += 1
            if total_wait > deadline_us:
                deadline_violations += 1

        # Enqueue new arrival
        if len(queue) < max_queue_size:
            if server_busy_until <= clock:
                # Server idle, serve immediately
                service_time = rng.expovariate(1.0 / mean_service)
                wait = service_time * 1e6
                wait_times.append(wait)
                server_busy_until = clock + service_time
                total_served += 1
                if wait > deadline_us:
                    deadline_violations += 1
            else:
                queue.append(clock)
        else:
            total_dropped += 1

        queue_lengths.append(len(queue))

        # Schedule next arrival
        next_arrival = clock + rng.expovariate(1.0 / mean_interarrival)

    # Drain remaining queue
    while queue:
        arrival_time = queue.pop(0)
        service_time = rng.expovariate(1.0 / mean_service)
        server_busy_until = max(server_busy_until, arrival_time) + service_time
        wait = (server_busy_until - arrival_time) * 1e6
        wait_times.append(wait)
        total_served += 1
        if wait > deadline_us:
            deadline_violations += 1

    if not wait_times:
        wait_times = [0.0]
    if not queue_lengths:
        queue_lengths = [0]

    sorted_waits = sorted(wait_times)
    n = len(sorted_waits)

    return SimulationResult(
        arrival_rate=arrival_rate_pps,
        service_rate=service_rate_ops,
        duration_seconds=duration_seconds,
        total_arrivals=total_arrivals,
        total_served=total_served,
        total_dropped=total_dropped,
        mean_wait_us=statistics.mean(wait_times),
        median_wait_us=sorted_waits[n // 2],
        p95_wait_us=sorted_waits[int(n * 0.95)] if n >= 20 else sorted_waits[-1],
        p99_wait_us=sorted_waits[int(n * 0.99)] if n >= 100 else sorted_waits[-1],
        max_wait_us=sorted_waits[-1],
        deadline_violations=deadline_violations,
        deadline_violation_ratio=deadline_violations / max(total_served, 1),
        mean_queue_length=statistics.mean(queue_lengths),
        max_queue_length=max(queue_lengths),
        utilization=arrival_rate_pps / service_rate_ops if service_rate_ops > 0 else float('inf'),
    )


def validate_queue_model(
    service_rate: float,
    attack_rates: list[float],
    deadline_us: float = 3000.0,
    sim_duration: float = 10.0,
    sim_seeds: list[int] | None = None,
    verbose: bool = True,
) -> list[dict]:
    """
    Validate M/M/1 analytical model against discrete-event simulation.

    Runs simulations at each attack rate and compares predictions
    with observed behavior. Reports prediction error.
    """
    if sim_seeds is None:
        sim_seeds = [42, 123, 456, 789, 1024]

    results = []

    if verbose:
        print(f"\n{'λ (pps)':>10} │ {'ρ':>6} │ "
              f"{'Model Wq':>10} │ {'Sim Wq':>10} │ {'Error':>8} │ "
              f"{'Model P(v)':>10} │ {'Sim P(v)':>10} │ {'Error':>8}")
        print("─" * 95)

    for rate in attack_rates:
        rho = rate / service_rate
        if rho >= 1.0:
            if verbose:
                print(f"{rate:>10,.0f} │ {rho:>6.3f} │ {'∞':>10} │ "
                      f"{'—':>10} │ {'—':>8} │ {'1.000':>10} │ "
                      f"{'—':>10} │ {'—':>8}")
            continue

        # Analytical M/M/1 prediction
        try:
            mm1 = MM1Queue(rate, service_rate)
            model_wq = mm1.mean_wait_time * 1e6  # seconds → µs
            model_pv = mm1.prob_deadline_violation(deadline_us / 1e6)
        except (ValueError, ZeroDivisionError):
            continue

        # Simulation (average across seeds)
        sim_wqs = []
        sim_pvs = []
        for seed in sim_seeds:
            sim = simulate_verification_queue(
                arrival_rate_pps=rate,
                service_rate_ops=service_rate,
                duration_seconds=sim_duration,
                deadline_us=deadline_us,
                seed=seed,
            )
            sim_wqs.append(sim.mean_wait_us)
            sim_pvs.append(sim.deadline_violation_ratio)

        sim_wq = statistics.mean(sim_wqs)
        sim_pv = statistics.mean(sim_pvs)

        wq_error = abs(model_wq - sim_wq) / max(sim_wq, 0.001) * 100
        pv_error = abs(model_pv - sim_pv) * 100  # Absolute error in percentage points

        row = {
            "arrival_rate": rate,
            "utilization": rho,
            "model_wq_us": model_wq,
            "sim_wq_us": sim_wq,
            "wq_error_pct": wq_error,
            "model_violation_prob": model_pv,
            "sim_violation_prob": sim_pv,
            "pv_error_pp": pv_error,
        }
        results.append(row)

        if verbose:
            print(f"{rate:>10,.0f} │ {rho:>6.3f} │ "
                  f"{model_wq:>8.1f}µs │ {sim_wq:>8.1f}µs │ "
                  f"{wq_error:>6.1f}% │ "
                  f"{model_pv:>10.4f} │ {sim_pv:>10.4f} │ "
                  f"{pv_error:>6.2f}pp")

    return results


# ============================================================================
# 4. Ablation Study
# ============================================================================

@dataclass
class AblationResult:
    """Result of one ablation experiment configuration."""
    algorithm: str
    attack_rate_pps: float
    defense_mode: str      # "none", "rate_limit", "mac_filter", "full_xdp"
    service_rate: float
    utilization: float
    mean_wait_us: float
    deadline_violation_ratio: float
    effective_attack_rate: float  # After defense filtering


def run_ablation_study(
    benchmark_results: dict[str, MultiTrialResult],
    attack_rates: list[float] | None = None,
    defense_filter_rates: dict[str, float] | None = None,
    deadline_us: float = 3000.0,
    verbose: bool = True,
) -> list[AblationResult]:
    """
    Ablation study: algorithm × attack_rate × defense_mode.

    For each combination, computes the expected queue behavior
    and deadline violation probability.

    Defense modes:
    - "none": No defense, all attack traffic reaches verification
    - "rate_limit_1k": Rate limiter at 1000 pps per source
    - "rate_limit_5k": Rate limiter at 5000 pps per source
    - "mac_filter": MAC allowlist drops 100% of attack traffic
    - "full_xdp": Combined MAC + rate limit + sequence validation
    """
    if attack_rates is None:
        attack_rates = [1000, 5000, 10000, 20000, 50000, 100000]

    if defense_filter_rates is None:
        defense_filter_rates = {
            "none": 1.0,           # 100% passes through
            "rate_limit_1k": None, # Capped at 1000 pps
            "rate_limit_5k": None, # Capped at 5000 pps
            "mac_filter": 0.0,     # 0% passes (all dropped)
            "full_xdp": 0.0,       # 0% passes
        }

    results: list[AblationResult] = []

    if verbose:
        print(f"\n{'Algorithm':<15} │ {'Attack λ':>10} │ {'Defense':>15} │ "
              f"{'Eff. λ':>10} │ {'ρ':>6} │ {'Wq (µs)':>10} │ {'P(viol)':>10}")
        print("─" * 90)

    for algo_name, multi_result in benchmark_results.items():
        mu = multi_result.mean_throughput_ops_sec

        for attack_rate in attack_rates:
            for defense, filter_factor in defense_filter_rates.items():
                # Calculate effective attack rate after defense
                if filter_factor is not None:
                    effective_rate = attack_rate * filter_factor
                elif "1k" in defense:
                    effective_rate = min(attack_rate, 1000)
                elif "5k" in defense:
                    effective_rate = min(attack_rate, 5000)
                else:
                    effective_rate = attack_rate

                # Add baseline legitimate traffic (~100 pps)
                total_rate = effective_rate + 100

                rho = total_rate / mu
                if rho >= 1.0:
                    wq = float('inf')
                    pv = 1.0
                else:
                    try:
                        mm1 = MM1Queue(total_rate, mu)
                        wq = mm1.mean_wait_time * 1e6
                        pv = mm1.prob_deadline_violation(deadline_us / 1e6)
                    except (ValueError, ZeroDivisionError):
                        wq = float('inf')
                        pv = 1.0

                result = AblationResult(
                    algorithm=algo_name,
                    attack_rate_pps=attack_rate,
                    defense_mode=defense,
                    service_rate=mu,
                    utilization=rho,
                    mean_wait_us=wq,
                    deadline_violation_ratio=pv,
                    effective_attack_rate=effective_rate,
                )
                results.append(result)

                if verbose:
                    wq_str = f"{wq:.1f}" if wq < 1e6 else "∞"
                    print(f"{algo_name:<15} │ {attack_rate:>10,.0f} │ "
                          f"{defense:>15} │ {effective_rate:>10,.0f} │ "
                          f"{rho:>6.3f} │ {wq_str:>10} │ {pv:>10.4f}")

    return results


# ============================================================================
# 5. Full Validation Runner
# ============================================================================

def run_full_validation(
    output_dir: str | Path = "results",
    num_trials: int = 10,
    iterations: int = 10000,
    sim_duration: float = 10.0,
    verbose: bool = True,
) -> dict:
    """
    Run the complete experimental validation suite.

    Produces:
    - results/environment.json          Hardware & software specs
    - results/multi_trial_crypto.csv    Per-trial benchmark data
    - results/multi_trial_summary.csv   Aggregated results with CIs
    - results/queue_validation.csv      Model vs. simulation comparison
    - results/ablation_study.csv        Algorithm × rate × defense matrix
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = {}

    # ── Step 1: Environment ──────────────────────────────────────
    if verbose:
        print("=" * 60)
        print("  STEP 1: Capturing Experiment Environment")
        print("=" * 60)

    env = ExperimentEnvironment.capture()
    env.save(output_dir / "environment.json")
    if verbose:
        print(str(env))
    all_results["environment"] = env.to_dict()

    # ── Step 2: Multi-Trial Benchmarks ───────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  STEP 2: Multi-Trial Cryptographic Benchmarks")
        print(f"          {num_trials} trials × {iterations:,} iterations")
        print("=" * 60)

    multi_results = run_multi_trial_benchmark(
        num_trials=num_trials,
        iterations=iterations,
        verbose=verbose,
    )

    # Save per-trial CSV
    with open(output_dir / "multi_trial_crypto.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Algorithm", "Trial", "Mean_us", "Median_us", "P95_us",
            "P99_us", "Min_us", "Max_us", "StdDev_us", "Throughput_ops_sec"
        ])
        for algo, multi in multi_results.items():
            for tr in multi.trials:
                writer.writerow([
                    algo, tr.trial_number, f"{tr.mean_us:.4f}",
                    f"{tr.median_us:.4f}", f"{tr.p95_us:.4f}",
                    f"{tr.p99_us:.4f}", f"{tr.min_us:.4f}",
                    f"{tr.max_us:.4f}", f"{tr.std_dev_us:.4f}",
                    f"{tr.throughput_ops_sec:.2f}"
                ])

    # Save summary CSV
    with open(output_dir / "multi_trial_summary.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Algorithm", "Trials", "Iterations", "Grand_Mean_us",
            "CI95_Lower_us", "CI95_Upper_us", "StdDev_us", "CV_pct",
            "Mean_Throughput", "Throughput_CI95_Lower", "Throughput_CI95_Upper"
        ])
        for algo, multi in multi_results.items():
            writer.writerow([
                algo, multi.num_trials, multi.iterations_per_trial,
                f"{multi.grand_mean_us:.4f}",
                f"{multi.ci_95_lower_us:.4f}", f"{multi.ci_95_upper_us:.4f}",
                f"{multi.grand_std_dev_us:.4f}", f"{multi.coefficient_of_variation:.2f}",
                f"{multi.mean_throughput_ops_sec:.2f}",
                f"{multi.throughput_ci_95_lower:.2f}",
                f"{multi.throughput_ci_95_upper:.2f}",
            ])

    all_results["benchmarks"] = {
        algo: {
            "grand_mean_us": m.grand_mean_us,
            "ci_95": [m.ci_95_lower_us, m.ci_95_upper_us],
            "throughput": m.mean_throughput_ops_sec,
            "cv_pct": m.coefficient_of_variation,
        }
        for algo, m in multi_results.items()
    }

    # ── Step 3: Queue Model Validation ───────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  STEP 3: Queueing Model Validation (M/M/1 vs Simulation)")
        print("=" * 60)

    # Use RSA-2048 service rate for validation (most relevant for CIL-DoS)
    rsa_mu = multi_results["RSA-2048"].mean_throughput_ops_sec
    validation_rates = [
        rsa_mu * 0.1, rsa_mu * 0.3, rsa_mu * 0.5,
        rsa_mu * 0.7, rsa_mu * 0.8, rsa_mu * 0.9,
        rsa_mu * 0.95, rsa_mu * 0.98,
    ]

    validation = validate_queue_model(
        service_rate=rsa_mu,
        attack_rates=validation_rates,
        deadline_us=3000.0,
        sim_duration=sim_duration,
        verbose=verbose,
    )

    with open(output_dir / "queue_validation.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Arrival_Rate", "Utilization", "Model_Wq_us", "Sim_Wq_us",
            "Wq_Error_pct", "Model_Violation_Prob", "Sim_Violation_Prob",
            "PV_Error_pp"
        ])
        for row in validation:
            writer.writerow([
                f"{row['arrival_rate']:.0f}", f"{row['utilization']:.4f}",
                f"{row['model_wq_us']:.2f}", f"{row['sim_wq_us']:.2f}",
                f"{row['wq_error_pct']:.2f}", f"{row['model_violation_prob']:.6f}",
                f"{row['sim_violation_prob']:.6f}", f"{row['pv_error_pp']:.4f}",
            ])

    all_results["queue_validation"] = validation

    # ── Step 4: Ablation Study ───────────────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  STEP 4: Ablation Study (Algorithm × Rate × Defense)")
        print("=" * 60)

    ablation = run_ablation_study(
        benchmark_results=multi_results,
        verbose=verbose,
    )

    with open(output_dir / "ablation_study.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Algorithm", "Attack_Rate", "Defense_Mode", "Service_Rate",
            "Effective_Rate", "Utilization", "Mean_Wait_us",
            "Deadline_Violation_Ratio"
        ])
        for r in ablation:
            wq = f"{r.mean_wait_us:.2f}" if r.mean_wait_us < 1e6 else "inf"
            writer.writerow([
                r.algorithm, f"{r.attack_rate_pps:.0f}", r.defense_mode,
                f"{r.service_rate:.2f}", f"{r.effective_attack_rate:.0f}",
                f"{r.utilization:.6f}", wq,
                f"{r.deadline_violation_ratio:.6f}",
            ])

    all_results["ablation_count"] = len(ablation)

    # ── Summary ──────────────────────────────────────────────────
    if verbose:
        print("\n" + "=" * 60)
        print("  VALIDATION COMPLETE")
        print("=" * 60)
        print(f"\n  Output files in {output_dir}/:")
        for f in sorted(output_dir.glob("*")):
            size = f.stat().st_size
            print(f"    {f.name:<35} {size:>8,} bytes")

    return all_results


# ============================================================================
# CLI entry point
# ============================================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GridPulse Experimental Validation")
    parser.add_argument("--trials", type=int, default=10, help="Number of benchmark trials")
    parser.add_argument("--iterations", type=int, default=10000, help="Iterations per trial")
    parser.add_argument("--sim-duration", type=float, default=10.0, help="Simulation duration (sec)")
    parser.add_argument("--output", type=str, default="results", help="Output directory")
    args = parser.parse_args()

    run_full_validation(
        output_dir=args.output,
        num_trials=args.trials,
        iterations=args.iterations,
        sim_duration=args.sim_duration,
    )
