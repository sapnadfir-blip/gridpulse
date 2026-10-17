"""
Cryptographic Latency Benchmarks for IEC 62351-6.
"""
import csv
import hashlib
import hmac
import time
import math
import statistics
from dataclasses import dataclass
from typing import Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


@dataclass
class BenchmarkResult:
    algorithm: str
    iterations: int
    timings_ns: List[int]
    mean_us: float
    median_us: float
    p95_us: float
    p99_us: float
    min_us: float
    max_us: float
    std_dev_us: float
    total_seconds: float
    throughput_ops_per_sec: float

    def __str__(self) -> str:
        return (
            f"BenchmarkResult(algorithm={self.algorithm}, iter={self.iterations}, "
            f"mean={self.mean_us:.2f}µs, p99={self.p99_us:.2f}µs, ops/s={self.throughput_ops_per_sec:.2f})"
        )

class CryptoBenchmark:
    def __init__(self):
        self.payload = b"GOOSE_PDU_PAYLOAD_DATA" * 10 # ~220 bytes

    def _calc_stats(self, name: str, timings_ns: List[int]) -> BenchmarkResult:
        timings_us = [t / 1000.0 for t in timings_ns]
        total_s = sum(timings_ns) / 1e9
        iterations = len(timings_ns)
        return BenchmarkResult(
            algorithm=name,
            iterations=iterations,
            timings_ns=timings_ns,
            mean_us=statistics.mean(timings_us),
            median_us=statistics.median(timings_us),
            p95_us=statistics.quantiles(timings_us, n=100)[94] if len(timings_us) > 1 else timings_us[0],
            p99_us=statistics.quantiles(timings_us, n=100)[98] if len(timings_us) > 1 else timings_us[0],
            min_us=min(timings_us),
            max_us=max(timings_us),
            std_dev_us=statistics.stdev(timings_us) if len(timings_us) > 1 else 0.0,
            total_seconds=total_s,
            throughput_ops_per_sec=iterations / total_s if total_s > 0 else 0.0,
        )

    def benchmark_hmac_sha256(self, iterations: int = 10000) -> BenchmarkResult:
        key = b"secret_key_for_hmac_sha256_32b!"
        mac = hmac.new(key, self.payload, hashlib.sha256).digest()
        
        # Warmup
        for _ in range(100):
            hmac.compare_digest(hmac.new(key, self.payload, hashlib.sha256).digest(), mac)
            
        timings = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            hmac.compare_digest(hmac.new(key, self.payload, hashlib.sha256).digest(), mac)
            t1 = time.perf_counter_ns()
            timings.append(t1 - t0)
            
        return self._calc_stats("HMAC-SHA256", timings)

    def benchmark_rsa_2048(self, iterations: int = 1000) -> BenchmarkResult:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        signature = private_key.sign(
            self.payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        # Warmup
        for _ in range(100):
            try:
                public_key.verify(
                    signature, self.payload,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception:
                pass
                
        timings = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            public_key.verify(
                signature, self.payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            t1 = time.perf_counter_ns()
            timings.append(t1 - t0)
            
        return self._calc_stats("RSA-2048", timings)

    def benchmark_ecdsa_p256(self, iterations: int = 1000) -> BenchmarkResult:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        signature = private_key.sign(self.payload, ec.ECDSA(hashes.SHA256()))
        
        # Warmup
        for _ in range(100):
            try:
                public_key.verify(signature, self.payload, ec.ECDSA(hashes.SHA256()))
            except Exception:
                pass
                
        timings = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            public_key.verify(signature, self.payload, ec.ECDSA(hashes.SHA256()))
            t1 = time.perf_counter_ns()
            timings.append(t1 - t0)
            
        return self._calc_stats("ECDSA-P256", timings)

    def benchmark_all(self, iterations: int = 1000) -> Dict[str, BenchmarkResult]:
        return {
            "HMAC-SHA256": self.benchmark_hmac_sha256(iterations * 10),
            "RSA-2048": self.benchmark_rsa_2048(iterations),
            "ECDSA-P256": self.benchmark_ecdsa_p256(iterations),
        }

def export_csv(results: List[BenchmarkResult], path: str):
    if not results:
        return
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Algorithm", "Iterations", "Mean (us)", "Median (us)", "P95 (us)", "P99 (us)", "Min (us)", "Max (us)", "StdDev (us)", "Total (s)", "Throughput (ops/s)"])
        for r in results:
            writer.writerow([
                r.algorithm, r.iterations, f"{r.mean_us:.2f}", f"{r.median_us:.2f}", 
                f"{r.p95_us:.2f}", f"{r.p99_us:.2f}", f"{r.min_us:.2f}", f"{r.max_us:.2f}", 
                f"{r.std_dev_us:.2f}", f"{r.total_seconds:.4f}", f"{r.throughput_ops_per_sec:.2f}"
            ])

def print_results(results: List[BenchmarkResult]):
    print(f"{'Algorithm':<15} | {'Ops/sec':<10} | {'Mean (µs)':<10} | {'P99 (µs)':<10}")
    print("-" * 55)
    for r in results:
        print(f"{r.algorithm:<15} | {r.throughput_ops_per_sec:<10.2f} | {r.mean_us:<10.2f} | {r.p99_us:<10.2f}")
