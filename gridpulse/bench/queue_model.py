"""
Queueing Theory Model for CIL-DoS analysis.
"""
import math
from dataclasses import dataclass
from typing import List, Dict, Any
from .crypto_bench import BenchmarkResult

@dataclass
class QueuePrediction:
    arrival_rate: float
    service_rate: float
    utilization: float
    mean_wait_us: float
    deadline_violation_prob: float
    queue_length: float

    def __str__(self) -> str:
        return (f"Rate={self.arrival_rate:g}, Util={self.utilization*100:.1f}%, "
                f"Wait={self.mean_wait_us:.1f}µs, MissProb={self.deadline_violation_prob*100:.2f}%")


class MM1Queue:
    """
    M/M/1 Queueing Model.
    Models exponential arrivals and exponential service times.
    """
    def __init__(self, arrival_rate_lambda: float, service_rate_mu: float):
        self.arrival_rate_lambda = arrival_rate_lambda
        self.service_rate_mu = service_rate_mu
        
    @property
    def utilization_rho(self) -> float:
        """Utilization factor (rho = lambda / mu)."""
        if self.service_rate_mu == 0:
            return float('inf')
        return self.arrival_rate_lambda / self.service_rate_mu

    @property
    def mean_queue_length(self) -> float:
        """Mean number of items in the queue (L_q = rho^2 / (1 - rho))."""
        rho = self.utilization_rho
        if rho >= 1.0:
            return float('inf')
        return (rho ** 2) / (1 - rho)

    @property
    def mean_wait_time(self) -> float:
        """Mean time spent waiting in the queue (W_q = rho / (mu * (1 - rho)))."""
        rho = self.utilization_rho
        if rho >= 1.0:
            return float('inf')
        return rho / (self.service_rate_mu * (1 - rho))

    @property
    def mean_system_time(self) -> float:
        """Mean time spent in the system (W = 1 / (mu - lambda))."""
        rho = self.utilization_rho
        if rho >= 1.0:
            return float('inf')
        return 1 / (self.service_rate_mu - self.arrival_rate_lambda)

    def prob_deadline_violation(self, deadline_seconds: float) -> float:
        """Probability that waiting time W exceeds a given deadline (P(W > t) = rho * e^(-mu * (1 - rho) * t))."""
        rho = self.utilization_rho
        if rho >= 1.0:
            return 1.0
        return rho * math.exp(-self.service_rate_mu * (1 - rho) * deadline_seconds)

    def find_critical_arrival_rate(self, deadline_seconds: float, max_violation_prob: float) -> float:
        """Find the maximum arrival rate that keeps deadline violation probability below max_violation_prob."""
        low = 0.0
        high = self.service_rate_mu - 0.001
        for _ in range(50):
            mid = (low + high) / 2
            self.arrival_rate_lambda = mid
            prob = self.prob_deadline_violation(deadline_seconds)
            if prob > max_violation_prob:
                high = mid
            else:
                low = mid
        ans = (low + high) / 2
        return ans


class MD1Queue:
    """
    M/D/1 Queueing Model.
    Models exponential arrivals and deterministic service times.
    """
    def __init__(self, arrival_rate_lambda: float, service_rate_mu: float):
        self.arrival_rate_lambda = arrival_rate_lambda
        self.service_rate_mu = service_rate_mu

    @property
    def utilization_rho(self) -> float:
        if self.service_rate_mu == 0:
            return float('inf')
        return self.arrival_rate_lambda / self.service_rate_mu

    @property
    def mean_queue_length(self) -> float:
        """L_q = rho^2 / (2 * (1 - rho))"""
        rho = self.utilization_rho
        if rho >= 1.0:
            return float('inf')
        return (rho ** 2) / (2 * (1 - rho))

    @property
    def mean_wait_time(self) -> float:
        """W_q = rho / (2 * mu * (1 - rho))"""
        rho = self.utilization_rho
        if rho >= 1.0:
            return float('inf')
        return rho / (2 * self.service_rate_mu * (1 - rho))

    @property
    def mean_system_time(self) -> float:
        """W = W_q + 1/mu"""
        rho = self.utilization_rho
        if rho >= 1.0:
            return float('inf')
        return self.mean_wait_time + (1 / self.service_rate_mu)

    def prob_deadline_violation(self, deadline_seconds: float) -> float:
        """Approximation for M/D/1 tail distribution."""
        rho = self.utilization_rho
        if rho >= 1.0:
            return 1.0
        return rho * math.exp(-2 * self.service_rate_mu * (1 - rho) * deadline_seconds)

    def find_critical_arrival_rate(self, deadline_seconds: float, max_violation_prob: float) -> float:
        low = 0.0
        high = self.service_rate_mu - 0.001
        for _ in range(50):
            mid = (low + high) / 2
            self.arrival_rate_lambda = mid
            prob = self.prob_deadline_violation(deadline_seconds)
            if prob > max_violation_prob:
                high = mid
            else:
                low = mid
        ans = (low + high) / 2
        return ans


class QueueAnalysis:
    def __init__(self, service_rate_mu: float):
        self.service_rate_mu = service_rate_mu

    @classmethod
    def from_crypto_benchmark(cls, bench_result: BenchmarkResult) -> "QueueAnalysis":
        """Derive service rate mu from measured verification throughput."""
        return cls(service_rate_mu=bench_result.throughput_ops_per_sec)

    def analyze_cil_dos(self, attack_rates: List[float]) -> List[QueuePrediction]:
        predictions = []
        for rate in attack_rates:
            queue = MM1Queue(rate, self.service_rate_mu)
            predictions.append(QueuePrediction(
                arrival_rate=rate,
                service_rate=self.service_rate_mu,
                utilization=queue.utilization_rho,
                mean_wait_us=queue.mean_wait_time * 1e6 if queue.utilization_rho < 1 else float('inf'),
                deadline_violation_prob=queue.prob_deadline_violation(3000 / 1e6),
                queue_length=queue.mean_queue_length
            ))
        return predictions

    def find_saturation_point(self, deadline_us: float = 3000) -> float:
        queue = MM1Queue(0, self.service_rate_mu)
        return queue.find_critical_arrival_rate(deadline_us / 1e6, max_violation_prob=0.99)

    def plot_data(self) -> Dict[str, Any]:
        """Return data suitable for plotting."""
        rates = [self.service_rate_mu * r / 100 for r in range(1, 100, 5)]
        preds = self.analyze_cil_dos(rates)
        return {
            "rates": rates,
            "wait_times_us": [p.mean_wait_us for p in preds],
            "violation_probs": [p.deadline_violation_prob for p in preds],
            "queue_lengths": [p.queue_length for p in preds]
        }

    def print_predictions(self, predictions: List[QueuePrediction]):
        print(f"{'Arrival Rate':<15} | {'Utilization':<15} | {'Wait Time (µs)':<15} | {'Violation Prob':<15}")
        print("-" * 65)
        for p in predictions:
            util = f"{p.utilization*100:.1f}%"
            wait = f"{p.mean_wait_us:.1f}" if p.mean_wait_us != float('inf') else "INF"
            prob = f"{p.deadline_violation_prob*100:.2f}%"
            print(f"{p.arrival_rate:<15.1f} | {util:<15} | {wait:<15} | {prob:<15}")
