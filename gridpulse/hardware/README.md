# GridPulse Hardware & Process Bus Testbed

This directory contains the production-grade C implementation of the IEC 61850 substation process bus testbed, including the multi-container Docker environment, the Priority Queue Admission Controller (PQAC), and traffic generation utilities.

## Directory Structure
* `goose_subscriber.c`: Decoupled 2-thread GOOSE subscriber with PQAC admission control and FIFO comparison modes.
* `goose_attacker.c`: Raw Ethernet socket CIL-DoS flood generator supporting rate sweeping (1K to 100K+ pps) and MAC spoofing.
* `goose_publisher.c`: IEC 61850 GOOSE publisher implementing the geometric burst retransmission profile (1ms, 2ms, 4ms, ... up to 1000ms).
* `xdp_goose_filter.c`: Line-rate Linux kernel eBPF/XDP filter for wire-speed ingress filtering.
* `crypto_bench.c`: Host-level OpenSSL cryptographic benchmarking utility.
* `docker-compose.yml`: Multi-container Docker environment with an isolated bridge network configured with MTU 9,000 for jumbo frame support.
* `esp32_crypto_bench/`: Arduino sketch for benchmarking crypto verification directly on ESP32 silicon.

---

## Quick Start via Docker Compose

The easiest way to run the testbed is using Docker:

### 1. Build the Container Images
```bash
docker compose build
```

### 2. Run the Protected Subscriber (PQAC Mode)
```bash
docker compose run --rm subscriber --mode priority --workers 1
```

### 3. In a Second Terminal, Launch the Attack
```bash
docker compose run --rm attacker --rate 100000 --duration 10
```

### 4. Run Baseline FIFO (Vulnerable Mode)
```bash
docker compose run --rm subscriber --mode fifo --workers 1
```

---

## Native Compilation (Linux / macOS)

### Prerequisites
* GCC or Clang (`build-essential`)
* OpenSSL development headers (`libssl-dev` or `openssl`)
* Libpcap (`libpcap-dev`)

### Compile Binaries
```bash
# Compile Subscriber
gcc -O2 -pthread -Wall -o goose_subscriber goose_subscriber.c -lssl -lcrypto

# Compile Attacker
gcc -O2 -Wall -o goose_attacker goose_attacker.c

# Compile Publisher
gcc -O2 -pthread -Wall -o goose_publisher goose_publisher.c -lssl -lcrypto
```

---

## Command-Line Usage

### Subscriber (`goose_subscriber`)
```text
Usage: ./goose_subscriber [options]
Options:
  -i, --interface <iface>     Network interface (default: eth0)
  -m, --mode <fifo|priority>  Queue admission mode (default: fifo)
  -w, --workers <N>           Number of verification worker threads (default: 1)
  -q, --queue-size <N>        Queue capacity (default: 4096)
  --t-normal <N>              Rate threshold for NORMAL queue (default: 50)
  --t-burst <N>               Rate threshold for BURST admission (default: 500)
  --t-flood <N>               Rate threshold for FLOOD dropping (default: 1000)
  --no-mac                    [Ablation] Disable MAC allowlist learning
  --no-rate                   [Ablation] Disable rate tracking
  --no-priority               [Ablation] Single FIFO queue with drop logic
```

### Attacker (`goose_attacker`)
```text
Usage: ./goose_attacker [options]
Options:
  -i, --interface <iface>     Target interface (default: eth0)
  -r, --rate <pps>            Flood injection rate in packets/sec (default: 10000)
  -d, --duration <sec>        Attack duration in seconds (default: 10)
  -M, --spoof-mac <MAC>       Spoof source MAC address (XX:XX:XX:XX:XX:XX)
```
