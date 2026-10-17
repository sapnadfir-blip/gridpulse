.PHONY: help build test reproduce clean

help:
	@echo "GridPulse - Research & Testbed Makefile"
	@echo "  make build      - Compile native C substation binaries (OpenSSL required)"
	@echo "  make test       - Run Python test suite via pytest"
	@echo "  make reproduce  - Validate and print summary of experimental results from results/"
	@echo "  make clean      - Remove build artifacts and temporary files"

build:
	@echo "==> Compiling native C binaries..."
	gcc -O2 -pthread -Wall -o gridpulse/hardware/goose_subscriber gridpulse/hardware/goose_subscriber.c -lssl -lcrypto
	gcc -O2 -Wall -o gridpulse/hardware/goose_attacker gridpulse/hardware/goose_attacker.c
	gcc -O2 -pthread -Wall -o gridpulse/hardware/goose_publisher gridpulse/hardware/goose_publisher.c -lssl -lcrypto
	gcc -O2 -Wall -o gridpulse/hardware/crypto_bench gridpulse/hardware/crypto_bench.c -lssl -lcrypto
	@echo "==> Native binaries successfully compiled in gridpulse/hardware/"

test:
	@echo "==> Running test suite..."
	pytest tests/ -v

reproduce:
	@echo "==> Verifying experimental dataset provenance and benchmarks..."
	@python3 scripts/verify_results.py

clean:
	@echo "==> Cleaning build artifacts..."
	rm -f gridpulse/hardware/goose_subscriber gridpulse/hardware/goose_attacker gridpulse/hardware/goose_publisher gridpulse/hardware/crypto_bench
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
