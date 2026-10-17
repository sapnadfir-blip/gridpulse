.PHONY: xdp-build xdp-attach xdp-detach test bench clean install

xdp-build:
	@echo "Building XDP program..."
	clang -O2 -g -Wall -target bpf -c gridpulse/defense/xdp/filter.c -o gridpulse/defense/xdp/filter.o

xdp-attach:
	@echo "Attaching XDP program to interface (requires IFACE environment variable)..."
	@if [ -z "$(IFACE)" ]; then echo "IFACE is not set. Usage: make xdp-attach IFACE=eth0"; exit 1; fi
	sudo ip link set dev $(IFACE) xdp obj gridpulse/defense/xdp/filter.o sec xdp

xdp-detach:
	@echo "Detaching XDP program from interface..."
	@if [ -z "$(IFACE)" ]; then echo "IFACE is not set. Usage: make xdp-detach IFACE=eth0"; exit 1; fi
	sudo ip link set dev $(IFACE) xdp off

test:
	pytest tests/

bench:
	python3 -m gridpulse.bench.benchmark

clean:
	rm -rf .pytest_cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.o" -delete

install:
	pip install -e .[test]
