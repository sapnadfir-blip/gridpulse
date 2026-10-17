import os
import subprocess
import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

@dataclass
class XDPConfig:
    """Configuration for XDP program."""
    interface: str
    mode: str = "native"
    source_path: str = "xdp_goose_filter.c"
    output_path: str = "xdp_goose_filter.o"


class XDPLoader:
    """Compiles, loads, and manages the XDP BPF program."""

    def __init__(self, config: XDPConfig):
        self.config = config
        self._check_root()

    def _check_root(self):
        if os.geteuid() != 0:
            logger.warning("Root privileges required to manage XDP programs.")

    def compile(self) -> bool:
        """Compile the .c source to .o using clang."""
        try:
            cmd = [
                "clang",
                "-O2",
                "-g",
                "-Wall",
                "-target", "bpf",
                "-c", self.config.source_path,
                "-o", self.config.output_path
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Compiled {self.config.source_path} successfully.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Compilation failed: {e.stderr}")
            return False

    def attach(self) -> bool:
        """Attach XDP program to interface."""
        try:
            cmd = [
                "ip", "link", "set", "dev", self.config.interface,
                f"xdp{self.config.mode}", "obj", self.config.output_path,
                "sec", "xdp"
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Attached XDP to {self.config.interface} in {self.config.mode} mode.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to attach XDP: {e.stderr}")
            return False

    def detach(self) -> bool:
        """Detach XDP program from interface."""
        try:
            cmd = [
                "ip", "link", "set", "dev", self.config.interface,
                f"xdp{self.config.mode}", "off"
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Detached XDP from {self.config.interface}.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to detach XDP: {e.stderr}")
            return False

    def is_attached(self) -> bool:
        """Check if XDP is attached."""
        try:
            cmd = ["ip", "-details", "link", "show", "dev", self.config.interface]
            res = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return "prog/xdp" in res.stdout
        except subprocess.CalledProcessError:
            return False


class MapManager:
    """Manages BPF maps for the XDP program via bpftool."""
    def __init__(self, prog_name: str = "xdp_goose_prog"):
        self.prog_name = prog_name

    def _mac_to_hex(self, mac: str) -> str:
        return " ".join([f"0x{x}" for x in mac.split(":")])

    def add_mac(self, mac_address: str) -> bool:
        """Add MAC to allowlist via bpftool."""
        hex_mac = self._mac_to_hex(mac_address)
        try:
            cmd = f"bpftool map update name mac_allowlist key {hex_mac} value 0 0 0 0 0 0 0 1"
            subprocess.run(cmd.split(), check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def remove_mac(self, mac_address: str) -> bool:
        """Remove MAC from allowlist."""
        hex_mac = self._mac_to_hex(mac_address)
        try:
            cmd = f"bpftool map delete name mac_allowlist key {hex_mac}"
            subprocess.run(cmd.split(), check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def list_macs(self) -> List[str]:
        """List all allowed MACs. Simplified implementation."""
        # For a full implementation, you would parse the JSON output of bpftool map dump
        return []

    def set_rate_limit(self, mac: str, max_pps: int) -> bool:
        """Configure rate limit for a MAC."""
        pass # Placeholder for rate limit config

    def get_seq_state(self, mac: str):
        """Read current sequence tracker state."""
        pass # Placeholder

    def dump_stats(self) -> dict:
        """Read all statistics counters."""
        return {}
