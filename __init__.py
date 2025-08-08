# pynetscanner/__init__.py

"""
PyNetScanner Package
--------------------

A stealthy, versatile network scanner toolkit with CLI and GUI interfaces.

Provides:
- NetworkScanner: core scanning class supporting ICMP/TCP discovery, TCP/UDP port scans, and OS fingerprinting.
- parse_ports: utility to parse port strings (e.g., "22,80,1000-1010") into lists.
- cli_main: CLI entry point function for command-line scanning.
- run_gui: GUI launcher function for graphical scanning interface.

Author: Lithiokride
Version: 1.0.0
"""

from .scanner import NetworkScanner, parse_ports
from .cli import main as cli_main
from .gui import run_gui

__all__ = ['NetworkScanner', 'parse_ports', 'cli_main', 'run_gui']

__version__ = "1.0.0"
__author__ = "Lithiokride"
