import argparse
import sys
import threading
import time
from pynetscanner.scanner import NetworkScanner, parse_ports
from pynetscanner.gui import run_gui

def main():
    parser = argparse.ArgumentParser(description="PyNetScanner - Stealthy Network Scanner")
    parser.add_argument('--mode', choices=['cli', 'gui'], default='cli', help='Run mode (cli/gui)')
    parser.add_argument('--targets', type=str, help='Targets (comma, CIDR, file)')
    parser.add_argument('--tcp-ports', type=str, default='22,80,443', help='TCP ports to scan')
    parser.add_argument('--udp-ports', type=str, default='', help='UDP ports to scan')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout per probe')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--delay', type=float, default=0, help='Delay between probes')
    parser.add_argument('--rate', type=float, default=0, help='Rate limit packets/sec (0=unlimited)')
    parser.add_argument('--discovery', choices=['icmp', 'tcp'], default='icmp', help='Host discovery method')
    parser.add_argument('--export', type=str, default='results.json', help='Export file name')
    parser.add_argument('--export-format', choices=['json', 'csv'], default='json', help='Export file format')
    parser.add_argument('--pause', action='store_true', help='Pause after discovery and before port scan')
    args = parser.parse_args()

    if args.mode == 'gui':
        run_gui()
        return

    if not args.targets:
        print("Error: --targets argument is required in CLI mode")
        sys.exit(1)

    # Parse targets (split if multiple)
    targets = []
    import os
    if os.path.isfile(args.targets):
        with open(args.targets, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = args.targets.split()

    tcp_ports = parse_ports(args.tcp_ports) if args.tcp_ports else []
    udp_ports = parse_ports(args.udp_ports) if args.udp_ports else []

    scanner = NetworkScanner(
        targets=targets,
        ports_tcp=tcp_ports,
        ports_udp=udp_ports,
        timeout=args.timeout,
        threads=args.threads,
        delay=args.delay,
        rate_limit=args.rate,
        discovery_method=args.discovery
    )

    print("[*] Starting host discovery...")
    live_hosts = scanner.discover_hosts(progress_callback=lambda done, total: print(f"Discovery: {done}/{total}", end='\r'))

    if not live_hosts:
        print("[!] No live hosts found. Exiting.")
        sys.exit(0)

    print(f"\n[*] Host discovery complete. {len(live_hosts)} hosts live.")

    if args.pause:
        input("Paused before port scan. Press Enter to continue...")

    print("[*] Starting port scan...")
    completed_hosts = 0
    total_hosts = len(live_hosts)

    def progress(ip, port):
        nonlocal completed_hosts
        print(f"Scanning {ip} port {port}    ", end='\r')

    for ip in live_hosts:
        if scanner.is_stopped():
            print("\n[!] Scan stopped.")
            break
        scanner._wait_if_paused()
        ip, result = scanner.scan_host(ip, progress_callback=progress)
        completed_hosts += 1
        print(f"Scanned {completed_hosts}/{total_hosts} hosts      ", end='\r')

    print("\n[*] Scan complete. Exporting results...")
    scanner.export_results(args.export, args.export_format)
    print(f"[*] Results saved to {args.export}")

if __name__ == "__main__":
    main()
