import socket
import ipaddress
import threading
import time
import struct
import platform
import subprocess
import sys
import re
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parse_ports(port_string):
    ports = set()
    parts = port_string.split(",")
    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            if part.strip():
                ports.add(int(part.strip()))
    return sorted(ports)


class NetworkScanner:
    def __init__(self, targets, ports_tcp=None, ports_udp=None, timeout=1.0,
                 threads=50, delay=0, rate_limit=0, discovery_method='icmp'):
        self.targets = self._expand_targets(targets)
        self.ports_tcp = ports_tcp if ports_tcp else []
        self.ports_udp = ports_udp if ports_udp else []
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.rate_limit = rate_limit
        self.discovery_method = discovery_method

        self.live_hosts = set()
        self.results = {}  # ip -> scan data
        self.os_info = {}  # ip -> os guess
        self._pause_flag = threading.Event()
        self._pause_flag.set()  # initially not paused
        self._stop_flag = threading.Event()

        self.lock = threading.Lock()

    def _expand_targets(self, targets):
        expanded = []
        for target in targets:
            target = target.strip()
            if not target:
                continue
            try:
                if '/' in target:
                    net = ipaddress.ip_network(target, strict=False)
                    expanded.extend([str(ip) for ip in net.hosts()])
                else:
                    # Could be single IP or hostname - resolve
                    try:
                        ips = socket.gethostbyname_ex(target)[2]
                        expanded.extend(ips)
                    except socket.gaierror:
                        # fallback to raw IP if looks valid
                        expanded.append(target)
            except Exception:
                expanded.append(target)
        return list(set(expanded))

    def pause(self):
        self._pause_flag.clear()

    def resume(self):
        self._pause_flag.set()

    def stop(self):
        self._stop_flag.set()

    def _wait_if_paused(self):
        self._pause_flag.wait()

    def is_stopped(self):
        return self._stop_flag.is_set()

    # ICMP Ping to detect if host is alive
    def icmp_ping(self, ip):
        self._wait_if_paused()
        if self.is_stopped():
            return False
        pkt = IP(dst=ip)/ICMP()
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 0:
                return True
            return False
        except Exception:
            return False

    # TCP Ping for hosts where ICMP might be blocked
    def tcp_ping(self, ip, port=80):
        self._wait_if_paused()
        if self.is_stopped():
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def discover_hosts(self, progress_callback=None):
        self.live_hosts = set()
        total = len(self.targets)
        completed = 0

        def worker(ip):
            self._wait_if_paused()
            if self.is_stopped():
                return None
            if self.discovery_method == 'icmp':
                alive = self.icmp_ping(ip)
            else:
                alive = self.tcp_ping(ip)
            return ip if alive else None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(worker, ip): ip for ip in self.targets}
            for future in futures:
                if self.is_stopped():
                    break
                ip = futures[future]
                try:
                    res = future.result()
                    if res:
                        self.live_hosts.add(res)
                except Exception:
                    pass
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        return self.live_hosts

    def scan_host(self, ip, progress_callback=None):
        self._wait_if_paused()
        if self.is_stopped():
            return (ip, {})
        host_result = {'tcp': {}, 'udp': [], 'os': None}
        # TCP scan
        for port in self.ports_tcp:
            if self.is_stopped():
                break
            self._wait_if_paused()
            status, banner = self.tcp_scan_port(ip, port)
            if status == 'open':
                host_result['tcp'][port] = banner
            if progress_callback:
                progress_callback(ip, port)
            if self.delay > 0:
                time.sleep(self.delay)
        # UDP scan (simple)
        for port in self.ports_udp:
            if self.is_stopped():
                break
            self._wait_if_paused()
            status = self.udp_scan_port(ip, port)
            if status == 'open':
                host_result['udp'].append(port)
            if progress_callback:
                progress_callback(ip, port)
            if self.delay > 0:
                time.sleep(self.delay)

        # OS detection
        try:
            host_result['os'] = self.detect_os(ip)
        except Exception:
            host_result['os'] = None

        with self.lock:
            self.results[ip] = host_result
            if host_result['os']:
                self.os_info[ip] = host_result['os']

        return (ip, host_result)

    def tcp_scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = self.banner_grab(ip, port)
                sock.close()
                return ('open', banner)
            sock.close()
            return ('closed', None)
        except Exception:
            return ('closed', None)

    def udp_scan_port(self, ip, port):
        # Simple UDP scan: send empty UDP packet, wait for ICMP port unreachable response or timeout
        try:
            pkt = IP(dst=ip)/UDP(dport=port)
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None:
                # No response usually means open|filtered
                return 'open'
            if resp.haslayer(ICMP):
                icmp_type = int(resp.getlayer(ICMP).type)
                icmp_code = int(resp.getlayer(ICMP).code)
                if icmp_type == 3 and icmp_code == 3:
                    # Port unreachable = closed
                    return 'closed'
                else:
                    return 'open'  # filtered or other
            return 'open'
        except Exception:
            return 'closed'

    def banner_grab(self, ip, port):
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            return banner
        except Exception:
            return ""

    def detect_os(self, ip):
        # Very simple OS fingerprint:
        # 1. TTL heuristic from ping response (using scapy)
        # 2. Banner strings if available

        ttl = self.get_ttl(ip)
        if ttl is None:
            return None

        os_guess = "Unknown"
        if ttl >= 128:
            os_guess = "Windows"
        elif 64 <= ttl < 128:
            os_guess = "Linux/Unix"
        elif ttl < 64:
            os_guess = "Network Device or Unknown"

        # Check banners for common service fingerprints
        banners = []
        for port in self.ports_tcp:
            banner = self.results.get(ip, {}).get('tcp', {}).get(port, "")
            if banner:
                banners.append(banner.lower())

        if any("windows" in b for b in banners):
            os_guess = "Windows"
        elif any("linux" in b or "unix" in b for b in banners):
            os_guess = "Linux/Unix"
        return os_guess

    def get_ttl(self, ip):
        # Send ICMP echo request and get TTL from response
        pkt = IP(dst=ip)/ICMP()
        try:
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None:
                return None
            return resp.ttl
        except Exception:
            return None

    def export_results(self, filename="results.json", file_format="json"):
        try:
            if file_format.lower() == 'json':
                self._export_json(filename)
            elif file_format.lower() == 'csv':
                self._export_csv(filename)
            else:
                raise ValueError("Unsupported export format: " + file_format)
        except Exception as e:
            raise e

    def _export_json(self, filename):
        import json
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)

    def _export_csv(self, filename):
        import csv
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Protocol', 'Port', 'Banner/OS'])
            for ip, data in self.results.items():
                for port, banner in data.get('tcp', {}).items():
                    writer.writerow([ip, 'TCP', port, banner])
                for port in data.get('udp', []):
                    writer.writerow([ip, 'UDP', port, ''])
                if data.get('os'):
                    writer.writerow([ip, 'OS', '', data['os']])
