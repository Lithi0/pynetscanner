# PYNETSCANNER  
**By Lithiokride**

---

## Overview  
**PYNETSCANNER** is a versatile network scanning tool designed to help you discover live hosts, scan TCP/UDP ports, and perform OS fingerprinting with both CLI and GUI modes. Powered by Python and leveraging multithreading for speed, it’s your nova cyber tool for network recon.

---

## Features

- Discover live hosts via **ICMP** or **TCP** probes  
- Scan specified **TCP** and **UDP** ports on discovered hosts  
- Adjustable **timeout** and **delay** settings for scanning  
- High-performance **multithreading** for faster scans  
- Pause, resume, and stop scans mid-process (**GUI only**)  
- Export results in **JSON** or **CSV** formats  
- Basic OS fingerprinting using **TTL analysis** and **banner grabbing**  
- CLI and GUI interfaces for flexible usage  
- Detailed error handling and retry options (**GUI**)  

---

## How to Use

### 1. Run CLI scan

    python -m pynetscanner.cli --mode cli --targets 192.168.1.0/24 --tcp-ports 22,80,443 --udp-ports 53 --threads 100 --discovery icmp

### 2. Run GUI

    python -m pynetscanner.cli --mode gui

---

## How It Works

- **Host Discovery:** Sends ICMP echo requests or TCP probes to identify live hosts  
- **Port Scanning:** Checks specified TCP and UDP ports to find open services  
- **Multithreading:** Concurrent scanning for efficiency  
- **Banner Grabbing & TTL Analysis:** Basic OS fingerprinting techniques  
- **Result Handling:** Stores and exports scan data with detailed host info  
- **Error Handling:** GUI provides advanced dialogs for retry, ignore, or cancel  

---

## Requirements

- Python 3.x  
- [scapy](https://scapy.net/) (for network probing)  
- Standard Python libraries: `threading`, `queue`, `socket`, `tkinter`, `ipaddress`, etc.

---

## Troubleshooting

- **No live hosts found:**  
  - Verify network connectivity and target format  
  - ICMP probes may be blocked—try TCP discovery mode  

- **Permission errors:**  
  - Run as Administrator or with `sudo` for ICMP scans  

- **Slow or hanging scans:**  
  - Adjust `--threads`, `--timeout`, and `--delay` parameters  
  - Large networks/ports will increase scan time  

- **Export issues:**  
  - Use `.json` or `.csv` file extensions  
  - Verify write permissions for export directory  

- **GUI crashes or unresponsive:**  
  - Confirm `tkinter` is installed properly  
  - Test CLI mode to isolate GUI problems  

---

## Additional Info

- Targets support:  
  - Individual IP addresses  
  - CIDR ranges (e.g., `192.168.1.0/24`)  
  - Hostnames  
  - Files with list of targets  

- Pause/resume supported only in GUI mode  
- Exported results include detailed host, port, and OS info  
- Respect timeout/delay to minimize network load or detection risk  

---

## License & Signature

This file and its contents are digitally signed by **Lithiokride**.  
Unauthorized modification or removal of this signature is prohibited.

For verification or licensing inquiries, contact **Lithiokride** directly.

---

## Thank You!  
Thanks for using **PYNETSCANNER!** For questions or feature requests, hit up the author.
