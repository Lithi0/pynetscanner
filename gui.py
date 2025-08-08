import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import traceback
from pynetscanner.scanner import NetworkScanner, parse_ports
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import os

class AdvancedErrorDialog(tk.Toplevel):
    def __init__(self, parent, title, error_msg, traceback_str):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()

        label = ttk.Label(self, text=error_msg, foreground="red")
        label.pack(pady=10)

        self.text = tk.Text(self, height=15)
        self.text.pack(fill=tk.BOTH, expand=True, padx=10)
        self.text.insert(tk.END, traceback_str)
        self.text.config(state=tk.DISABLED)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)

        self.retry = False
        ttk.Button(btn_frame, text="Retry", command=self.on_retry).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Ignore", command=self.on_ignore).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT, padx=10)

        self.result = None

    def on_retry(self):
        self.result = 'retry'
        self.destroy()

    def on_ignore(self):
        self.result = 'ignore'
        self.destroy()

    def on_cancel(self):
        self.result = 'cancel'
        self.destroy()


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyNetScanner - Stealthy Network Scanner GUI")
        self.geometry("850x650")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.queue = queue.Queue()
        self.scanner_thread = None
        self.scanner = None
        self.running = False
        self.paused = False

        self.create_widgets()
        self.after(100, self.process_queue)

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(frame, text="Targets (IP, CIDR, or file):").grid(row=0, column=0, sticky=tk.W)
        self.targets_var = tk.StringVar()
        self.targets_entry = ttk.Entry(frame, textvariable=self.targets_var, width=60)
        self.targets_entry.grid(row=0, column=1, sticky=tk.W)
        ttk.Button(frame, text="Load from File", command=self.load_file).grid(row=0, column=2, sticky=tk.W)

        ttk.Label(frame, text="TCP Ports (e.g. 22,80,1000-1010):").grid(row=1, column=0, sticky=tk.W)
        self.tcp_ports_var = tk.StringVar(value="22,80,443")
        self.tcp_ports_entry = ttk.Entry(frame, textvariable=self.tcp_ports_var, width=60)
        self.tcp_ports_entry.grid(row=1, column=1, sticky=tk.W)

        ttk.Label(frame, text="UDP Ports (optional):").grid(row=2, column=0, sticky=tk.W)
        self.udp_ports_var = tk.StringVar()
        self.udp_ports_entry = ttk.Entry(frame, textvariable=self.udp_ports_var, width=60)
        self.udp_ports_entry.grid(row=2, column=1, sticky=tk.W)

        ttk.Label(frame, text="Discovery Method:").grid(row=3, column=0, sticky=tk.W)
        self.discovery_var = tk.StringVar(value='icmp')
        ttk.Combobox(frame, textvariable=self.discovery_var, values=['icmp', 'tcp'], width=58).grid(row=3, column=1, sticky=tk.W)

        ttk.Label(frame, text="Timeout (seconds):").grid(row=4, column=0, sticky=tk.W)
        self.timeout_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(frame, from_=0.1, to=10, increment=0.1, textvariable=self.timeout_var, width=10).grid(row=4, column=1, sticky=tk.W)

        ttk.Label(frame, text="Threads:").grid(row=5, column=0, sticky=tk.W)
        self.threads_var = tk.IntVar(value=50)
        ttk.Spinbox(frame, from_=1, to=200, increment=1, textvariable=self.threads_var, width=10).grid(row=5, column=1, sticky=tk.W)

        ttk.Label(frame, text="Delay between probes (seconds):").grid(row=6, column=0, sticky=tk.W)
        self.delay_var = tk.DoubleVar(value=0)
        ttk.Spinbox(frame, from_=0, to=5, increment=0.1, textvariable=self.delay_var, width=10).grid(row=6, column=1, sticky=tk.W)

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=7, column=0, columnspan=3, pady=15)

        self.start_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.pause_btn = ttk.Button(btn_frame, text="Pause Scan", command=self.pause_resume_scan, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.export_btn = ttk.Button(btn_frame, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)

        # Progress text
        self.progress_text = tk.Text(self, height=20, state=tk.DISABLED)
        self.progress_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def load_file(self):
        filename = filedialog.askopenfilename(title="Select Targets File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]
            self.targets_var.set(" ".join(lines))

    def log(self, msg):
        self.progress_text.config(state=tk.NORMAL)
        self.progress_text.insert(tk.END, msg + "\n")
        self.progress_text.see(tk.END)
        self.progress_text.config(state=tk.DISABLED)

    def start_scan(self):
        if self.running:
            messagebox.showinfo("Info", "Scan already running")
            return

        targets = self.targets_var.get().strip()
        if not targets:
            messagebox.showerror("Error", "Please specify targets")
            return

        tcp_ports = self.tcp_ports_var.get().strip()
        udp_ports = self.udp_ports_var.get().strip()
        try:
            tcp_ports_list = parse_ports(tcp_ports) if tcp_ports else []
            udp_ports_list = parse_ports(udp_ports) if udp_ports else []
        except Exception as e:
            messagebox.showerror("Error", f"Invalid port format: {e}")
            return

        discovery = self.discovery_var.get()
        timeout = self.timeout_var.get()
        threads = self.threads_var.get()
        delay = self.delay_var.get()

        # Parse targets string into list
        target_list = targets.split()

        self.scanner = NetworkScanner(
            targets=target_list,
            ports_tcp=tcp_ports_list,
            ports_udp=udp_ports_list,
            timeout=timeout,
            threads=threads,
            delay=delay,
            discovery_method=discovery
        )

        self.running = True
        self.paused = False
        self.pause_btn.config(state=tk.NORMAL, text="Pause Scan")
        self.stop_btn.config(state=tk.NORMAL)
        self.start_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)

        self.progress_text.config(state=tk.NORMAL)
        self.progress_text.delete(1.0, tk.END)
        self.progress_text.config(state=tk.DISABLED)

        self.scanner_thread = threading.Thread(target=self.run_scan)
        self.scanner_thread.start()

    def run_scan(self):
        try:
            self.log("[*] Starting host discovery...")
            live_hosts = set()

            def discovery_progress(done, total):
                self.queue.put(('log', f"Discovery: {done}/{total}"))

            live_hosts = self.scanner.discover_hosts(progress_callback=discovery_progress)
            if not live_hosts:
                self.queue.put(('log', "[!] No live hosts found. Scan stopped."))
                self.queue.put(('scan_complete', None))
                return

            self.queue.put(('log', f"[*] Host discovery complete. {len(live_hosts)} hosts live."))

            # Port scanning
            total_hosts = len(live_hosts)
            completed_hosts = 0

            def port_scan_progress(ip, port):
                self.queue.put(('log', f"Scanning {ip} port {port}"))

            for ip in live_hosts:
                if self.scanner.is_stopped():
                    self.queue.put(('log', "[!] Scan stopped by user."))
                    break
                self.scanner._wait_if_paused()
                self.scanner.scan_host(ip, progress_callback=port_scan_progress)
                completed_hosts += 1
                self.queue.put(('progress', f"Scanned {completed_hosts}/{total_hosts} hosts"))

            self.queue.put(('log', "[*] Scan complete. You can export results now."))
            self.queue.put(('scan_complete', None))
        except Exception as e:
            tb = traceback.format_exc()
            self.queue.put(('error', (str(e), tb)))

    def process_queue(self):
        try:
            while True:
                try:
                    item = self.queue.get_nowait()
                except queue.Empty:
                    break
                msg_type = item[0]

                if msg_type == 'log':
                    self.log(item[1])

                elif msg_type == 'progress':
                    # Could add GUI progress bar update here
                    pass

                elif msg_type == 'scan_complete':
                    self.running = False
                    self.pause_btn.config(state=tk.DISABLED)
                    self.stop_btn.config(state=tk.DISABLED)
                    self.start_btn.config(state=tk.NORMAL)
                    self.export_btn.config(state=tk.NORMAL)

                elif msg_type == 'error':
                    err_msg, tb = item[1]
                    dlg = AdvancedErrorDialog(self, "Error occurred", err_msg, tb)
                    self.wait_window(dlg)
                    if dlg.result == 'retry':
                        self.start_scan()
                    elif dlg.result == 'ignore':
                        self.running = False
                        self.pause_btn.config(state=tk.DISABLED)
                        self.stop_btn.config(state=tk.DISABLED)
                        self.start_btn.config(state=tk.NORMAL)
                        self.export_btn.config(state=tk.DISABLED)
                    elif dlg.result == 'cancel':
                        self.stop_scan()

        finally:
            self.after(100, self.process_queue)

    def pause_resume_scan(self):
        if not self.running:
            return
        if self.paused:
            self.scanner.resume()
            self.paused = False
            self.pause_btn.config(text="Pause Scan")
            self.log("[*] Resuming scan...")
        else:
            self.scanner.pause()
            self.paused = True
            self.pause_btn.config(text="Resume Scan")
            self.log("[*] Scan paused...")

    def stop_scan(self):
        if not self.running:
            return
        if messagebox.askyesno("Confirm Stop", "Are you sure you want to stop the scan?"):
            self.scanner.stop()
            self.running = False
            self.paused = False
            self.pause_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.DISABLED)
            self.start_btn.config(state=tk.NORMAL)
            self.export_btn.config(state=tk.DISABLED)
            self.log("[*] Scan stopped by user.")

    def export_results(self):
        if not self.scanner or not self.scanner.results:
            messagebox.showinfo("Info", "No results to export")
            return

        filetypes = [('JSON files', '*.json'), ('CSV files', '*.csv'), ('All files', '*.*')]
        filename = filedialog.asksaveasfilename(title="Export Results", defaultextension=".json", filetypes=filetypes)
        if not filename:
            return

        fmt = 'json'
        if filename.lower().endswith('.csv'):
            fmt = 'csv'

        try:
            self.scanner.export_results(filename, fmt)
            messagebox.showinfo("Export Successful", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {e}")

    def on_close(self):
        if self.running:
            if not messagebox.askyesno("Quit", "A scan is running. Do you want to quit?"):
                return
            self.scanner.stop()
        self.destroy()


def run_gui():
    app = ScannerGUI()
    app.mainloop()
