#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, List, Tuple
import threading
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


@dataclass
class CertAnalysis:
    host: str
    port: int
    success: bool
    error: Optional[str]
    algo_family: Optional[str]
    key_size: Optional[int]
    quantum_vulnerable: Optional[bool]
    severity: Optional[str]
    comment: Optional[str]


def fetch_server_certificate(host: str, port: int, timeout: float = 3.0) -> bytes:
    """Fetch the DER-encoded leaf certificate from a TLS server."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    conn = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(conn, server_hostname=host)
    der_cert = sock.getpeercert(binary_form=True)
    sock.close()
    return der_cert


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open on the host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def analyze_certificate(host: str, port: int) -> CertAnalysis:
    try:
        der_cert = fetch_server_certificate(host, port)
    except Exception as e:
        return CertAnalysis(
            host=host, port=port, success=False, error=str(e),
            algo_family=None, key_size=None, quantum_vulnerable=None,
            severity=None, comment=None,
        )

    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        public_key = cert.public_key()

        algo_family = None
        key_size = None
        quantum_vulnerable = None
        severity = None
        comment = None

        if isinstance(public_key, rsa.RSAPublicKey):
            algo_family = "RSA"
            key_size = public_key.key_size
            quantum_vulnerable = True

            if key_size < 2048:
                severity = "High"
                comment = f"RSA-{key_size} is weak even against classical attacks and fully exposed to future quantum (Shor's algorithm)."
            elif key_size < 4096:
                severity = "High"
                comment = f"RSA-{key_size} is considered strong classically today but fails rapidly once scalable quantum factoring is available."
            else:
                severity = "Medium"
                comment = f"RSA-{key_size} marginally improves classical resistance, but remains fundamentally breakable by Shor's algorithm."

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algo_family = "EC"
            key_size = public_key.curve.key_size
            quantum_vulnerable = True
            severity = "High"
            comment = f"Elliptic Curve cryptography (approx. {key_size}-bit strength) is directly broken by quantum discrete log attacks."

        else:
            algo_family = type(public_key).__name__
            quantum_vulnerable = None
            severity = "Informational"
            comment = "Non-RSA/EC key detected. Manual review required to determine quantum posture and conformance with NIST PQC guidance."

        return CertAnalysis(
            host=host, port=port, success=True, error=None,
            algo_family=algo_family, key_size=key_size,
            quantum_vulnerable=quantum_vulnerable, severity=severity,
            comment=comment,
        )

    except Exception as e:
        return CertAnalysis(
            host=host, port=port, success=False,
            error=f"Certificate parse error: {e}",
            algo_family=None, key_size=None, quantum_vulnerable=None,
            severity=None, comment=None,
        )


def parse_ip_range(ip_input: str) -> List[str]:
    """Parse IP range input and return list of IP addresses."""
    try:
        # Handle CIDR notation (e.g., 192.168.1.0/24)
        if '/' in ip_input:
            network = ipaddress.ip_network(ip_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        
        # Handle IP range (e.g., 192.168.1.1-192.168.1.10)
        elif '-' in ip_input:
            start_ip, end_ip = ip_input.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            ips = []
            current = start
            while current <= end:
                ips.append(str(current))
                current = ipaddress.ip_address(int(current) + 1)
            return ips
        
        # Single IP
        else:
            ipaddress.ip_address(ip_input.strip())
            return [ip_input.strip()]
    except Exception as e:
        raise ValueError(f"Invalid IP format: {e}")


def parse_port_range(port_input: str) -> List[int]:
    """Parse port range input."""
    ports = []
    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def format_report(results: List[CertAnalysis]) -> str:
    """Generate a formatted report string."""
    output = "=" * 70 + "\n"
    output += "QUANTUM READINESS NETWORK SCAN – TLS CERTIFICATES\n"
    output += "=" * 70 + "\n\n"

    high_count = 0
    medium_count = 0
    info_count = 0
    error_count = 0
    total_vulnerable = 0

    for r in results:
        output += f"Target: {r.host}:{r.port}\n"
        if not r.success:
            output += "  Status      : ERROR\n"
            output += f"  Detail      : {r.error}\n\n"
            error_count += 1
            continue

        output += "  Status      : OK\n"
        output += f"  Key family  : {r.algo_family}\n"
        if r.key_size:
            output += f"  Key size    : {r.key_size} bits\n"
        if r.quantum_vulnerable is True:
            output += "  Quantum risk: VULNERABLE (pre-quantum algorithm)\n"
            total_vulnerable += 1
        elif r.quantum_vulnerable is False:
            output += "  Quantum risk: Not vulnerable (as currently understood)\n"
        else:
            output += "  Quantum risk: UNKNOWN (manual review required)\n"

        if r.severity:
            output += f"  Severity    : {r.severity}\n"
            if r.severity == "High":
                high_count += 1
            elif r.severity == "Medium":
                medium_count += 1
            else:
                info_count += 1

        if r.comment:
            output += f"  Commentary  : {r.comment}\n"

        output += "\n"

    # Summary section
    output += "=" * 70 + "\n"
    output += "SUMMARY\n"
    output += "=" * 70 + "\n"
    total = len(results)

    output += f"Total targets assessed     : {total}\n"
    output += f" - High risk (quantum)     : {high_count}\n"
    output += f" - Medium risk (quantum)   : {medium_count}\n"
    output += f" - Informational/Other     : {info_count}\n"
    output += f" - Errors / unreachable    : {error_count}\n\n"

    if total_vulnerable > 0:
        output += "QUANTUM RISK SUMMARY\n"
        output += "--------------------\n"
        output += (
            "Finding: One or more endpoints rely on RSA/ECC, which are "
            "susceptible to Shor-style quantum attacks once a fault-tolerant "
            "quantum computer is available.\n\n"
        )
        output += (
            "Impact: Confidential data protected by these keys may be subject "
            "to 'harvest now, decrypt later' risk – adversaries can record "
            "encrypted traffic today and decrypt it in the future.\n\n"
        )
        output += "Recommendations:\n"
        output += "  1. Establish a crypto inventory and crypto-agility strategy.\n"
        output += "  2. Track NIST PQC standardisation (e.g., Kyber (ML-KEM), Dilithium (ML-DSA)).\n"
        output += "  3. Plan migration away from RSA/ECC for long-lived data.\n"
        output += "  4. Align remediation with your internal risk framework and regulations.\n"
    else:
        output += "QUANTUM RISK SUMMARY\n"
        output += "--------------------\n"
        output += (
            "No clearly quantum-vulnerable RSA/ECC keys detected in the "
            "assessed certificates. This does NOT guarantee overall quantum safety.\n"
        )

    return output


# --- GUI Implementation ---
class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PQC Network Scanner")
        self.root.geometry("950x750")
        self.root.configure(bg='#f0f0f0')
        self.scan_cancelled = False

        # Header
        header_frame = tk.Frame(root, bg='#00796B', height=70)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)

        header_label = tk.Label(header_frame, text="PQC Network Scanner", 
                                font=("Arial", 20, "bold"), fg="white", bg='#00796B')
        header_label.pack(pady=10)

        subtitle = tk.Label(header_frame, text="Internal Network TLS Certificate Quantum Vulnerability Assessment", 
                           font=("Arial", 10), fg="#E0F2F1", bg='#00796B')
        subtitle.pack()

        # Input frame
        input_frame = tk.LabelFrame(root, text="Network Scan Configuration", 
                                   font=("Arial", 11, "bold"),
                                   bg='#f0f0f0', padx=15, pady=15)
        input_frame.pack(padx=20, pady=10, fill='x')

        # IP Range input
        tk.Label(input_frame, text="IP Range (CIDR, range, or single IP):", 
                font=("Arial", 10), bg='#f0f0f0', anchor='w').grid(row=0, column=0, sticky='w', pady=5)
        
        self.ip_entry = tk.Entry(input_frame, width=40, font=("Arial", 10))
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky='w')

        tk.Label(input_frame, text="Examples: 192.168.1.0/24, 10.0.0.1-10.0.0.50, 172.16.0.10", 
                font=("Arial", 8), bg='#f0f0f0', fg='#666666').grid(row=1, column=1, sticky='w', padx=10)

        # Port input
        tk.Label(input_frame, text="Ports (comma-separated or range):", 
                font=("Arial", 10), bg='#f0f0f0', anchor='w').grid(row=2, column=0, sticky='w', pady=5)
        
        self.port_entry = tk.Entry(input_frame, width=40, font=("Arial", 10))
        self.port_entry.insert(0, "443,8443")
        self.port_entry.grid(row=2, column=1, padx=10, pady=5, sticky='w')

        tk.Label(input_frame, text="Examples: 443,8443,10443 or 443-445", 
                font=("Arial", 8), bg='#f0f0f0', fg='#666666').grid(row=3, column=1, sticky='w', padx=10)

        # Options
        self.check_open_var = tk.BooleanVar(value=True)
        tk.Checkbutton(input_frame, text="Only scan open ports (faster)", 
                      variable=self.check_open_var, bg='#f0f0f0',
                      font=("Arial", 9)).grid(row=4, column=1, sticky='w', padx=10, pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(input_frame, mode='determinate', length=400)
        self.progress.grid(row=5, column=0, columnspan=2, pady=10, padx=10)

        # Buttons frame
        button_frame = tk.Frame(root, bg='#f0f0f0')
        button_frame.pack(pady=10)

        self.btn_scan = tk.Button(button_frame, text='Start Network Scan', 
                                 command=self.run_scan_threaded,
                                 bg='#4CAF50', fg='white', 
                                 font=("Arial", 11, "bold"), 
                                 padx=25, pady=10, relief=tk.RAISED, bd=3)
        self.btn_scan.grid(row=0, column=0, padx=10)

        self.btn_cancel = tk.Button(button_frame, text='Cancel Scan', 
                                    command=self.cancel_scan, state='disabled',
                                    bg='#FF5722', fg='white', 
                                    font=("Arial", 11, "bold"), 
                                    padx=25, pady=10, relief=tk.RAISED, bd=3)
        self.btn_cancel.grid(row=0, column=1, padx=10)

        tk.Button(button_frame, text='Clear Results', command=self.clear_results,
                 bg='#FF9800', fg='white', font=("Arial", 11, "bold"), 
                 padx=25, pady=10, relief=tk.RAISED, bd=3).grid(row=0, column=2, padx=10)

        tk.Button(button_frame, text='Save Report', command=self.save_report,
                 bg='#2196F3', fg='white', font=("Arial", 11, "bold"), 
                 padx=25, pady=10, relief=tk.RAISED, bd=3).grid(row=0, column=3, padx=10)

        tk.Button(button_frame, text='Exit', command=root.quit,
                 bg='#F44336', fg='white', font=("Arial", 11, "bold"), 
                 padx=25, pady=10, relief=tk.RAISED, bd=3).grid(row=0, column=4, padx=10)

        # Results frame
        results_frame = tk.LabelFrame(root, text="Scan Results", 
                                     font=("Arial", 11, "bold"),
                                     bg='#f0f0f0', padx=10, pady=10)
        results_frame.pack(padx=20, pady=5, fill='both', expand=True)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap='word',
                                                     font=("Courier New", 9),
                                                     bg='#ffffff', height=20)
        self.results_text.pack(fill='both', expand=True)

        # Status bar
        self.status_label = tk.Label(root, text="Ready to scan network", 
                                    font=("Arial", 9), bg='#f0f0f0', 
                                    fg='#666666', anchor='w')
        self.status_label.pack(side='bottom', fill='x', padx=20, pady=5)

    def clear_results(self):
        """Clear the results text box."""
        self.results_text.delete('1.0', tk.END)
        self.status_label.config(text="Results cleared. Ready to scan.", fg='#666666')
        self.progress['value'] = 0

    def cancel_scan(self):
        """Cancel the ongoing scan."""
        self.scan_cancelled = True
        self.status_label.config(text="Cancelling scan...", fg='#FF9800')

    def save_report(self):
        """Save the scan results to a file."""
        report_content = self.results_text.get('1.0', tk.END).strip()
        
        if not report_content:
            messagebox.showwarning("No Results", "No scan results to save. Please run a scan first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Network Scan Report",
            initialfile="network_quantum_scan_report.txt"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                messagebox.showinfo("Success", f"Report saved successfully to:\n{file_path}")
                self.status_label.config(text=f"Report saved to {file_path}", fg='#4CAF50')
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save report:\n{e}")
                self.status_label.config(text="Failed to save report.", fg='#F44336')

    def run_scan_threaded(self):
        """Run scan in a separate thread to avoid blocking the GUI."""
        self.scan_cancelled = False
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()

    def run_scan(self):
        """Execute the network scan and display results."""
        try:
            # Parse inputs
            ip_input = self.ip_entry.get().strip()
            port_input = self.port_entry.get().strip()
            
            if not ip_input or not port_input:
                messagebox.showwarning("Missing Input", "Please enter both IP range and ports.")
                return

            # Parse IP addresses and ports
            try:
                ips = parse_ip_range(ip_input)
                ports = parse_port_range(port_input)
            except ValueError as e:
                messagebox.showerror("Input Error", str(e))
                return

            total_targets = len(ips) * len(ports)
            
            if total_targets > 1000:
                response = messagebox.askyesno("Large Scan", 
                    f"This will scan {total_targets} targets. This may take a while. Continue?")
                if not response:
                    return

            # Update UI
            self.btn_scan.config(state='disabled')
            self.btn_cancel.config(state='normal')
            self.status_label.config(text=f"Scanning {len(ips)} IPs on {len(ports)} port(s)...", fg='#FF9800')
            self.progress['maximum'] = total_targets
            self.progress['value'] = 0
            self.root.update()

            # Clear previous results
            self.results_text.delete('1.0', tk.END)

            # Run scan
            results = []
            scanned = 0
            check_open = self.check_open_var.get()

            for ip in ips:
                if self.scan_cancelled:
                    break
                    
                for port in ports:
                    if self.scan_cancelled:
                        break
                    
                    scanned += 1
                    self.progress['value'] = scanned
                    self.status_label.config(text=f"Scanning {ip}:{port} ({scanned}/{total_targets})...", fg='#FF9800')
                    self.root.update()
                    
                    # Check if port is open first (if enabled)
                    if check_open:
                        if not is_port_open(ip, port):
                            continue
                    
                    # Analyze certificate
                    result = analyze_certificate(ip, port)
                    if result.success or result.error != 'timed out':  # Include meaningful errors
                        results.append(result)

            if self.scan_cancelled:
                self.results_text.insert('1.0', "=== SCAN CANCELLED ===\n\n")
                self.status_label.config(text=f"Scan cancelled. {len(results)} certificates analyzed.", fg='#FF9800')
            else:
                # Format and display results
                report = format_report(results)
                self.results_text.insert('1.0', report)

                # Update status
                vulnerable_count = sum(1 for r in results if r.quantum_vulnerable)
                self.status_label.config(
                    text=f"Scan complete. {len(results)} certificates found, {vulnerable_count} quantum-vulnerable.",
                    fg='#F44336' if vulnerable_count > 0 else '#4CAF50'
                )

        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{e}")
            self.status_label.config(text="Scan failed. See error message.", fg='#F44336')
        
        finally:
            self.btn_scan.config(state='normal')
            self.btn_cancel.config(state='disabled')
            self.root.update()


def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
