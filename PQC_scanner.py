#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, List, Tuple
import threading

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


def fetch_server_certificate(host: str, port: int, timeout: float = 5.0) -> bytes:
    """Fetch the DER-encoded leaf certificate from a TLS server."""
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(conn, server_hostname=host)
    der_cert = sock.getpeercert(binary_form=True)
    sock.close()
    return der_cert


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
                comment = (
                    f"RSA-{key_size} is weak even against classical attacks and "
                    f"fully exposed to future quantum (Shor's algorithm)."
                )
            elif key_size < 4096:
                severity = "High"
                comment = (
                    f"RSA-{key_size} is considered strong classically today but "
                    f"fails rapidly once scalable quantum factoring is available."
                )
            else:
                severity = "Medium"
                comment = (
                    f"RSA-{key_size} marginally improves classical resistance, "
                    f"but remains fundamentally breakable by Shor's algorithm."
                )

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algo_family = "EC"
            key_size = public_key.curve.key_size
            quantum_vulnerable = True
            severity = "High"
            comment = (
                f"Elliptic Curve cryptography (approx. {key_size}-bit strength) "
                f"is directly broken by quantum discrete log attacks."
            )

        else:
            algo_family = type(public_key).__name__
            quantum_vulnerable = None
            severity = "Informational"
            comment = (
                "Non-RSA/EC key detected. Manual review required to determine "
                "quantum posture and conformance with NIST PQC guidance."
            )

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


def parse_target(target: str) -> Tuple[str, int]:
    """Accepts 'host' or 'host:port', defaults to 443 if port is omitted."""
    target = target.strip()
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        return host.strip(), int(port_str)
    return target, 443


def run_scan(targets: List[str]) -> List[CertAnalysis]:
    results: List[CertAnalysis] = []
    for t in targets:
        if t.strip():  # Skip empty lines
            host, port = parse_target(t)
            result = analyze_certificate(host, port)
            results.append(result)
    return results


def format_report(results: List[CertAnalysis]) -> str:
    """Generate a formatted report string."""
    output = "=" * 70 + "\n"
    output += "QUANTUM READINESS SCAN – TLS PUBLIC ENDPOINTS\n"
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
        output += "  4. Align remediation with your internal risk framework "
        output += "and any relevant regulations/standards.\n"
    else:
        output += "QUANTUM RISK SUMMARY\n"
        output += "--------------------\n"
        output += (
            "No clearly quantum-vulnerable RSA/ECC keys detected in the "
            "assessed certificates. This does NOT guarantee overall "
            "quantum safety; internal systems, VPNs and data-at-rest "
            "should also be reviewed.\n"
        )

    return output


# --- GUI Implementation ---
class QuantumScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Quantum Readiness Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')

        # Header
        header_frame = tk.Frame(root, bg='#03A9F4', height=70)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)

        header_label = tk.Label(header_frame, text="Quantum Readiness Scanner", 
                                font=("Arial", 20, "bold"), fg="white", bg='#03A9F4')
        header_label.pack(pady=10)

        subtitle = tk.Label(header_frame, text="TLS Certificate Quantum Vulnerability Assessment", 
                           font=("Arial", 10), fg="#E3F2FD", bg='#03A9F4')
        subtitle.pack()

        # Input frame
        input_frame = tk.LabelFrame(root, text="Target Configuration", 
                                   font=("Arial", 11, "bold"),
                                   bg='#f0f0f0', padx=15, pady=15)
        input_frame.pack(padx=20, pady=10, fill='x')

        tk.Label(input_frame, text="Enter targets (one per line, format: host or host:port e.g github.com or example.com:8443):", 
                font=("Arial", 10), bg='#f0f0f0', anchor='w').pack(fill='x', pady=(0, 5))

        # Targets text box
        self.targets_text = tk.Text(input_frame, height=6, width=80, 
                                   font=("Courier New", 10), wrap='word')
        self.targets_text.pack(fill='x', pady=5)
        

        # Buttons frame
        button_frame = tk.Frame(root, bg='#f0f0f0')
        button_frame.pack(pady=10)

        self.btn_scan = tk.Button(button_frame, text='Scan Targets', 
                                 command=self.run_scan_threaded,
                                 bg='#4CAF50', fg='white', 
                                 font=("Arial", 11, "bold"), 
                                 padx=25, pady=10, relief=tk.RAISED, bd=3)
        self.btn_scan.grid(row=0, column=0, padx=10)

        tk.Button(button_frame, text='Clear Results', command=self.clear_results,
                 bg='#FF9800', fg='white', font=("Arial", 11, "bold"), 
                 padx=25, pady=10, relief=tk.RAISED, bd=3).grid(row=0, column=1, padx=10)

        tk.Button(button_frame, text='Save Report', command=self.save_report,
                 bg='#2196F3', fg='white', font=("Arial", 11, "bold"), 
                 padx=25, pady=10, relief=tk.RAISED, bd=3).grid(row=0, column=2, padx=10)

        tk.Button(button_frame, text='Exit', command=root.quit,
                 bg='#F44336', fg='white', font=("Arial", 11, "bold"), 
                 padx=25, pady=10, relief=tk.RAISED, bd=3).grid(row=0, column=3, padx=10)

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
        self.status_label = tk.Label(root, text="Ready to scan", 
                                    font=("Arial", 9), bg='#f0f0f0', 
                                    fg='#666666', anchor='w')
        self.status_label.pack(side='bottom', fill='x', padx=20, pady=5)

    def clear_results(self):
        """Clear the results text box."""
        self.results_text.delete('1.0', tk.END)
        self.status_label.config(text="Results cleared. Ready to scan.", fg='#666666')

    def save_report(self):
        """Save the scan results to a file."""
        report_content = self.results_text.get('1.0', tk.END).strip()
        
        if not report_content:
            messagebox.showwarning("No Results", "No scan results to save. Please run a scan first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Scan Report",
            initialfile="quantum_scan_report.txt"
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
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()

    def run_scan(self):
        """Execute the scan and display results."""
        try:
            # Get targets from input
            targets_input = self.targets_text.get('1.0', tk.END)
            targets = [line.strip() for line in targets_input.split('\n') if line.strip()]

            if not targets:
                messagebox.showwarning("No Targets", "Please enter at least one target to scan.")
                return

            # Update UI
            self.btn_scan.config(state='disabled', text='Scanning...')
            self.status_label.config(text=f"Scanning {len(targets)} target(s)...", fg='#FF9800')
            self.root.update()

            # Clear previous results
            self.results_text.delete('1.0', tk.END)

            # Run scan
            results = run_scan(targets)
            
            # Format and display results
            report = format_report(results)
            self.results_text.insert('1.0', report)

            # Update status
            vulnerable_count = sum(1 for r in results if r.quantum_vulnerable)
            self.status_label.config(
                text=f"Scan complete. {len(results)} target(s) assessed, {vulnerable_count} quantum-vulnerable.",
                fg='#F44336' if vulnerable_count > 0 else '#4CAF50'
            )

        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{e}")
            self.status_label.config(text="Scan failed. See error message.", fg='#F44336')
        
        finally:
            self.btn_scan.config(state='normal', text='Scan Targets')
            self.root.update()


def main():
    root = tk.Tk()
    app = QuantumScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
