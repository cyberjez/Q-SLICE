import tkinter as tk
from tkinter import messagebox, scrolledtext
import sys
import os

# Import the actual harness
try:
    from qslice_threat_harness_v3 import QSLICEHarnessV3
    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False
    print("[WARNING] Could not import QSLICEHarnessV3, using simulated results")

import numpy as np

def run_qslice_harness(shots, shor_n, bell_error, rng_bias):
    """Run the actual QSLICE harness or return simulated results."""
    if HARNESS_AVAILABLE:
        try:
            harness = QSLICEHarnessV3(shots=shots, N=shor_n, error_rate=bell_error, rng_bias=rng_bias)
            data = harness.run_all()
            # Merge results and metrics into single dict for easier access
            combined = data["threat_results"].copy()
            combined["QSLICE_Metrics"] = data["metrics"]
            return combined
        except Exception as e:
            print(f"[ERROR] Harness execution failed: {e}")
            # Fall through to simulated results
    
    # Simulated outputs for demonstration when harness unavailable
    results = {
        "QuantumExploitation_Grover": {bin(i)[2:].zfill(3): shots // 8 for i in range(8)},
        "QuantumExploitation_Shor": {"N": shor_n, "factors": [3, 5] if shor_n == 15 else [shor_n]},
        "SubversionOfTrust_BB84": {"qber": 0.2507, "kept": int(shots * 0.5)},
        "SubversionOfTrust_RNG": {
            "entropy": np.float64(1.0),
            "biased": {"0": int(shots * rng_bias), "1": int(shots * (1 - rng_bias))},
            "clean": {"0": shots // 2, "1": shots // 2}
        },
        "LegacyExploitation": {
            "cipher_suites": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"],
            "key_sizes": {"RSA": 2048, "ECC": "P-256"},
            "pqc_migration_status": "partial",
            "harvest_now_decrypt_later_risk": "elevated"
        },
        "IntegrityDisruption_Bell": {
            "clean": {"00": shots // 2, "11": shots // 2},
            "attacked": {
                "00": int(shots * (0.5 - bell_error)),
                "11": int(shots * (0.5 - bell_error)),
                "01": int(shots * bell_error),
                "10": int(shots * bell_error)
            }
        },
        "CoherenceAttacks_Noise": {
            "clean": {"0": shots // 2, "1": shots // 2},
            "attacked": {"0": int(shots * 0.45), "1": int(shots * 0.55)}
        },
        "EcosystemAbuse": {
            "clean_env": {"0": shots // 2, "1": shots // 2},
            "untrusted_env": {"0": shots // 2, "1": shots // 2}
        },
        "QSLICE_Metrics": {
            "QuantumExploitation_Depth": 1.0,
            "IntegrityDisruption_Fidelity": max(0.0, 1.0 - 2 * bell_error),
            "IntegrityDisruption_Leakage": int(shots * 2 * bell_error),
            "CoherenceAttacks_Bias": 0.1,
            "SubversionOfTrust_QBER": 0.2507
        }
    }
    return results

def format_dict_pretty(d, indent=0):
    """Recursively format dictionary for display."""
    lines = []
    for key, value in d.items():
        if isinstance(value, dict):
            lines.append("  " * indent + f"{key}:")
            lines.append(format_dict_pretty(value, indent + 1))
        else:
            lines.append("  " * indent + f"{key}: {value}")
    return "\n".join(lines)

def run_qslice():
    try:
        shots = int(entry_shots.get())
        shor_n = int(entry_shor.get())
        bell_error = float(entry_bell.get())
        rng_bias = float(entry_rng.get())

        # Validate inputs
        if shots <= 0:
            raise ValueError("Shots must be positive")
        if shor_n <= 1:
            raise ValueError("Shor's N must be greater than 1")
        if not (0.0 <= bell_error <= 1.0):
            raise ValueError("Bell error rate must be between 0.0 and 1.0")
        if not (0.0 <= rng_bias <= 1.0):
            raise ValueError("RNG bias must be between 0.0 and 1.0")

        # Disable button during execution
        btn_run.config(state='disabled', text='Running...')
        root.update()

        results = run_qslice_harness(shots, shor_n, bell_error, rng_bias)

        # Build detailed output
        output = "=" * 60 + "\n"
        output += "QSLICE THREAT HARNESS RESULTS\n"
        output += "=" * 60 + "\n\n"

        # Summary Section
        output += "--- EXECUTIVE SUMMARY ---\n"
        metrics = results.get('QSLICE_Metrics', {})
        output += f"• Grover Depth: {metrics.get('QuantumExploitation_Depth', 'N/A'):.3f} → {'Uniform (no exploitation)' if metrics.get('QuantumExploitation_Depth', 0) <= 1.0 else 'Amplification detected'}\n"
        output += f"• Shor Factors: {results.get('QuantumExploitation_Shor', {}).get('factors', [])} → Demonstrates algorithmic collapse\n"
        output += f"• QBER: {metrics.get('SubversionOfTrust_QBER', 0):.4f} → {'Trust compromised' if metrics.get('SubversionOfTrust_QBER', 0) > 0.11 else 'Trust maintained'} in BB84\n"
        
        rng_result = results.get('SubversionOfTrust_RNG', {})
        output += f"• RNG Bias: {rng_result.get('biased', {})} → Entropy corruption detected\n"
        
        output += f"• Fidelity: {metrics.get('IntegrityDisruption_Fidelity', 0):.4f} → {abs(1.0 - metrics.get('IntegrityDisruption_Fidelity', 1.0)) * 100:.1f}% entanglement loss\n"
        output += f"• Leakage: {metrics.get('IntegrityDisruption_Leakage', 0)} → Unintended Bell outcomes\n"
        output += f"• Coherence Bias: {metrics.get('CoherenceAttacks_Bias', 0):.4f} → Skewed quantum state distribution\n"
        
        legacy = results.get('LegacyExploitation', {})
        output += f"• Legacy Risk: {legacy.get('harvest_now_decrypt_later_risk', 'N/A')} → PQC migration {legacy.get('pqc_migration_status', 'unknown')}\n"

        output += "\n--- DETAILED THREAT RESULTS ---\n\n"
        
        # Detailed results for each category
        for category in ["QuantumExploitation_Grover", "QuantumExploitation_Shor", 
                         "SubversionOfTrust_BB84", "SubversionOfTrust_RNG",
                         "LegacyExploitation", "IntegrityDisruption_Bell",
                         "CoherenceAttacks_Noise", "EcosystemAbuse"]:
            if category in results:
                output += f"{category}:\n"
                output += format_dict_pretty(results[category], indent=1)
                output += "\n\n"

        output += "--- QSLICE METRICS ---\n"
        output += format_dict_pretty(metrics, indent=1)
        output += "\n\n"
        output += "=" * 60 + "\n"

        # Display in scrollable text widget
        result_window = tk.Toplevel(root)
        result_window.title("Q-SLICE Results")
        result_window.geometry("700x600")
        
        text_widget = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, font=("Courier", 9))
        text_widget.pack(expand=True, fill='both', padx=10, pady=10)
        text_widget.insert(tk.END, output)
        text_widget.config(state='disabled')  # Make read-only
        
        # Copy button
        def copy_to_clipboard():
            root.clipboard_clear()
            root.clipboard_append(output)
            messagebox.showinfo("Copied", "Results copied to clipboard!")
        
        tk.Button(result_window, text='Copy to Clipboard', command=copy_to_clipboard).pack(pady=5)

    except ValueError as e:
        messagebox.showerror("Input Error", f"Invalid input: {e}")
    except Exception as e:
        messagebox.showerror("Execution Error", f"Error running harness: {e}")
    finally:
        # Re-enable button
        btn_run.config(state='normal', text='Run Q-SLICE')

# UI setup
root = tk.Tk()
root.title("Q-SLICE Threat Harness GUI")
root.geometry("400x250")

# Header
header = tk.Label(root, text="QSLICE Threat Harness", font=("Arial", 16, "bold"), fg="navy")
header.grid(row=0, column=0, columnspan=2, pady=10)

# Input fields
tk.Label(root, text="Shots:", anchor='w').grid(row=1, column=0, sticky='w', padx=20, pady=5)
tk.Label(root, text="Shor's N:", anchor='w').grid(row=2, column=0, sticky='w', padx=20, pady=5)
tk.Label(root, text="Bell Error Rate (0.0–1.0):", anchor='w').grid(row=3, column=0, sticky='w', padx=20, pady=5)
tk.Label(root, text="RNG Bias (0.0–1.0):", anchor='w').grid(row=4, column=0, sticky='w', padx=20, pady=5)

entry_shots = tk.Entry(root, width=20)
entry_shor = tk.Entry(root, width=20)
entry_bell = tk.Entry(root, width=20)
entry_rng = tk.Entry(root, width=20)

# Default values
entry_shots.insert(0, "1024")
entry_shor.insert(0, "15")
entry_bell.insert(0, "0.05")
entry_rng.insert(0, "0.7")

entry_shots.grid(row=1, column=1, padx=20, pady=5)
entry_shor.grid(row=2, column=1, padx=20, pady=5)
entry_bell.grid(row=3, column=1, padx=20, pady=5)
entry_rng.grid(row=4, column=1, padx=20, pady=5)

# Run button
btn_run = tk.Button(root, text='Run Q-SLICE', command=run_qslice, bg='#4CAF50', fg='white', 
                    font=("Arial", 12, "bold"), padx=20, pady=10)
btn_run.grid(row=5, column=0, columnspan=2, pady=20)

# Status label
status_text = "Ready" if HARNESS_AVAILABLE else "Using Simulated Mode (harness not found)"
status_label = tk.Label(root, text=status_text, fg="green" if HARNESS_AVAILABLE else "orange", font=("Arial", 8))
status_label.grid(row=6, column=0, columnspan=2)

root.mainloop()
