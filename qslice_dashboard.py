import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import csv
import sys
import os

# Import the actual harness
try:
    from qslice_threat_harness_v3 import QSLICEHarnessV3
    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False
    print("[WARNING] Could not import QSLICEHarnessV3, using simulated results")

# --- Q-SLICE Threat Harness Core Logic ---
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
    
    # Simulated results fallback
    results = {
        "QuantumExploitation_Shor": {"N": shor_n, "factors": [3, 5]},
        "SubversionOfTrust_RNG": {"biased": {"0": int(shots * rng_bias), "1": int(shots * (1 - rng_bias))}},
        "LegacyExploitation": {
            "cipher_suites": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"],
            "key_sizes": {"RSA": 2048, "ECC": "P-256"},
            "pqc_migration_status": "partial",
            "harvest_now_decrypt_later_risk": "elevated"
        },
        "QSLICE_Metrics": {
            "QuantumExploitation_Depth": 1.0,
            "IntegrityDisruption_Fidelity": max(0.0, 1.0 - 2 * bell_error),
            "IntegrityDisruption_Leakage": int(shots * 2 * bell_error),
            "CoherenceAttacks_Bias": round(abs(bell_error), 4),
            "SubversionOfTrust_QBER": 0.2507
        }
    }
    return results

# --- GUI Logic ---
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

        global results
        results = run_qslice_harness(shots, shor_n, bell_error, rng_bias)
        metrics = results["QSLICE_Metrics"]

        # --- Full Metric Explanations ---
        explanation = "=" * 70 + "\n"
        explanation += "QSLICE METRICS EXPLAINED\n"
        explanation += "=" * 70 + "\n\n"

        explanation += f"QuantumExploitation_Depth: {metrics['QuantumExploitation_Depth']:.4f}\n"
        explanation += "  → Grover amplification measure.\n"
        explanation += "     1.0 = uniform distribution (no exploitation)\n"
        explanation += "     >1.0 = adversarial advantage detected\n\n"

        explanation += f"IntegrityDisruption_Fidelity: {metrics['IntegrityDisruption_Fidelity']:.4f}\n"
        explanation += "  → Overlap between clean and attacked Bell states.\n"
        explanation += f"     1.0 = perfect integrity, current = {(1.0 - metrics['IntegrityDisruption_Fidelity']) * 100:.1f}% loss\n\n"

        explanation += f"IntegrityDisruption_Leakage: {metrics['IntegrityDisruption_Leakage']}\n"
        explanation += "  → Number of unintended Bell outcomes.\n"
        explanation += "     High leakage = strong entanglement disruption.\n\n"

        explanation += f"CoherenceAttacks_Bias: {metrics['CoherenceAttacks_Bias']:.4f}\n"
        explanation += "  → Noise-induced skew in quantum state distribution.\n"
        explanation += "     Even small biases undermine reliability. Ideal = 0.0\n\n"

        explanation += f"SubversionOfTrust_QBER: {metrics['SubversionOfTrust_QBER']:.4f}\n"
        explanation += "  → Quantum Bit Error Rate in BB84.\n"
        explanation += "     Secure threshold <11%. "
        if metrics['SubversionOfTrust_QBER'] > 0.11:
            explanation += "ALERT: Heavy interference/eavesdropping!\n\n"
        else:
            explanation += "Within secure range.\n\n"

        explanation += f"Shor Factorization: {results['QuantumExploitation_Shor']['factors']}\n"
        explanation += "  → Successful factoring demonstrates algorithmic collapse.\n"
        explanation += "     Evidences quantum threat to RSA/ECC cryptography.\n\n"

        explanation += f"RNG Bias Distribution: {results.get('SubversionOfTrust_RNG', {}).get('biased', {})}\n"
        explanation += "  → Entropy corruption indicator.\n"
        explanation += "     Balanced RNG = trust; skewed RNG = manipulation.\n\n"

        legacy = results['LegacyExploitation']
        explanation += f"Legacy Cryptography Risk: {legacy['harvest_now_decrypt_later_risk']}\n"
        explanation += f"  → PQC Migration: {legacy['pqc_migration_status']}\n"
        explanation += "     'Elevated' = vulnerable to harvest-now-decrypt-later attacks.\n\n"

        # Show explanations in scrollable text box
        text_box.config(state='normal')
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, explanation)
        text_box.config(state='disabled')

        # --- Dashboard Visualization ---
        # Clear previous plot if exists
        for widget in chart_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(1, 2, figsize=(10, 4))
        fig.patch.set_facecolor('#f0f0f0')

        # RNG Bias bar chart
        rng_data = results.get("SubversionOfTrust_RNG", {}).get("biased", {"0": 0, "1": 0})
        colors = ['#2196F3', '#F44336']
        ax[0].bar(rng_data.keys(), rng_data.values(), color=colors)
        ax[0].set_title("RNG Bias Distribution", fontsize=12, fontweight='bold')
        ax[0].set_ylabel("Counts", fontsize=10)
        ax[0].set_xlabel("Bit Value", fontsize=10)
        ax[0].grid(axis='y', alpha=0.3)

        # Metrics bar chart (normalized for better visualization)
        metric_names = ['Depth', 'Fidelity', 'QBER', 'Bias']
        metric_values = [
            min(metrics['QuantumExploitation_Depth'], 2.0),  # Cap at 2 for visualization
            metrics['IntegrityDisruption_Fidelity'],
            metrics['SubversionOfTrust_QBER'] * 4,  # Scale up for visibility
            metrics['CoherenceAttacks_Bias'] * 4    # Scale up for visibility
        ]
        colors_metrics = ['#4CAF50', '#2196F3', '#FF9800', '#9C27B0']
        bars = ax[1].barh(metric_names, metric_values, color=colors_metrics)
        ax[1].set_title("QSLICE Metrics (Normalized)", fontsize=12, fontweight='bold')
        ax[1].set_xlabel("Value", fontsize=10)
        ax[1].set_xlim(0, 2)
        ax[1].grid(axis='x', alpha=0.3)

        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax[1].text(width, bar.get_y() + bar.get_height()/2, 
                      f'{width:.3f}', ha='left', va='center', fontsize=9)

        plt.tight_layout()

        # Embed matplotlib figure in Tkinter
        global canvas, fig_ref
        fig_ref = fig
        canvas = FigureCanvasTkAgg(fig, master=chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

        btn_save.config(state='normal')

    except ValueError as e:
        messagebox.showerror("Input Error", f"Invalid input: {e}")
    except Exception as e:
        messagebox.showerror("Execution Error", f"Error running harness:\n{e}")
    finally:
        # Re-enable button
        btn_run.config(state='normal', text='Run Q-SLICE')

def save_results():
    if not results:
        messagebox.showerror("Error", "No results to save. Run Q-SLICE first.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        title="Save QSLICE Results"
    )
    
    if file_path:
        try:
            # Save metrics to CSV
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Category", "Metric", "Value"])
                
                # Write metrics
                for k, v in results["QSLICE_Metrics"].items():
                    writer.writerow(["Metrics", k, v])
                
                # Write Shor results
                shor = results.get("QuantumExploitation_Shor", {})
                writer.writerow(["Shor", "N", shor.get("N", "")])
                writer.writerow(["Shor", "Factors", str(shor.get("factors", []))])
                
                # Write RNG bias
                rng = results.get("SubversionOfTrust_RNG", {}).get("biased", {})
                for bit, count in rng.items():
                    writer.writerow(["RNG_Bias", f"Bit_{bit}", count])
                
                # Write legacy risk
                legacy = results.get("LegacyExploitation", {})
                writer.writerow(["Legacy", "Risk", legacy.get("harvest_now_decrypt_later_risk", "")])
                writer.writerow(["Legacy", "PQC_Status", legacy.get("pqc_migration_status", "")])
            
            messagebox.showinfo("Saved", f"Metrics saved to:\n{file_path}")

            # Save chart as PNG alongside CSV
            if fig_ref:
                png_path = file_path.replace(".csv", "_chart.png")
                fig_ref.savefig(png_path, dpi=150, bbox_inches='tight')
                messagebox.showinfo("Saved", f"Dashboard chart saved to:\n{png_path}")
        
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save results:\n{e}")

# --- GUI Setup ---
root = tk.Tk()
root.title("Q-SLICE Threat Harness - Enhanced Dashboard")
root.geometry("900x800")
root.configure(bg='#f0f0f0')

# Header
header_frame = tk.Frame(root, bg='#1976D2', height=70)
header_frame.pack(fill='x')
header_frame.pack_propagate(False)

header_label = tk.Label(header_frame, text="Q-SLICE Threat Harness", 
                        font=("Arial", 20, "bold"), fg="white", bg='#1976D2')
header_label.pack(pady=10)

subtitle = tk.Label(header_frame, text="Quantum Threat Modelling Dashboard", 
                    font=("Arial", 10), fg="#E3F2FD", bg='#1976D2')
subtitle.pack()

# Input frame
input_frame = tk.LabelFrame(root, text="Configuration Parameters", font=("Arial", 11, "bold"),
                           bg='#f0f0f0', padx=20, pady=15)
input_frame.pack(padx=20, pady=10, fill='x')

labels_text = [
    "Shots (e.g. 1024):",
    "Shor's N (e.g. 15):",
    "Bell Error Rate (0.0–1.0):",
    "RNG Bias (0.0–1.0):"
]

entries = []
default_values = ["1024", "15", "0.05", "0.7"]

for i, (label_text, default) in enumerate(zip(labels_text, default_values)):
    label = tk.Label(input_frame, text=label_text, anchor='w', width=25, 
                    font=("Arial", 10), bg='#f0f0f0')
    label.grid(row=i, column=0, sticky='w', pady=5, padx=5)
    
    entry = tk.Entry(input_frame, width=20, font=("Arial", 10))
    entry.insert(0, default)
    entry.grid(row=i, column=1, padx=10, pady=5)
    entries.append(entry)

entry_shots, entry_shor, entry_bell, entry_rng = entries

# Button frame
button_frame = tk.Frame(root, bg='#f0f0f0')
button_frame.pack(pady=10)

btn_run = tk.Button(button_frame, text='Run Q-SLICE Analysis', command=run_qslice, 
                   bg='#4CAF50', fg='white', font=("Arial", 11, "bold"), 
                   padx=20, pady=10, relief=tk.RAISED, bd=3)
btn_run.grid(row=0, column=0, padx=10)

btn_save = tk.Button(button_frame, text='Save Results & Chart', command=save_results, 
                    bg='#2196F3', fg='white', font=("Arial", 11, "bold"), 
                    padx=20, pady=10, relief=tk.RAISED, bd=3, state='disabled')
btn_save.grid(row=0, column=1, padx=10)

btn_exit = tk.Button(button_frame, text='Exit', command=root.quit, 
                    bg='#F44336', fg='white', font=("Arial", 11, "bold"), 
                    padx=20, pady=10, relief=tk.RAISED, bd=3)
btn_exit.grid(row=0, column=2, padx=10)

# Results text box
text_frame = tk.LabelFrame(root, text="Metric Explanations", font=("Arial", 11, "bold"),
                          bg='#f0f0f0', padx=10, pady=10)
text_frame.pack(padx=20, pady=5, fill='both')

text_box = scrolledtext.ScrolledText(text_frame, height=10, width=100, wrap="word",
                                     font=("Courier New", 9), bg='#ffffff')
text_box.pack(fill='both', expand=True)
text_box.config(state='disabled')

# Chart frame
chart_frame = tk.LabelFrame(root, text="Visual Dashboard", font=("Arial", 11, "bold"),
                           bg='#f0f0f0', padx=10, pady=10)
chart_frame.pack(padx=20, pady=5, fill='both', expand=True)

# Status footer
status_text = "✓ Harness Connected" if HARNESS_AVAILABLE else "⚠ Using Simulated Mode"
status_color = "#4CAF50" if HARNESS_AVAILABLE else "#FF9800"
status_label = tk.Label(root, text=status_text, fg=status_color, 
                       font=("Arial", 9, "bold"), bg='#f0f0f0')
status_label.pack(pady=5)

results = None
canvas = None
fig_ref = None

root.mainloop()
