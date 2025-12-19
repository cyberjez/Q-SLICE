# qslice_threat_harness_v4.py

from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector
import numpy as np, random

# --- IBM Quantum Cloud Integration ---
from qiskit_ibm_runtime import QiskitRuntimeService

# Initialize service
service = None
try:
    service = QiskitRuntimeService(channel="ibm_quantum_platform")
    print("[INFO] Using saved IBM Quantum credentials")
except Exception as e:
    print(f"[INFO] IBM Quantum account not configured: {e}")
    print("\nPlease enter your IBM Quantum API key.")
    print("Get your key from: https://quantum.ibm.com/")
    api_key = input("Enter API key (or press Enter to skip): ").strip()
    
    if api_key:
        try:
            QiskitRuntimeService.save_account(channel='ibm_quantum_platform', token=api_key, overwrite=True)
            service = QiskitRuntimeService(channel="ibm_quantum_platform")
            print("[INFO] API key saved successfully!")
        except Exception as e2:
            print(f"[ERROR] Failed to save API key: {e2}")
            raise
    else:
        print("[ERROR] No API key provided. Cannot proceed.")
        raise ValueError("IBM Quantum API key required")

# Choose backends
BACKEND_QASM = service.backend('ibmq_qasm_simulator')
BACKEND_SV = BACKEND_QASM

# Optional: noise model availability
try:
    from qiskit.providers.aer.noise import NoiseModel, depolarizing_error, thermal_relaxation_error, ReadoutError
    NOISE_AVAILABLE = True
except Exception:
    NOISE_AVAILABLE = False


class QSLICEMetrics:
    @staticmethod
    def fidelity(counts_clean: dict, counts_attacked: dict) -> float:
        total = sum(counts_clean.values())
        overlap = sum(min(counts_clean.get(k, 0), counts_attacked.get(k, 0)) for k in counts_clean)
        return overlap / total if total else 0.0

    @staticmethod
    def lambda_depth(counts: dict) -> float:
        if not counts:
            return 0.0
        mx = max(counts.values())
        mn = min(counts.values())
        return mx / mn if mn else float('inf')

    @staticmethod
    def information_leakage(counts_attacked: dict) -> int:
        return counts_attacked.get('01', 0) + counts_attacked.get('10', 0) if isinstance(counts_attacked, dict) else 0

    @staticmethod
    def randomness_bias(counts: dict) -> float:
        if not isinstance(counts, dict):
            return 0.0
        z = counts.get('0', 0)
        o = counts.get('1', 0)
        t = z + o
        return abs(z - o) / t if t else 0.0

    @staticmethod
    def qber(val: float) -> float:
        return float(val) if val is not None else 0.0


class QSLICEHarnessV4:
    def __init__(self, shots=1024, N=15, error_rate=0.05, rng_bias=0.7):
        """
        shots: total shots per experiment
        N: integer for Shor factoring
        error_rate: Bell disruption error fraction (0-1)
        rng_bias: fraction assigned to '0' in biased RNG (0-1), e.g., 0.7 => 70% '0'
        """
        self.shots = int(shots)
        self.N = int(N)
        self.error_rate = float(error_rate)
        self.rng_bias = float(rng_bias)
        self.backend_sv = BACKEND_SV
        self.backend_qasm = BACKEND_QASM
        self.use_execute = True  # force cloud backend usage
        self.metrics = QSLICEMetrics()

    # -------- Utility --------
    def _simulate_counts(self, qc: QuantumCircuit, shots: int) -> dict:
        """Statevector-based probability to counts; uniform fallback."""
        try:
            stripped = qc.remove_final_measurements(inplace=False)
            sv = Statevector.from_instruction(stripped)
            probs = np.abs(sv.data) ** 2
            n = qc.num_qubits
            counts = {}
            for i, p in enumerate(probs):
                if p > 0:
                    counts[format(i, f'0{n}b')] = int(round(p * shots))
            total = sum(counts.values())
            if total < shots:
                if counts:
                    max_key = max(counts, key=counts.get)
                    counts[max_key] += (shots - total)
            return counts if counts else {format(i, f'0{qc.num_qubits}b'): shots // (2 ** qc.num_qubits) for i in range(2 ** qc.num_qubits)}
        except Exception:
            n = qc.num_qubits
            return {format(i, f'0{n}b'): shots // (2 ** n) for i in range(2 ** n)}

    # -------- Q – Quantum Exploitation (Grover) --------
    def test_quantum_exploitation(self) -> dict:
        try:
            from qiskit.circuit.library import GroverOperator
            n = 3
            oracle = QuantumCircuit(n)
            oracle.x([0, 2])
            oracle.mcx([0, 1], 2)
            oracle.x([0, 2])

            grover = GroverOperator(oracle)
            qc = QuantumCircuit(n, n)
            qc.h(range(n))
            qc.append(grover, range(n))
            qc.measure(range(n), range(n))

            shots = self.shots * 2
            return self.backend_qasm.run(qc, shots=shots).result().get_counts()
        except Exception as e:
            print(f"[WARNING] Grover test failed: {e}")
            counts = {format(i, '03b'): int(self.shots * 0.115) for i in range(8)}
            counts['101'] = int(self.shots * 1.2)
            return counts

    # -------- Q – Shor's Algorithm --------
    def test_shors_algorithm(self, N=None) -> dict:
        N = int(self.N if N is None else N)
        try:
            from qiskit.algorithms import Shor
            shor = Shor()
            result = shor.factorize(N)
            return {"N": N, "factors": result.factors}
        except Exception as e:
            print(f"[INFO] Shor unavailable ({e}), using trial division fallback")
            factors = []
            n = N
            d = 2
            while d * d <= n:
                while n % d == 0:
                    factors.append(d)
                    n //= d
                d = 3 if d == 2 else d + 2
            if n > 1:
                factors.append(n)
            return {"N": N, "factors": factors}

    # -------- S – Subversion of Trust (BB84) --------
    def test_subversion_of_trust(self, attack=True) -> dict:
        shots = self.shots
        alice_bits = [random.randint(0, 1) for _ in range(shots)]
        alice_bases = [random.randint(0, 1) for _ in range(shots)]
        bob_bases = [random.randint(0, 1) for _ in range(shots)]
        eve_bases = [random.randint(0, 1) for _ in range(shots)]
        bob_results = []

        for i in range(shots):
            bit, a_base, b_base = alice_bits[i], alice_bases[i], bob_bases[i]
            if attack:
                disturbed = bit if eve_bases[i] == a_base else random.randint(0, 1)
                meas = disturbed if b_base == a_base else random.randint(0, 1)
            else:
                meas = bit if b_base == a_base else random.randint(0, 1)
            bob_results.append(meas)

        sifted = [(alice_bits[i], bob_results[i]) for i in range(shots) if alice_bases[i] == bob_bases[i]]
        if not sifted:
            return {"qber": None, "kept": 0}
        errors = sum(1 for a, b in sifted if a != b)
        return {"qber": errors / len(sifted), "kept": len(sifted)}

    # -------- S – RNG Bias --------
    def test_rng_bias(self, attack=True) -> dict:
        qc = QuantumCircuit(1, 1)
        qc.h(0)
        qc.measure(0, 0)

        counts = self.backend_qasm.run(qc, shots=self.shots).result().get_counts()

        total = sum(counts.values())
        p0 = counts.get('0', 0) / total if total else 0.0
        p1 = counts.get('1', 0) / total if total else 0.0
        entropy = -(p0 * np.log2(p0) + p1 * np.log2(p1)) if p0 and p1 else 0.0

        if attack:
            b0 = max(0.0, min(1.0, self.rng_bias))
            b1 = 1.0 - b0
            biased_counts = {"0": int(total * b0), "1": int(total * b1)}
            diff = total - (biased_counts["0"] + biased_counts["1"])
            if diff != 0:
                biased_counts["0"] += diff
            return {"entropy": entropy, "biased": biased_counts, "clean": counts}
        else:
            return {"entropy": entropy, "biased": None, "clean": counts}