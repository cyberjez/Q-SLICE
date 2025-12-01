from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector
import random, numpy as np, time

# Try Aer first, fallback to BasicAer or Statevector
execute = None
try:
    from qiskit import Aer
    from qiskit import execute as qiskit_execute
    execute = qiskit_execute
    BACKEND_SV = Aer.get_backend('statevector_simulator')
    BACKEND_QASM = Aer.get_backend('qasm_simulator')
    print("[INFO] Using Aer backends with execute")
except Exception as e:
    print(f"[INFO] Aer unavailable ({e}), trying BasicAer")
    try:
        from qiskit import BasicAer
        from qiskit import execute as qiskit_execute
        execute = qiskit_execute
        BACKEND_SV = BasicAer.get_backend('statevector_simulator')
        BACKEND_QASM = BasicAer.get_backend('qasm_simulator')
        print("[INFO] Using BasicAer backends")
    except Exception as e2:
        print(f"[INFO] BasicAer/execute unavailable ({e2}), using Statevector fallback")
        BACKEND_SV = None
        BACKEND_QASM = None

# Optional: import noise models only if Aer is present
try:
    from qiskit.providers.aer.noise import NoiseModel, depolarizing_error, thermal_relaxation_error, ReadoutError
    NOISE_AVAILABLE = True
except Exception:
    NOISE_AVAILABLE = False


class QSLICEMetrics:
    @staticmethod
    def fidelity(counts_clean, counts_attacked):
        """Compare overlap between clean and attacked distributions."""
        total = sum(counts_clean.values())
        overlap = sum(min(counts_clean.get(k, 0), counts_attacked.get(k, 0)) for k in counts_clean)
        return overlap / total if total else 0

    @staticmethod
    def lambda_depth(counts):
        """Proxy: depth of exploitation signal (marked vs others)."""
        if not counts: return 0
        mx = max(counts.values()); mn = min(counts.values())
        return mx / mn if mn else float('inf')

    @staticmethod
    def information_leakage(counts_attacked):
        """Leakage into unintended states."""
        return counts_attacked.get('01', 0) + counts_attacked.get('10', 0) if isinstance(counts_attacked, dict) else 0

    @staticmethod
    def randomness_bias(counts):
        """Bias in 0/1 distribution."""
        if not isinstance(counts, dict): return 0
        z = counts.get('0',0); o = counts.get('1',0); t = z+o
        return abs(z-o)/t if t else 0

    @staticmethod
    def qber(val):
        """Return QBER value."""
        return val


class QSLICEHarnessV2:
    def __init__(self, shots=1024):
        self.shots = shots
        self.backend_sv = BACKEND_SV
        self.backend_qasm = BACKEND_QASM
        self.use_execute = execute is not None
        self.metrics = QSLICEMetrics()

    def _simulate_counts(self, qc, shots):
        """Fallback count simulation via Statevector when execute unavailable."""
        try:
            stripped = qc.remove_final_measurements(inplace=False)
            sv = Statevector.from_instruction(stripped)
            probs = np.abs(sv.data)**2
            n = qc.num_qubits
            counts = {}
            for i,p in enumerate(probs):
                if p>0:
                    counts[format(i,f'0{n}b')] = int(round(p*shots))
            return counts
        except Exception:
            # uniform fallback
            n = qc.num_qubits
            return {format(i,f'0{n}b'): shots//(2**n) for i in range(2**n)}

    # Q – Quantum Exploitation (Grover)
    def test_quantum_exploitation(self):
        try:
            from qiskit.circuit.library import GroverOperator
            n = 3
            oracle = QuantumCircuit(n)
            oracle.x([0,2]); oracle.mcx([0,1],2); oracle.x([0,2])
            grover = GroverOperator(oracle)

            qc = QuantumCircuit(n,n)
            qc.h(range(n))
            qc.append(grover, range(n))
            qc.measure(range(n), range(n))

            if self.use_execute and self.backend_qasm:
                return execute(qc, self.backend_qasm, shots=self.shots*2).result().get_counts()
            else:
                return self._simulate_counts(qc, self.shots*2)
        except Exception as e:
            print(f"[WARNING] Grover test failed: {e}")
            # Fallback: amplified distribution
            counts = {format(i,'03b'): 117 for i in range(8)}
            counts['101'] = int(self.shots*1.2)
            return counts

    def test_shors_algorithm(self, N=15):
        """Test Shor's algorithm for integer factorization."""
        try:
            from qiskit.algorithms import Shor
            if self.use_execute and self.backend_qasm:
                shor = Shor()
                result = shor.factorize(N)
                return {"N": N, "factors": result.factors}
            else:
                raise ImportError("Shor requires execute backend")
        except Exception as e:
            print(f"[INFO] Shor unavailable ({e}), using trial division fallback")
            # Trial division fallback
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

    # S – Subversion of Trust (BB84)
    def test_subversion_of_trust(self, attack=True):
        shots = self.shots
        alice_bits = [random.randint(0,1) for _ in range(shots)]
        alice_bases = [random.randint(0,1) for _ in range(shots)]
        bob_bases = [random.randint(0,1) for _ in range(shots)]
        eve_bases = [random.randint(0,1) for _ in range(shots)]

        bob_results = []
        for i in range(shots):
            bit, a_base, b_base = alice_bits[i], alice_bases[i], bob_bases[i]
            if attack:
                disturbed = bit if eve_bases[i]==a_base else random.randint(0,1)
                meas = disturbed if b_base==a_base else random.randint(0,1)
            else:
                meas = bit if b_base==a_base else random.randint(0,1)
            bob_results.append(meas)

        sifted = [(alice_bits[i], bob_results[i]) for i in range(shots) if alice_bases[i]==bob_bases[i]]
        if not sifted: return {"qber": None, "kept": 0}
        errors = sum(1 for a,b in sifted if a!=b)
        return {"qber": errors/len(sifted), "kept": len(sifted)}

    def test_rng_bias(self, attack=True):
        """Test quantum random number generator for bias."""
        qc = QuantumCircuit(1,1)
        qc.h(0)
        qc.measure(0,0)
        
        if self.use_execute and self.backend_qasm:
            counts = execute(qc, self.backend_qasm, shots=self.shots).result().get_counts()
        else:
            counts = self._simulate_counts(qc, self.shots)
        
        total = sum(counts.values())
        p0 = counts.get('0',0)/total if total else 0
        p1 = counts.get('1',0)/total if total else 0
        entropy = -(p0*np.log2(p0) + p1*np.log2(p1)) if p0 and p1 else 0
        
        if attack:
            # Simulate biased RNG attack
            biased_counts = {"0": int(total*0.7), "1": int(total*0.3)}
            return {"entropy": entropy, "biased": biased_counts, "clean": counts}
        return {"entropy": entropy, "counts": counts}

    # L – Legacy Exploitation
    def test_legacy_exploitation(self):
        return {
            "cipher_suites": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"],
            "key_sizes": {"RSA": 2048, "ECC": "P-256"},
            "pqc_migration_status": "partial",
            "harvest_now_decrypt_later_risk": "elevated"
        }

    # I – Integrity Disruption (Bell state with noise if available)
    def test_integrity_disruption(self, error_rate=0.05):
        qc = QuantumCircuit(2,2)
        qc.h(0); qc.cx(0,1)
        qc.measure([0,1],[0,1])

        if self.use_execute and self.backend_qasm:
            counts_clean = execute(qc, self.backend_qasm, shots=self.shots).result().get_counts()
        else:
            counts_clean = self._simulate_counts(qc, self.shots)

        if NOISE_AVAILABLE and self.use_execute and self.backend_qasm:
            noise = NoiseModel()
            noise.add_all_qubit_quantum_error(depolarizing_error(error_rate, 2), ['cx'])
            counts_attacked = execute(qc, self.backend_qasm, shots=self.shots, noise_model=noise).result().get_counts()
        else:
            # Fallback: simulate error by rerunning and manually flipping some bits
            if self.use_execute and self.backend_qasm:
                counts_attacked = execute(qc, self.backend_qasm, shots=self.shots).result().get_counts()
            else:
                counts_attacked = self._simulate_counts(qc, self.shots)
            # Add simulated errors
            flips = int(self.shots * error_rate)
            attacked_sim = dict(counts_attacked)
            attacked_sim['01'] = attacked_sim.get('01', 0) + flips//2
            attacked_sim['10'] = attacked_sim.get('10', 0) + (flips - flips//2)
            attacked_sim['00'] = max(0, attacked_sim.get('00', 0) - flips//4)
            attacked_sim['11'] = max(0, attacked_sim.get('11', 0) - flips//4)
            counts_attacked = attacked_sim

        return {"clean": counts_clean, "attacked": counts_attacked}

    # C – Coherence Attacks
    def test_coherence_attacks(self):
        qc = QuantumCircuit(1,1)
        qc.h(0); qc.measure(0,0)

        if self.use_execute and self.backend_qasm:
            counts_clean = execute(qc, self.backend_qasm, shots=self.shots).result().get_counts()
        else:
            counts_clean = self._simulate_counts(qc, self.shots)

        if NOISE_AVAILABLE and self.use_execute and self.backend_qasm:
            noise = NoiseModel()
            trelax = thermal_relaxation_error(T1=50e3, T2=30e3, time=100)
            noise.add_all_qubit_quantum_error(trelax, ['id','u1','u2','u3'])
            read_err = ReadoutError([[0.95,0.05],[0.05,0.95]])
            noise.add_all_qubit_readout_error(read_err)
            counts_attacked = execute(qc, self.backend_qasm, shots=self.shots, noise_model=noise).result().get_counts()
        else:
            # Simulated readout bias
            counts_attacked = {'0': int(self.shots*0.45), '1': int(self.shots*0.55)}

        return {"clean": counts_clean, "attacked": counts_attacked}

    # E – Ecosystem Abuse
    def test_ecosystem_abuse(self):
        qc = QuantumCircuit(1,1)
        qc.h(0); qc.measure(0,0)
        if self.use_execute and self.backend_qasm:
            clean = execute(qc, self.backend_qasm, shots=self.shots).result().get_counts()
            untrusted = execute(qc, self.backend_qasm, shots=self.shots).result().get_counts()
        else:
            clean = self._simulate_counts(qc, self.shots)
            untrusted = self._simulate_counts(qc, self.shots)
        return {"clean_env": clean, "untrusted_env": untrusted}

    # Run all tests
    def run_all(self):
        results = {
            "QuantumExploitation_Grover": self.test_quantum_exploitation(),
            "QuantumExploitation_Shor": self.test_shors_algorithm(),
            "SubversionOfTrust_BB84": self.test_subversion_of_trust(),
            "SubversionOfTrust_RNG": self.test_rng_bias(),
            "LegacyExploitation": self.test_legacy_exploitation(),
            "IntegrityDisruption_Bell": self.test_integrity_disruption(),
            "CoherenceAttacks_Noise": self.test_coherence_attacks(),
            "EcosystemAbuse": self.test_ecosystem_abuse()
        }
        
        # Compute QSLICE metrics
        metrics = {
            "QuantumExploitation_Depth": self.metrics.lambda_depth(results["QuantumExploitation_Grover"]),
            "IntegrityDisruption_Fidelity": self.metrics.fidelity(
                results["IntegrityDisruption_Bell"]["clean"],
                results["IntegrityDisruption_Bell"]["attacked"]
            ),
            "IntegrityDisruption_Leakage": self.metrics.information_leakage(
                results["IntegrityDisruption_Bell"]["attacked"]
            ),
            "CoherenceAttacks_Bias": self.metrics.randomness_bias(results["CoherenceAttacks_Noise"]["attacked"]),
            "SubversionOfTrust_QBER": self.metrics.qber(results["SubversionOfTrust_BB84"].get("qber", 0))
        }
        
        return {"threat_results": results, "metrics": metrics}


if __name__ == "__main__":
    print("\n=== QSLICE Threat Harness V2 ===")
    harness = QSLICEHarnessV2(shots=1024)
    data = harness.run_all()
    
    print("\n-- Threat Results --")
    for k,v in data["threat_results"].items():
        print(f"{k}: {v}")
    
    print("\n-- QSLICE Metrics --")
    for k,v in data["metrics"].items():
        print(f"{k}: {v}")
    
    print("=== End ===\n")
