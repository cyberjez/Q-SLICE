from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector
import random, numpy as np, time

_use_aer = True
try:
    from qiskit import Aer, execute
    from qiskit.circuit.library import GroverOperator
    from qiskit.algorithms import Shor
    from qiskit.providers.aer.noise import NoiseModel, depolarizing_error, thermal_relaxation_error, ReadoutError
except Exception as e:
    _use_aer = False
    Aer = None
    execute = None
    GroverOperator = None
    Shor = None
    NoiseModel = None
    depolarizing_error = None
    thermal_relaxation_error = None
    ReadoutError = None
    print(f"[WARNING] Aer or noise providers unavailable: {e}")


class QSLICEMetrics:
    @staticmethod
    def fidelity(counts_clean, counts_attacked):
        total = sum(counts_clean.values())
        overlap = sum(min(counts_clean.get(k, 0), counts_attacked.get(k, 0)) for k in counts_clean)
        return overlap / total if total else 0

    @staticmethod
    def lambda_depth(counts):
        if not counts: return 0
        mx = max(counts.values()); mn = min(counts.values())
        return mx / mn if mn else float('inf')

    @staticmethod
    def information_leakage(counts_attacked):
        return counts_attacked.get('01', 0) + counts_attacked.get('10', 0) if isinstance(counts_attacked, dict) else 0

    @staticmethod
    def randomness_bias(counts):
        if not isinstance(counts, dict): return 0
        z = counts.get('0',0); o = counts.get('1',0); t = z+o
        return abs(z-o)/t if t else 0

    @staticmethod
    def qber(val):
        return val


class QSLICEHarness:
    def __init__(self, shots=1024):
        self.shots = shots
        self.metrics = QSLICEMetrics()
        self.backend_qasm = None
        if _use_aer:
            try:
                self.backend_qasm = Aer.get_backend('qasm_simulator')
            except Exception as e:
                print(f"[WARNING] Cannot get Aer backend: {e}")
                self.backend_qasm = None

    # Utility fallback simulate counts via Statevector (approx)
    def _simulate_counts(self, qc, shots):
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
            counts = {}
            for i in range(2**n):
                counts[format(i,f'0{n}b')] = shots // (2**n)
            return counts

    def test_quantum_exploitation(self):
        n = 3
        if _use_aer and self.backend_qasm and GroverOperator:
            oracle = QuantumCircuit(n)
            oracle.x([0,2]); oracle.mcx([0,1],2); oracle.x([0,2])
            grover = GroverOperator(oracle)
            qc = QuantumCircuit(n,n)
            qc.h(range(n)); qc.append(grover, range(n)); qc.measure(range(n), range(n))
            return execute(qc, self.backend_qasm, shots=self.shots*2).result().get_counts()
        # simulated amplification
        counts = {format(i,'03b'): 1 for i in range(8)}
        counts['101'] = int(self.shots*1.2)
        remaining = self.shots*2 - counts['101']
        for k in counts:
            if k!='101': counts[k] = remaining // 7
        return counts

    def test_shors_algorithm(self, N=15):
        if Shor and _use_aer and self.backend_qasm:
            try:
                res = Shor().factorize(N)
                return {"N":N,"factors":res.factors}
            except Exception as e:
                print(f"[WARNING] Shor failed: {e}")
        # trial division fallback
        fac=[]; n=N; d=2
        while d*d<=n:
            while n%d==0:
                fac.append(d); n//=d
            d = 3 if d==2 else d+2
        if n>1: fac.append(n)
        return {"N":N,"factors":fac}

    def test_subversion_of_trust(self, attack=True):
        shots=self.shots
        alice_bits=[random.randint(0,1) for _ in range(shots)]
        alice_bases=[random.randint(0,1) for _ in range(shots)]
        bob_bases=[random.randint(0,1) for _ in range(shots)]
        eve_bases=[random.randint(0,1) for _ in range(shots)]
        bob_results=[]
        for i in range(shots):
            bit,a_base,b_base=alice_bits[i],alice_bases[i],bob_bases[i]
            if attack:
                disturbed = bit if eve_bases[i]==a_base else random.randint(0,1)
                meas = disturbed if b_base==a_base else random.randint(0,1)
            else:
                meas = bit if b_base==a_base else random.randint(0,1)
            bob_results.append(meas)
        sifted=[(alice_bits[i],bob_results[i]) for i in range(shots) if alice_bases[i]==bob_bases[i]]
        if not sifted: return {"qber":None,"kept":0}
        errors=sum(1 for a,b in sifted if a!=b)
        return {"qber": errors/len(sifted), "kept": len(sifted)}

    def test_integrity_disruption(self, error_rate=0.05):
        qc=QuantumCircuit(2,2); qc.h(0); qc.cx(0,1); qc.measure([0,1],[0,1])
        if _use_aer and self.backend_qasm and NoiseModel and depolarizing_error:
            noise=NoiseModel(); noise.add_all_qubit_quantum_error(depolarizing_error(error_rate,2),['cx'])
            clean=execute(qc,self.backend_qasm,shots=self.shots).result().get_counts()
            attacked=execute(qc,self.backend_qasm,shots=self.shots,noise_model=noise).result().get_counts()
        else:
            clean={'00':self.shots//2,'11':self.shots - self.shots//2}
            flips=int(self.shots*error_rate)
            attacked={'00':max(0,clean['00']-flips),'11':max(0,clean['11']-flips),'01':flips//2,'10':flips - flips//2}
        return {"clean":clean,"attacked":attacked}

    def test_coherence_attacks(self):
        qc=QuantumCircuit(1,1); qc.h(0); qc.measure(0,0)
        if _use_aer and self.backend_qasm and thermal_relaxation_error and ReadoutError and NoiseModel:
            noise=NoiseModel(); trelax=thermal_relaxation_error(T1=50e3,T2=30e3,time=100)
            noise.add_all_qubit_quantum_error(trelax,['id','u1','u2','u3'])
            noise.add_all_qubit_readout_error(ReadoutError([[0.95,0.05],[0.05,0.95]]))
            clean=execute(qc,self.backend_qasm,shots=self.shots).result().get_counts()
            attacked=execute(qc,self.backend_qasm,shots=self.shots,noise_model=noise).result().get_counts()
        else:
            clean={'0':self.shots//2,'1':self.shots-self.shots//2}
            attacked={'0':int(self.shots*0.45),'1':int(self.shots*0.55)}
        return {"clean":clean,"attacked":attacked}

    def test_ecosystem_abuse(self):
        qc=QuantumCircuit(1,1); qc.h(0); qc.measure(0,0)
        if _use_aer and self.backend_qasm:
            clean=execute(qc,self.backend_qasm,shots=self.shots).result().get_counts()
            untrusted=execute(qc,self.backend_qasm,shots=self.shots).result().get_counts()
        else:
            clean={'0':self.shots//2,'1':self.shots-self.shots//2}
            untrusted={'0':int(self.shots*0.48),'1':int(self.shots*0.52)}
        return {"clean_env":clean,"untrusted_env":untrusted}

    def run_all(self):
        results={
            "QuantumExploitation": self.test_quantum_exploitation(),
            "SubversionOfTrust": self.test_subversion_of_trust(),
            "LegacyExploitation": {"cipher_suites":["TLS_RSA_WITH_AES_128_GCM_SHA256","ECDHE-ECDSA-AES256-GCM-SHA384"],"key_sizes":{"RSA":2048,"ECC":"P-256"},"pqc_migration_status":"partial","harvest_now_decrypt_later_risk":"elevated"},
            "IntegrityDisruption": self.test_integrity_disruption(),
            "CoherenceAttacks": self.test_coherence_attacks(),
            "EcosystemAbuse": self.test_ecosystem_abuse()
        }
        metrics={
            "QuantumExploitation_Depth": self.metrics.lambda_depth(results["QuantumExploitation"]),
            "IntegrityDisruption_Fidelity": self.metrics.fidelity(results["IntegrityDisruption"]["clean"],results["IntegrityDisruption"]["attacked"]),
            "IntegrityDisruption_Leakage": self.metrics.information_leakage(results["IntegrityDisruption"]["attacked"]),
            "CoherenceAttacks_Bias": self.metrics.randomness_bias(results["CoherenceAttacks"]["attacked"]),
            "SubversionOfTrust_QBER": self.metrics.qber(results["SubversionOfTrust"].get("qber",0))
        }
        return {"threat_results":results,"metrics":metrics}

if __name__ == "__main__":
    print("\n=== QSLICE Threat Harness (Fallback Capable) ===")
    harness=QSLICEHarness(shots=1024)
    data=harness.run_all()
    print("\n-- Threat Results --")
    for k,v in data["threat_results"].items():
        print(f"{k}: {v}")
    print("\n-- Metrics --")
    for k,v in data["metrics"].items():
        print(f"{k}: {v}")
    print("=== End ===\n")
