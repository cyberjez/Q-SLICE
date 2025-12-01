# Q-SLICE
Q-SLICE is a modular quantum adversarial simulation framework designed to model and measure quantum threats. Built with Qiskit, the harness runs targeted tests including Grover amplification, Shor’s factoring, BB84 key exchange, RNG bias injection, Bell state disruption and noise-based coherence drift.

Q-SLICE V3 introduces user-driven configuration: researchers can input custom values for shots, Shor’s N, Bell error rate, and RNG bias. This enables flexible scenario modelling and comparative testing across environments. The harness includes layered fallbacks (Aer → BasicAer → Statevector) and simulated noise injection, ensuring robustness even when full quantum backends are unavailable.
