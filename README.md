# Q-SLICE
Q-SLICE is a modular quantum adversarial simulation framework designed to model and measure quantum threats. Built with Qiskit, the harness runs targeted tests including Grover amplification, Shor’s factoring, BB84 key exchange, RNG bias injection, Bell state disruption and noise-based coherence drift.

Q-SLICE v3 introduces user-driven configuration. Researchers can input custom values for shots, Shor’s N, Bell error rate and RNG bias. This enables flexible scenario modelling and comparative testing across environments. The harness includes layered fallbacks (Aer to BasicAer to Statevector) and simulated noise injection, ensuring robustness even when full quantum backends are unavailable. qslice_gui incoperates a GUI and a report format output which can be easily copied into a reports or analysed for further tests. qlsice_dashboard adds graphs and metrics explanation. Different versions for diffeent use case and prefereces.

The dashboard version may require the installation of matplotlib to function. Also make sure qslice_threat_harness_v3.py is also in the same directory as the dashboard so it can be imported easily.

Designed for both research and outreach, Q-SLICE outputs are interpretable, extensible and research ready. It supports examiner demonstration, post-quantum migration validation and professional communication of quantum security risks. Whether evidencing algorithmic collapse, entropy corruption, or entanglement disruption, Q-SLICE provides a clear, actionable foundation for quantum threat modelling.

