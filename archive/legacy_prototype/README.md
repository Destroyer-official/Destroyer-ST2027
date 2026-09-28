# Quarantined Legacy Research Prototypes

## Security Notice & Quarantine Charter

The files in this directory (`secure_p2.py` and `secure_p2p.py`) represent the original 13,000-line multi-party chat research testbed developed during initial exploration phases.

### Operational Classification: QUARANTINED (NON-OPERATIONAL)

1. **Non-Compliance with CNSA Suite 2.0:**
   These legacy prototypes contain non-CNSA 2.0 algorithms (e.g. Falcon-1024, Classic McEliece, SPHINCS+) and pre-standardized hybrid handshakes. They **MUST NOT** be used for classified or high-assurance sovereign transmissions.

2. **Isolated Execution Boundary:**
   The 2027 sovereign defense pipeline is strictly orchestrated by [`secure_transmit_2027.py`](../../secure_transmit_2027.py) and the standalone native binary [`rust_data_plane/`](../../rust_data_plane/). Neither imports or relies upon these legacy prototypes.

3. **Retention Rationale:**
   These files are retained solely for academic reference, regression testing against legacy network captures, and comparative analysis of Double Ratchet state transitions.
