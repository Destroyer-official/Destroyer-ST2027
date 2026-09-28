"""Legacy P2P prototype quarantine (pre-2027, pre-CNSA-strict data plane).

DO NOT USE for production or TOP SECRET traffic. Both modules fail closed in
TS/PROD env (LEGACY QUARANTINE guard in SecureP2PChat.__init__). The supported
2027 pipeline is secure_transmit_2027.py + rust_data_plane (secure-transmit).

Import path (tests/orchestrators only):
    from archive.legacy_prototype.secure_p2p import SecureP2PChat
Direct execution requires repo root on sys.path, e.g.:
    PYTHONPATH=<repo-root> python archive/legacy_prototype/secure_p2.py [...]
"""
