# Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
# NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
export P2P_PRODUCTION=true
export P2P_REQUIRE_AUTH=true
export P2P_HSM_REQUIRED=true
export DATABASE_URL="sqlite:///production.db"
export P2P_LOG_LEVEL=WARNING
export P2P_AUDIT_ENABLED=true
