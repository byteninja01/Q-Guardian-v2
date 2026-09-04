import math
import re

# Mosca countdown logic
# X + Y > Z (Threat exists)
# X: Migration time
# Y: Data shelf life (Sensitivity)
# Z: Time until CRQC

SENSITIVITY_SHELF_LIFE = {
    "S1": 10,  # 10 years (Core payment)
    "S2": 7,   # 7 years (KYC/Identity)
    "S3": 5,   # 5 years (Transaction History)
    "S4": 3,   # 3 years (Internal Business)
    "S5": 1    # 1 year (Public Info)
}

CRQC_TIMELINE_YEARS = {
    "worst_case": 5,  # 5 years until CRQC
    "best_case": 15   # 15 years until CRQC
}

def derive_migration_complexity(asset: dict) -> float:
    """
    Derives migration complexity (X) from the REAL algorithm / key-size /
    primitive surface surfaced by any scanner family (network-tls,
    static-source, container-image, binary).
    Returns a value between 0.5 and 4.0 years.
    """
    complexity = 0.5  # Base minimum

    algo = str(asset.get("algorithm", "")).upper()
    primitive = str(asset.get("primitive", "")).lower()
    try:
        key_size = int(asset.get("key_size") or 0)
    except (TypeError, ValueError):
        key_size = 0
    try:
        nist_level = int(asset.get("nist_quantum_security_level") or 0)
    except (TypeError, ValueError):
        nist_level = 0

    # Assets already PQC-deployed (or actively migrating) shrink X to the floor.
    if asset.get("is_pqc") or nist_level >= 1:
        return 0.5

    # ── Weak / legacy hash families (MD5, SHA-1) ──
    if "MD5" in algo or "SHA-1" in algo or re.search(r"\bSHA1\b", algo):
        complexity += 0.75
    elif primitive == "hash":
        complexity += 0.5

    # ── Legacy symmetric ciphers (DES/3DES/RC4) and unsafe modes (ECB) ──
    if re.search(r"(DES|3DES|RC4|RC2|BLOWFISH)", algo):
        complexity += 1.25
    elif "ECB" in algo:
        complexity += 0.75

    # ── Public-key families — key size matters for RSA/DSA ──
    if "RSA" in algo:
        complexity += 1.0
        if 0 < key_size < 2048:
            complexity += 0.75
        elif key_size >= 4096:
            complexity += 0.25
    elif re.search(r"\bDSA\b", algo) and "ECDSA" not in algo:
        complexity += 1.25
    elif "ECDSA" in algo:
        complexity += 0.5

    tls_ver = str(asset.get("tls_version", ""))
    if tls_ver in ("1.0", "1.1"):
        complexity += 1.0
    elif tls_ver == "1.2":
        complexity += 0.5

    tier = asset.get("sensitivity_tier", "S5")
    if tier in ("S1", "S2"):
        complexity += 0.75

    if not asset.get("forward_secrecy", True):
        complexity += 0.5

    return min(max(complexity, 0.5), 4.0)

def calculate_mosca_clocks(migration_complexity: float, sensitivity_tier: str):
    # X = migration_complexity (already in years: 0.5 to 4.0)
    x = migration_complexity
    y = SENSITIVITY_SHELF_LIFE.get(sensitivity_tier, 1)
    
    # Calculate days remaining until X+Y hits Z
    # Risk window onset: Z - (X + Y)
    
    z_worst = CRQC_TIMELINE_YEARS["worst_case"]
    z_best = CRQC_TIMELINE_YEARS["best_case"]
    
    days_remaining_worst = (z_worst - (x + y)) * 365.25
    days_remaining_best = (z_best - (x + y)) * 365.25
    
    risk_state = "SAFE"
    if days_remaining_worst <= 0:
        risk_state = "CRITICAL"
    elif days_remaining_worst < 365:
        risk_state = "WARNING"
    elif days_remaining_best < 365 * 3:
        risk_state = "MONITOR"
        
    return {
        "x_migration_years": x,
        "y_shelf_life": y,
        "days_remaining_worst": max(0, int(days_remaining_worst)),
        "days_remaining_best": int(days_remaining_best),
        "risk_state": risk_state
    }
