# Dynamic Q-TRI Weighting Matrix (Weights must sum to 1.0)
# S1/S2: Critical (PQC heavily weighted)
# S3: Balanced
# S4/S5: Operational (PQC is a bonus, not a requirement)

TIER_CONFIG = {
    "S1": {"tls": 0.25, "fs": 0.20, "hygiene": 0.20, "cipher": 0.15, "pqc": 0.20},
    "S2": {"tls": 0.25, "fs": 0.20, "hygiene": 0.20, "cipher": 0.15, "pqc": 0.20},
    "S3": {"tls": 0.30, "fs": 0.20, "hygiene": 0.20, "cipher": 0.20, "pqc": 0.10},
    "S4": {"tls": 0.35, "fs": 0.25, "hygiene": 0.25, "cipher": 0.15, "pqc": 0.00}, # PQC 0 as it's bonus only
    "S5": {"tls": 0.35, "fs": 0.25, "hygiene": 0.25, "cipher": 0.15, "pqc": 0.00},
}

def calculate_qtri_score(data: dict):
    # Determine Tier (Default to S5 if missing)
    tier = data.get("sensitivity_tier", "S5")
    config = TIER_CONFIG.get(tier, TIER_CONFIG["S5"])
    
    # Check if host was even reachable
    if data.get("tls_version", "Unknown") == "Unknown":
        return 0

    # 1. TLS Score (0.0 to 1.0)
    tls_ver = data.get("tls_version", "1.0")
    tls_val = 1.0 if tls_ver == "1.3" else (0.6 if tls_ver == "1.2" else 0.2)
    
    # 2. Forward Secrecy (0.0 or 1.0)
    fs_val = 1.0 if data.get("forward_secrecy", False) else 0.0
    
    # 3. Cert Hygiene (0.0 to 1.0)
    hygiene_val = 0.0
    if data.get("cert_valid", False):
        keysize = data.get("key_size", 0)
        if keysize >= 4096: hygiene_val = 1.0
        elif keysize >= 2048: hygiene_val = 0.7
        else: hygiene_val = 0.3
        
    # 4. Cipher Strength (0.0 to 1.0)
    cipher = data.get("cipher_suite", "")
    cipher_val = 1.0 if ("GCM" in cipher or "CHACHA20" in cipher) else 0.4
    
    # 5. PQC Adoption (0.0 or 1.0)
    pqc_val = 1.0 if data.get("is_pqc", False) else 0.0
    
    # Calculate Weighted Average
    final_score = (
        (tls_val * config["tls"]) +
        (fs_val * config["fs"]) +
        (hygiene_val * config["hygiene"]) +
        (cipher_val * config["cipher"]) +
        (pqc_val * config["pqc"])
    ) * 100
    
    # 🎁 BONUS: For S4/S5, PQC acts as a raw bonus pts provider since it's not in the baseline
    if tier in ("S4", "S5") and pqc_val == 1.0:
        final_score += 15 # 15 point boost for early adoption on low-priority endpoints
        
    # Compliance modifier
    if data.get("policy_compliant", False):
        final_score += 5
        
    return max(0, min(100, int(final_score)))

def calculate_cyber_rating(qtri_scores: list):
    if not qtri_scores:
        return 0
    avg_score = sum(qtri_scores) / len(qtri_scores)
    # Scale 0-100 to 0-1000
    return int(avg_score * 10)
