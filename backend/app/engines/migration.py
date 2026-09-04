"""
PQC Migration Playbook Engine for Q-Guardian-v2
Maps every algorithm family surfaced by Semgrep / Trivy / source / network
scanners (DES/3DES, RC4, AES-ECB, MD5, SHA-1, RSA, DSA, ECDSA, ECDH) to a
concrete, standards-aligned PQC transition path (FIPS 203 / 204 / 205).

Rule table is ordered: the FIRST matching rule wins.
"""

import re


def _is_pqc_algo(algo: str) -> bool:
    return bool(re.search(r"(ML-KEM|KYBER|ML-DSA|DILITHIUM|SLH-DSA|SPHINCS|FALCON)", algo, re.IGNORECASE))


def _matches(rule: dict, algo: str, key_size: int) -> bool:
    tokens = rule.get("tokens", [])
    if tokens and not any(t in algo for t in tokens):
        return False
    key_min = rule.get("key_min")
    key_max = rule.get("key_max")
    if key_min is not None and key_size < key_min:
        return False
    if key_max is not None and key_size > key_max:
        return False
    return True


# ── Ordered migration rule table (first match wins) ──────────────────────────
MIGRATION_RULES = [
    # 1. Already PQC / hybrid deployed
    {
        "tokens": ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS", "FALCON", "X25519MLKEM"],
        "target_algorithm": "Maintain: Hybrid PQC (FIPS 203 / 204) already deployed",
        "nist_standard": "NIST FIPS 203 / FIPS 204 / FIPS 205",
        "effort_estimate": "None — monitor algorithm agility (crypto-agility program)",
        "risk_reduction": "Quantum-safe (Store-Now-Decrypt-Later mitigated)",
        "config_snippet": "# Continue hybrid handshake; track upstream NIST profile changes.\nssl_ecdh_curve X25519MLKEM768:prime256v1;",
    },
    # 2. Weak / legacy hashes
    {
        "tokens": ["MD5"],
        "target_algorithm": "SHA-256 / SHA3-256 (FIPS 180-4 / FIPS 202)",
        "nist_standard": "NIST FIPS 180-4 / FIPS 202",
        "effort_estimate": "2 to 4 weeks (re-hash + data migration)",
        "risk_reduction": "High (collision + Grover speedup mitigated)",
        "config_snippet": 'digest = hashlib.sha256(data).hexdigest()  # was hashlib.md5',
        "note": "MD5 is broken for collision resistance and halved by Grover's algorithm.",
    },
    {
        "tokens": ["SHA-1", "SHA1"],
        "target_algorithm": "SHA-256 / SHA-384 / SHA3-256",
        "nist_standard": "NIST FIPS 180-4 / FIPS 202",
        "effort_estimate": "2 to 4 weeks",
        "risk_reduction": "High (chosen-prefix collision + Grover speedup mitigated)",
        "config_snippet": "digest = hashlib.sha256(data).digest()  # was hashlib.sha1",
        "note": "SHA-1 is deprecated by NIST (SP 800-131A Rev.2); 80-bit strength is quantum-vulnerable.",
    },
    # 3. Legacy symmetric ciphers
    {
        "tokens": ["3DES", "DES", "RC4", "RC2", "BLOWFISH"],
        "target_algorithm": "AES-256-GCM / ChaCha20-Poly1305",
        "nist_standard": "NIST FIPS 197 / SP 800-38D / RFC 8439",
        "effort_estimate": "1 to 3 weeks (cipher + mode rewrite)",
        "risk_reduction": "Critical (56/112-bit keys broken by brute force; SWEET32/BEAST classes)",
        "config_snippet": 'cipher = AES.new(key_32b, AES.MODE_GCM)  # was DES/3DES',
    },
    # 4. AES in unsafe ECB mode
    {
        "tokens": ["ECB"],
        "target_algorithm": "AES-256-GCM (authenticated)",
        "nist_standard": "NIST SP 800-38D",
        "effort_estimate": "1 to 2 weeks (mode swap + IV handling)",
        "risk_reduction": "High (pattern leakage eliminated)",
        "config_snippet": "cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))  # was AES.MODE_ECB",
    },
    # 5. DSA (discrete-log, 1024/2048 bit)
    {
        "tokens": ["DSA"],
        "target_algorithm": "ML-DSA-65 (FIPS 204) or hybrid ECDSA P-256 + ML-DSA-65",
        "nist_standard": "NIST FIPS 204 (ML-DSA) / SP 800-186",
        "effort_estimate": "2 to 6 weeks (key + signature verification roll-out)",
        "risk_reduction": "Critical (DSA broken by Shor's algorithm)",
        "config_snippet": "# Replace KeyPairGenerator(\"DSA\") with ML-DSA-65 via BouncyCastle PQC provider.",
    },
    # 6. ECDSA signatures (smaller migration lift than RSA/DSA)
    {
        "tokens": ["ECDSA"],
        "target_algorithm": "Hybrid: ECDSA P-256 + ML-DSA-65, or SLH-DSA (hash-based)",
        "nist_standard": "NIST FIPS 186-5 / FIPS 204 / FIPS 205",
        "effort_estimate": "1 to 4 weeks (library + CA/key rollover)",
        "risk_reduction": "High (Shor's algorithm on ECC curves)",
        "config_snippet": "# Enroll dual-signature (ECDSA P-256 + ML-DSA-65) in signing stack.",
    },
    # 7. RSA by key size
    {
        "tokens": ["RSA"],
        "key_min": 2048,
        "target_algorithm": "Hybrid: RSA-3072/4096 + ML-KEM-768 (or pure ML-KEM-768)",
        "nist_standard": "NIST FIPS 203 / SP 800-52r2 / SP 800-56Br2",
        "effort_estimate": "4 to 8 weeks (certificate authority + key ceremony)",
        "risk_reduction": "High (Shor's algorithm breaks RSA factoring)",
        "config_snippet": "ssl_ecdh_curve X25519MLKEM768:prime256v1;\nssl_protocols TLSv1.3;",
    },
    {
        "tokens": ["RSA"],
        "key_min": 1,
        "key_max": 2047,
        "target_algorithm": "ML-KEM-768 (FIPS 203) hybrid — RSA-1024/512 is URGENT",
        "nist_standard": "NIST FIPS 203 / SP 800-52r2",
        "effort_estimate": "URGENT: 1 to 2 weeks (interim RSA-2048+, then ML-KEM-768)",
        "risk_reduction": "Critical (80-bit RSA is classically breakable)",
        "config_snippet": "openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048  # interim\n# then migrate keys/certs to ML-KEM-768 hybrid.",
        "note": "Sub-2048-bit RSA is broken classically; treat as P0 finding.",
    },
    # 8. Generic ECC key exchange (ECDH / P-256 etc.)
    {
        "tokens": ["ECDH", "P-256", "P-384", "X25519", "ECC"],
        "target_algorithm": "Hybrid: X25519MLKEM768 key exchange",
        "nist_standard": "NIST FIPS 203 / SP 800-186",
        "effort_estimate": "1 to 3 weeks (TLS 1.3 curve rollout)",
        "risk_reduction": "High (Shor's algorithm on ECC)",
        "config_snippet": "ssl_ecdh_curve X25519MLKEM768:prime256v1;",
    },
]


def _apply_tls_notes(recommendation: dict, tls_version: str):
    """TLS < 1.3 always tightens effort and NIST standard references."""
    if tls_version and tls_version != "1.3":
        recommendation["nist_standard"] += " & NIST SP 800-52 (TLS 1.3)"
        recommendation["effort_estimate"] = "Urgent: protocol + crypto upgrade (1 week head start)"
        recommendation["config_snippet"] = (
            "ssl_protocols TLSv1.3;\nssl_prefer_server_ciphers off;\n"
            + (recommendation.get("config_snippet") or "")
        ).strip()


def get_migration_playbook(asset: dict):
    algorithm = str(asset.get("algorithm", "RSA-2048")).upper()
    tls_version = str(asset.get("tls_version", "1.2"))
    try:
        key_size = int(asset.get("key_size") or 0)
    except (TypeError, ValueError):
        key_size = 0

    recommendation = {
        "current_state": f"{algorithm} {tls_version}",
        "target_algorithm": "ML-KEM-768 (FIPS 203)",
        "nist_standard": "FIPS 203 / NIST SP 800-52r2",
        "effort_estimate": "2 to 4 weeks",
        "risk_reduction": "High (Quantum-Safe Key Exchange)",
        "config_snippet": "",
    }

    matched = None
    if not _is_pqc_algo(algorithm):
        for rule in MIGRATION_RULES:
            if _matches(rule, algorithm, key_size):
                matched = rule
                break

    if matched:
        recommendation["target_algorithm"] = matched["target_algorithm"]
        recommendation["nist_standard"] = matched["nist_standard"]
        recommendation["effort_estimate"] = matched["effort_estimate"]
        recommendation["risk_reduction"] = matched["risk_reduction"]
        recommendation["config_snippet"] = matched["config_snippet"]
        if matched.get("note"):
            recommendation["note"] = matched["note"]
    elif _is_pqc_algo(algorithm):
        recommendation["target_algorithm"] = "Maintain: Hybrid PQC (FIPS 203 / 204) already deployed"
        recommendation["effort_estimate"] = "None — monitor algorithm agility (crypto-agility program)"
        recommendation["risk_reduction"] = "Quantum-safe (Store-Now-Decrypt-Later mitigated)"
    else:
        # Unknown algorithm family: conservative PQC default
        recommendation["note"] = (
            "Algorithm family not in migration table — review primitive and "
            "align to NIST IR 8547 transition profile."
        )

    _apply_tls_notes(recommendation, tls_version)
    return recommendation
