def get_migration_playbook(asset: dict):
    algorithm = asset.get("algorithm", "RSA-2048")
    tls_version = asset.get("tls_version", "1.2")
    
    recommendation = {
        "current_state": f"{algorithm} {tls_version}",
        "target_algorithm": "ML-KEM-768 (FIPS 203)",
        "nist_standard": "FIPS 203 / NIST SP 800-52r2",
        "effort_estimate": "2 to 4 weeks",
        "risk_reduction": "High (Quantum-Safe Key Exchange)",
        "config_snippet": ""
    }
    
    if "RSA" in algorithm:
        recommendation["target_algorithm"] = "Hybrid: RSA + ML-KEM-768"
        recommendation["config_snippet"] = """
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519MLKEM768:prime256v1; # Hybrid key exchange
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=63072000" always;
        """.strip()
    elif "ECC" in algorithm:
        recommendation["target_algorithm"] = "Hybrid: ECC + ML-KEM-512"
        recommendation["effort_estimate"] = "1 to 3 weeks"
        recommendation["config_snippet"] = """
ssl_protocols TLSv1.3;
ssl_ecdh_curve SecP256r1MLKEM512:prime256v1;
        """.strip()
    
    if tls_version != "1.3":
        recommendation["nist_standard"] += " & NIST SP 800-52"
        recommendation["effort_estimate"] = "Urgent: 1 week (Protocol Upgrade)"

    return recommendation
