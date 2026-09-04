# RBI CSF 2.0 Mapping Logic
# Controls:
# - C.1: Cryptography Controls - Key Management
# - V.3: Vulnerability Management - Patching
# - T.2: Third Party Risk - Crypto Dependencies

def map_to_rbi_controls(assets: list):
    mapping = []
    for asset in assets:
        findings = []
        if asset.get("tls_version") != "1.3":
            findings.append({
                "control": "RBI CSF 2.0 Annexure 1, Section 4.2",
                "description": "Insecure TLS protocol version in use.",
                "remediation": "Upgrade to TLS 1.3 with PQC-ready cipher suites."
            })
        if "RSA" in asset.get("algorithm", "") and asset.get("key_size", 0) < 2048:
            findings.append({
                "control": "RBI CSF 2.0 Annexure 1, Section 5.1",
                "description": "Weak cryptographic algorithm/key size.",
                "remediation": "Replace with 4096-bit RSA or PQC-equivalent (ML-DSA)."
            })
        if not asset.get("forward_secrecy", False):
            findings.append({
                "control": "RBI CSF 2.0 Annexure 4, Section 2.3",
                "description": "Lack of Perfect Forward Secrecy (PFS) - HNDL Risk.",
                "remediation": "Enable ECDHE or DHE key exchange mechanism."
            })
        
        if findings:
            mapping.append({
                "hostname": asset["hostname"],
                "findings": findings
            })
    return mapping
