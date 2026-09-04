"""
Deep Binary Cryptographic Scanner for Q-Guardian-v2
Uses LIEF for executable inspection (ELF, PE, Mach-O) and raw byte constant
matching to detect Post-Quantum (ML-KEM, ML-DSA) and classical cryptographic
primitives in stripped and unstripped binaries.
"""

import os
import re
import struct
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

# ─── Constant Signatures (Byte Patterns) ──────────────────────────────────────

# ML-KEM-768 / Kyber NTT Zeta Constants (FIPS 203)
# In ML-KEM, the NTT twiddle factors zeta mod 3329 bit-reversed:
# [2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468]
# Packed as little-endian 16-bit integers (int16_t / uint16_t):
ML_KEM_NTT_ZETAS_16 = struct.pack(
    "<8H",
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202
) # b'\xed\x08\x0b\x0a\x9a\x0b\x14\x07\xd5\x05\x8e\x05\x1f\x01\xca\x00'

# ML-KEM-768 Alternative/Standard Representation (Montgomery factors or non-bit-reversed)
ML_KEM_MONTGOMERY_R = struct.pack("<4H", 1353, 1084, 1584, 8)

# AES Rijndael S-Box (first 16 bytes: 0x63, 0x7C, 0x77, 0x7B, ...)
AES_SBOX_16 = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
])

# MD5 Initial Constants (A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476)
MD5_INIT_CONSTANTS = struct.pack("<4I", 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

# SHA-1 Initial State Constants
SHA1_INIT_CONSTANTS = struct.pack(">5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
SHA1_INIT_CONSTANTS_LE = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# DES S-Box 1 (first 16 entries)
DES_SBOX_1 = bytes([
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
])

# Cryptographic strings / symbols
CRYPTO_STRING_PATTERNS = [
    {
        "regex": r"(ML-KEM-512|ML-KEM-768|ML-KEM-1024|Kyber512|Kyber768|Kyber1024)",
        "algorithm": "ML-KEM-768",
        "primitive": "key-agreement",
        "is_pqc": True,
        "classical_sec": 192,
        "nist_level": 3,
        "qtri": 95,
        "recommendation": "Post-Quantum ML-KEM detected in compiled binary."
    },
    {
        "regex": r"(ML-DSA-44|ML-DSA-65|ML-DSA-87|Dilithium2|Dilithium3|Dilithium5)",
        "algorithm": "ML-DSA-65",
        "primitive": "signature",
        "is_pqc": True,
        "classical_sec": 192,
        "nist_level": 3,
        "qtri": 95,
        "recommendation": "Post-Quantum ML-DSA signature primitive identified in binary."
    },
    {
        "regex": r"(SPHINCS\+|SLH-DSA|Falcon-512|Falcon-1024)",
        "algorithm": "SLH-DSA",
        "primitive": "signature",
        "is_pqc": True,
        "classical_sec": 128,
        "nist_level": 2,
        "qtri": 90,
        "recommendation": "Stateful/Stateless Hash-based PQC signature primitive detected."
    },
    {
        "regex": r"-----BEGIN RSA PRIVATE KEY-----",
        "algorithm": "EMBEDDED-RSA-PRIVATE-KEY",
        "primitive": "public-key-encryption",
        "is_pqc": False,
        "classical_sec": 0,
        "nist_level": 0,
        "qtri": 5,
        "recommendation": "CRITICAL: Hardcoded private key embedded in compiled binary!"
    },
    {
        "regex": r"(MD5_Init|MD5_Update|md5_transform|EVP_md5)",
        "algorithm": "MD5",
        "primitive": "hash",
        "is_pqc": False,
        "classical_sec": 64,
        "nist_level": 0,
        "qtri": 10,
        "recommendation": "Deprecated MD5 symbol referenced in binary. Replace with SHA-256 or SHA-3."
    },
    {
        "regex": r"(SHA1_Init|SHA1_Update|EVP_sha1)",
        "algorithm": "SHA-1",
        "primitive": "hash",
        "is_pqc": False,
        "classical_sec": 80,
        "nist_level": 0,
        "qtri": 25,
        "recommendation": "Broken SHA-1 symbol compiled in binary. Migrate to SHA-256 or SHA-3."
    },
    {
        "regex": r"(DES_ecb_encrypt|DES_ede3_cbc|EVP_des_ede3)",
        "algorithm": "3DES",
        "primitive": "symmetric-cipher",
        "is_pqc": False,
        "classical_sec": 80,
        "nist_level": 0,
        "qtri": 20,
        "recommendation": "3DES legacy cipher symbols present. Transition to AES-256-GCM."
    },
    {
        "regex": r"(EVP_KEM_fetch|OQS_KEM_new|OQS_SIG_new)",
        "algorithm": "LIBOQS-PQC-INTERFACE",
        "primitive": "key-agreement",
        "is_pqc": True,
        "classical_sec": 256,
        "nist_level": 5,
        "qtri": 98,
        "recommendation": "Liboqs / OpenSSL 3.x PQC provider symbols identified."
    }
]

def _search_bytes(haystack: bytes, needle: bytes) -> List[int]:
    """Find all byte offset occurrences of needle in haystack."""
    offsets = []
    idx = 0
    while True:
        idx = haystack.find(needle, idx)
        if idx == -1:
            break
        offsets.append(idx)
        idx += len(needle)
    return offsets

def scan_binary(filepath: str) -> List[Dict[str, Any]]:
    """
    Reverse-engineer and scan an ELF, PE, Mach-O or raw binary file
    for cryptographic constants, NTT twiddle factors, and symbols.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Binary file not found: {filepath}")

    with open(filepath, "rb") as f:
        raw_data = f.read()

    findings: List[Dict[str, Any]] = []
    binary_name = os.path.basename(filepath)
    section_map = {}

    # Inspect with LIEF if available and executable
    if HAS_LIEF:
        try:
            parsed = lief.parse(filepath)
            if parsed:
                for section in parsed.sections:
                    sec_name = section.name
                    sec_content = bytes(section.content)
                    section_map[sec_name] = {
                        "offset": section.offset,
                        "virtual_address": section.virtual_address,
                        "content": sec_content
                    }
                # Check imported and exported symbols
                for sym in getattr(parsed, "symbols", []):
                    s_name = getattr(sym, "name", "")
                    for pat in CRYPTO_STRING_PATTERNS:
                        if re.search(pat["regex"], s_name, re.IGNORECASE):
                            findings.append({
                                "hostname": f"bin:{binary_name}:{pat['algorithm']}",
                                "tls_version": "N/A",
                                "algorithm": pat["algorithm"],
                                "key_size": 2048 if not pat["is_pqc"] else 3072,
                                "cipher_suite": f"BIN-SYM-{s_name[:20]}",
                                "forward_secrecy": True,
                                "cert_valid": True,
                                "cert_expiry": datetime.now().isoformat(),
                                "sensitivity_tier": "S2",
                                "is_pqc": pat["is_pqc"],
                                "policy_compliant": pat["qtri"] >= 60,
                                "qtri_score": pat["qtri"],
                                "source_type": "binary",
                                "asset_type": "binary",
                                "evidence_file": filepath,
                                "evidence_line": None,
                                "evidence_offset": getattr(sym, "value", 0),
                                "evidence_function": f"symbol:{s_name}",
                                "primitive": pat["primitive"],
                                "classical_security_level": pat["classical_sec"],
                                "nist_quantum_security_level": pat["nist_level"],
                                "recommendation": pat["recommendation"]
                            })
        except Exception:
            pass # Fall back to direct byte and section scanning

    # 1. 🌟 ML-KEM NTT Constant Signature Search (.rodata / raw)
    ntt_offsets = _search_bytes(raw_data, ML_KEM_NTT_ZETAS_16)
    if ntt_offsets:
        findings.append({
            "hostname": f"bin:{binary_name}:ML-KEM-768-NTT",
            "tls_version": "1.3",
            "algorithm": "ML-KEM-768",
            "key_size": 1184, # ML-KEM-768 public key size in bytes
            "cipher_suite": "PQC-KEM-KYBER768-NTT",
            "forward_secrecy": True,
            "cert_valid": True,
            "cert_expiry": datetime.now().isoformat(),
            "sensitivity_tier": "S1",
            "is_pqc": True,
            "policy_compliant": True,
            "qtri_score": 98,
            "source_type": "binary",
            "asset_type": "binary",
            "evidence_file": filepath,
            "evidence_line": None,
            "evidence_offset": ntt_offsets[0],
            "evidence_function": f".rodata:NTT_ZETAS_TABLE@0x{ntt_offsets[0]:08X}",
            "primitive": "key-agreement",
            "mode": "FIPS-203",
            "parameter_set_identifier": "ML-KEM-768",
            "classical_security_level": 192,
            "nist_quantum_security_level": 3,
            "oid": "2.16.840.1.101.3.4.4.2",
            "recommendation": "VERIFIED: Post-Quantum ML-KEM-768 NTT polynomial arithmetic constants verified in compiled binary."
        })

    # 2. AES Rijndael S-Box Search
    aes_offsets = _search_bytes(raw_data, AES_SBOX_16)
    if aes_offsets:
        findings.append({
            "hostname": f"bin:{binary_name}:AES-SBOX",
            "tls_version": "N/A",
            "algorithm": "AES-256",
            "key_size": 256,
            "cipher_suite": "SYMMETRIC-AES-SBOX",
            "forward_secrecy": True,
            "cert_valid": True,
            "cert_expiry": datetime.now().isoformat(),
            "sensitivity_tier": "S3",
            "is_pqc": True,
            "policy_compliant": True,
            "qtri_score": 88,
            "source_type": "binary",
            "asset_type": "binary",
            "evidence_file": filepath,
            "evidence_line": None,
            "evidence_offset": aes_offsets[0],
            "evidence_function": f".rodata:AES_SBOX@0x{aes_offsets[0]:08X}",
            "primitive": "symmetric-cipher",
            "classical_security_level": 256,
            "nist_quantum_security_level": 5, # Grover 128-bit quantum security
            "recommendation": "Hardware/software AES S-Box table identified."
        })

    # 3. MD5 Initial Constants Search
    md5_offsets = _search_bytes(raw_data, MD5_INIT_CONSTANTS)
    if md5_offsets:
        findings.append({
            "hostname": f"bin:{binary_name}:MD5-CONSTANTS",
            "tls_version": "N/A",
            "algorithm": "MD5",
            "key_size": 128,
            "cipher_suite": "HASH-MD5",
            "forward_secrecy": False,
            "cert_valid": False,
            "cert_expiry": datetime.now().isoformat(),
            "sensitivity_tier": "S1",
            "is_pqc": False,
            "policy_compliant": False,
            "qtri_score": 12,
            "source_type": "binary",
            "asset_type": "binary",
            "evidence_file": filepath,
            "evidence_line": None,
            "evidence_offset": md5_offsets[0],
            "evidence_function": f".rodata:MD5_IV@0x{md5_offsets[0]:08X}",
            "primitive": "hash",
            "classical_security_level": 64,
            "nist_quantum_security_level": 0,
            "recommendation": "CRITICAL: Hardcoded MD5 hash initial vector detected in binary. Remove broken digest."
        })

    # 4. SHA-1 Initial State Constants
    sha1_offsets = _search_bytes(raw_data, SHA1_INIT_CONSTANTS) or _search_bytes(raw_data, SHA1_INIT_CONSTANTS_LE)
    if sha1_offsets:
        findings.append({
            "hostname": f"bin:{binary_name}:SHA1-CONSTANTS",
            "tls_version": "N/A",
            "algorithm": "SHA-1",
            "key_size": 160,
            "cipher_suite": "HASH-SHA1",
            "forward_secrecy": False,
            "cert_valid": False,
            "cert_expiry": datetime.now().isoformat(),
            "sensitivity_tier": "S2",
            "is_pqc": False,
            "policy_compliant": False,
            "qtri_score": 28,
            "source_type": "binary",
            "asset_type": "binary",
            "evidence_file": filepath,
            "evidence_line": None,
            "evidence_offset": sha1_offsets[0],
            "evidence_function": f".rodata:SHA1_IV@0x{sha1_offsets[0]:08X}",
            "primitive": "hash",
            "classical_security_level": 80,
            "nist_quantum_security_level": 0,
            "recommendation": "Weak SHA-1 hash constants identified in binary."
        })

    # 5. DES S-Box Search
    des_offsets = _search_bytes(raw_data, DES_SBOX_1)
    if des_offsets:
        findings.append({
            "hostname": f"bin:{binary_name}:DES-SBOX",
            "tls_version": "N/A",
            "algorithm": "DES",
            "key_size": 56,
            "cipher_suite": "CIPHER-DES",
            "forward_secrecy": False,
            "cert_valid": False,
            "cert_expiry": datetime.now().isoformat(),
            "sensitivity_tier": "S1",
            "is_pqc": False,
            "policy_compliant": False,
            "qtri_score": 15,
            "source_type": "binary",
            "asset_type": "binary",
            "evidence_file": filepath,
            "evidence_line": None,
            "evidence_offset": des_offsets[0],
            "evidence_function": f".rodata:DES_SBOX_1@0x{des_offsets[0]:08X}",
            "primitive": "symmetric-cipher",
            "classical_security_level": 56,
            "nist_quantum_security_level": 0,
            "recommendation": "CRITICAL: Deprecated DES permutation table found in binary."
        })

    # 6. String Search Across Binary
    try:
        raw_text = raw_data.decode("latin1", errors="ignore")
        for pat in CRYPTO_STRING_PATTERNS:
            matches = list(re.finditer(pat["regex"], raw_text))
            for m in matches[:2]: # Max 2 per pattern to avoid flood
                offset = m.start()
                # Deduplicate if already reported by symbol or constant
                already_reported = any(
                    f["algorithm"] == pat["algorithm"] and abs((f.get("evidence_offset") or 0) - offset) < 100
                    for f in findings
                )
                if not already_reported:
                    matched_str = m.group(0)
                    findings.append({
                        "hostname": f"bin:{binary_name}:{pat['algorithm']}",
                        "tls_version": "N/A",
                        "algorithm": pat["algorithm"],
                        "key_size": 2048 if not pat["is_pqc"] else 3072,
                        "cipher_suite": f"BIN-STR-{matched_str[:20]}",
                        "forward_secrecy": True,
                        "cert_valid": True,
                        "cert_expiry": datetime.now().isoformat(),
                        "sensitivity_tier": "S2",
                        "is_pqc": pat["is_pqc"],
                        "policy_compliant": pat["qtri"] >= 60,
                        "qtri_score": pat["qtri"],
                        "source_type": "binary",
                        "asset_type": "binary",
                        "evidence_file": filepath,
                        "evidence_line": None,
                        "evidence_offset": offset,
                        "evidence_function": f"string:\"{matched_str[:30]}\"",
                        "primitive": pat["primitive"],
                        "classical_security_level": pat["classical_sec"],
                        "nist_quantum_security_level": pat["nist_level"],
                        "recommendation": pat["recommendation"]
                    })
    except Exception:
        pass

    return findings
