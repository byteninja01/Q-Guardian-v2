import os
import re
import ast
import json
from datetime import datetime

# Rules catalog mapping static code patterns to CBOM Cryptographic Asset fields
PYTHON_STATIC_RULES = [
    {
        "id": "PY-CRYPTO-MD5",
        "pattern": r"hashlib\.md5\(",
        "algorithm": "MD5",
        "key_size": 128,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 20,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace MD5 with SHA-256 or SHA-3 (FIPS 202) digest."
    },
    {
        "id": "PY-CRYPTO-SHA1",
        "pattern": r"hashlib\.sha1\(",
        "algorithm": "SHA-1",
        "key_size": 160,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 35,
        "classical_security_level": 64,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace SHA-1 with SHA-256, SHA-512, or SHA3-256."
    },
    {
        "id": "PY-RSA-WEAK-GEN",
        "pattern": r"RSA\.generate\(\s*(1024|512)\s*\)",
        "algorithm": "RSA-1024",
        "key_size": 1024,
        "primitive": "public-key-encryption",
        "asset_type": "library",
        "sensitivity_tier": "S1",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 15,
        "classical_security_level": 80,
        "nist_quantum_security_level": 0,
        "recommendation": "Upgrade to RSA-4096 or Hybrid ML-KEM-768 key encapsulation."
    },
    {
        "id": "PY-RSA-2048-GEN",
        "pattern": r"RSA\.generate\(\s*2048\s*\)",
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": "public-key-encryption",
        "asset_type": "library",
        "sensitivity_tier": "S2",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 50,
        "classical_security_level": 112,
        "nist_quantum_security_level": 0,
        "recommendation": "Plan migration to ML-KEM-768 (FIPS 203) per NIST IR 8547 timeline."
    },
    {
        "id": "PY-SSL-LEGACY-PROTO",
        "pattern": r"ssl\.PROTOCOL_(SSLv23|TLSv1|TLSv1_1)",
        "algorithm": "TLSv1.0",
        "key_size": 1024,
        "primitive": "key-agreement",
        "asset_type": "service",
        "sensitivity_tier": "S1",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 10,
        "classical_security_level": 80,
        "nist_quantum_security_level": 0,
        "recommendation": "Upgrade SSLContext to ssl.PROTOCOL_TLS_CLIENT / TLS 1.3 with PFS."
    },
    {
        "id": "PY-WEAK-CIPHER-DES",
        "pattern": r"algorithms\.(DES|TripleDES|ARC4|Blowfish)\(",
        "algorithm": "DES/ARC4-Legacy",
        "key_size": 56,
        "primitive": "symmetric-cipher",
        "asset_type": "library",
        "sensitivity_tier": "S2",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 10,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace legacy symmetric ciphers with AES-256-GCM."
    },
    {
        "id": "PY-HARDCODED-PRIVATE-KEY",
        "pattern": r"-----BEGIN (RSA )?PRIVATE KEY-----",
        "algorithm": "Hardcoded-Private-Key",
        "key_size": 2048,
        "primitive": "public-key-encryption",
        "asset_type": "secret",
        "sensitivity_tier": "S1",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 5,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Remove hardcoded keys immediately. Store keys in Cloud KMS or Hardware Security Module (HSM)."
    }
]

JS_STATIC_RULES = [
    {
        "id": "JS-CRYPTO-MD5",
        "pattern": r"crypto\.createHash\(\s*['\"]md5['\"]\s*\)",
        "algorithm": "MD5",
        "key_size": 128,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 20,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace Node.js md5 hash with sha256 or sha512."
    },
    {
        "id": "JS-CRYPTO-SHA1",
        "pattern": r"crypto\.createHash\(\s*['\"]sha1['\"]\s*\)",
        "algorithm": "SHA-1",
        "key_size": 160,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 35,
        "classical_security_level": 64,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace sha1 hash with sha256 or sha3-256."
    }
]

class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, lines: list):
        self.filepath = filepath
        self.lines = lines
        self.findings = []

    def visit_Call(self, node):
        call_str = ""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                call_str = f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                call_str = f"{getattr(node.func.value.value, 'id', '')}.{node.func.value.attr}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            call_str = node.func.id

        for rule in PYTHON_STATIC_RULES:
            if re.search(rule["pattern"], call_str):
                line_no = getattr(node, 'lineno', 1)
                self.findings.append({
                    "rule": rule,
                    "file": self.filepath,
                    "line": line_no,
                    "function": "call_scope",
                    "code_snippet": self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""
                })
        self.generic_visit(node)

def scan_file_static(filepath: str) -> list:
    """
    Scans a single source code file using AST parsing (Python) + regex pattern matching.
    Returns list of discovered cryptographic assets.
    """
    if not os.path.exists(filepath):
        return []

    findings = []
    rel_path = os.path.normpath(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return []

    ext = os.path.splitext(filepath)[1].lower()

    # 1. AST Analysis for Python Files
    if ext == ".py":
        try:
            tree = ast.parse(content, filename=filepath)
            visitor = PythonASTVisitor(rel_path, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception:
            pass

    # 2. Regex Pattern Matching
    rules_to_check = PYTHON_STATIC_RULES if ext == ".py" else (JS_STATIC_RULES if ext in (".js", ".ts", ".jsx", ".tsx") else PYTHON_STATIC_RULES + JS_STATIC_RULES)
    
    existing_locations = {(f["file"], f["line"], f["rule"]["id"]) for f in findings}

    for line_idx, line in enumerate(lines, start=1):
        for rule in rules_to_check:
            if re.search(rule["pattern"], line):
                loc_key = (rel_path, line_idx, rule["id"])
                if loc_key not in existing_locations:
                    existing_locations.add(loc_key)
                    findings.append({
                        "rule": rule,
                        "file": rel_path,
                        "line": line_idx,
                        "function": "source_location",
                        "code_snippet": line.strip()
                    })

    # 3. Dependency Manifest Analysis
    filename = os.path.basename(filepath).lower()
    if filename == "requirements.txt":
        if "cryptography<3.0" in content:
            findings.append({
                "rule": {
                    "id": "MANIFEST-OLD-CRYPTOGRAPHY",
                    "algorithm": "Legacy-PyCA-Cryptography",
                    "key_size": 1024,
                    "primitive": "library",
                    "asset_type": "library",
                    "sensitivity_tier": "S2",
                    "is_pqc": False,
                    "policy_compliant": False,
                    "qtri_score": 30,
                    "classical_security_level": 80,
                    "nist_quantum_security_level": 0,
                    "recommendation": "Upgrade pyca/cryptography package to version 42.0+ for ML-KEM FIPS 203 support."
                },
                "file": rel_path,
                "line": 1,
                "function": "manifest_dependency",
                "code_snippet": "cryptography<3.0"
            })

    # Map findings into unified asset dictionary format
    discovered_assets = []
    for item in findings:
        r = item["rule"]
        hostname_label = f"static::{os.path.basename(item['file'])}:{item['line']}"
        discovered_assets.append({
            "hostname": hostname_label,
            "tls_version": "N/A",
            "algorithm": r["algorithm"],
            "key_size": r["key_size"],
            "cipher_suite": "AST_STATIC_SCAN",
            "forward_secrecy": False,
            "cert_valid": True,
            "cert_expiry": datetime.now().isoformat(),
            "sensitivity_tier": r["sensitivity_tier"],
            "is_pqc": r["is_pqc"],
            "policy_compliant": r["policy_compliant"],
            "qtri_score": r["qtri_score"],
            "source_type": "static_code",
            "asset_type": r["asset_type"],
            "evidence_file": item["file"],
            "evidence_line": item["line"],
            "evidence_function": item["function"],
            "primitive": r["primitive"],
            "classical_security_level": r["classical_security_level"],
            "nist_quantum_security_level": r["nist_quantum_security_level"],
            "recommendation": r["recommendation"]
        })

    return discovered_assets

def scan_directory_static(target_dir: str) -> list:
    """
    Recursively scans a directory for Python, JavaScript, TypeScript, and manifest files.
    """
    if not os.path.exists(target_dir):
        return []

    if not os.path.isdir(target_dir):
        return scan_file_static(target_dir)

    all_assets = []
    ignore_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx", "requirements.txt", "package.json")):
                filepath = os.path.join(root, f)
                assets = scan_file_static(filepath)
                all_assets.extend(assets)

    return all_assets
