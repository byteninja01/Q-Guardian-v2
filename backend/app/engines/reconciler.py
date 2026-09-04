"""
CBOM Reconciliation & Divergence Engine for Q-Guardian-v2
Correlates discoveries across multiple vectors: static-source, binary,
container, and network-live scans. Identifies "Declared vs Actual"
divergences and computes crypto-agility maturity levels.
"""

from typing import Dict, Any, List, Optional
from sqlmodel import Session, select
from datetime import datetime
import re

from app.database import DBAsset

def _normalize_hostname(h: str) -> str:
    """Normalize asset hostnames to detect shared logical service identities."""
    # Strip protocol and prefixes like bin:, src:, container:
    cleaned = re.sub(r"^(bin|src|container|live):", "", h)
    cleaned = re.sub(r":\d+$", "", cleaned) # strip line or port numbers
    cleaned = re.sub(r":.*$", "", cleaned)  # strip package or symbol suffix
    return cleaned.lower().strip()

def reconcile_assets(session: Session) -> Dict[str, Any]:
    """
    Evaluate all assets across sources, detect divergence discrepancies,
    update DBAsset.divergence_flag in DB, and generate divergence summary.
    """
    statement = select(DBAsset)
    assets = session.exec(statement).all()

    if not assets:
        return {
            "status": "empty",
            "total_evaluated": 0,
            "divergence_count": 0,
            "divergences": [],
            "crypto_agility_score": 1,
            "maturity_label": "Level 1: Initial / Undiscovered"
        }

    # Group by source type
    by_source: Dict[str, List[DBAsset]] = {
        "static": [],
        "binary": [],
        "container": [],
        "network": []
    }

    for a in assets:
        st = (a.source_type or "").lower()
        if "static" in st:
            by_source["static"].append(a)
        elif "binary" in st:
            by_source["binary"].append(a)
        elif "container" in st:
            by_source["container"].append(a)
        elif "network" in st or "live" in st:
            by_source["network"].append(a)
        else:
            by_source["network"].append(a)

    divergent_items = []
    updated_records = 0

    # ─── Check 1: Declared Source TLS 1.3 / PQC vs Live Network Legacy TLS ───
    static_pqc_or_tls13 = [
        a for a in by_source["static"]
        if a.is_pqc or a.tls_version == "1.3" or "ml-kem" in (a.algorithm or "").lower()
    ]
    live_weak_tls = [
        a for a in by_source["network"]
        if a.tls_version in ["1.0", "1.1", "1.2"] or not a.policy_compliant
    ]

    if static_pqc_or_tls13 and live_weak_tls:
        for net_a in live_weak_tls:
            flag = f"DIV_STATIC_TLS1.3_VS_LIVE_{net_a.tls_version or '1.0'}"
            net_a.divergence_flag = flag
            session.add(net_a)
            updated_records += 1
            divergent_items.append({
                "type": "STATIC_VS_LIVE_PROTOCOL_DIVERGENCE",
                "severity": "CRITICAL",
                "divergence_flag": flag,
                "asset_id": net_a.asset_uuid,
                "target": net_a.hostname,
                "declared": "Source code specifies modern TLS 1.3 / PQC-ready configuration",
                "actual": f"Live network endpoint enforces {net_a.tls_version} with {net_a.cipher_suite}",
                "impact": "Man-in-the-Middle exposure, Harvest-Now-Decrypt-Later vulnerability.",
                "remediation": "Update reverse proxy and gateway cipher suite configuration to disable legacy TLS."
            })

    # ─── Check 2: Container Modern OpenSSL vs Binary Legacy Constants ─────────
    container_modern = [
        a for a in by_source["container"]
        if "3." in (a.algorithm or "") or a.is_pqc
    ]
    binary_legacy = [
        a for a in by_source["binary"]
        if not a.is_pqc and a.qtri_score < 40
    ]

    if container_modern and binary_legacy:
        for bin_a in binary_legacy:
            flag = f"DIV_CONTAINER_MODERN_VS_BINARY_{bin_a.algorithm or 'LEGACY'}"
            bin_a.divergence_flag = flag
            session.add(bin_a)
            updated_records += 1
            divergent_items.append({
                "type": "CONTAINER_VS_BINARY_DIVERGENCE",
                "severity": "HIGH",
                "divergence_flag": flag,
                "asset_id": bin_a.asset_uuid,
                "target": bin_a.hostname,
                "declared": "Container environment supplies modern OpenSSL 3.x / base libraries",
                "actual": f"Compiled binary contains hardcoded legacy primitive: {bin_a.algorithm} ({bin_a.evidence_function or ''})",
                "impact": "Static linking or legacy embedded routines bypass host/container security updates.",
                "remediation": "Recompile binary artifact against shared OpenSSL 3.x and remove embedded legacy routines."
            })

    # ─── Check 3: Static Code PQC vs Live Network Classical Cert ─────────────
    live_classical_certs = [
        a for a in by_source["network"]
        if not a.is_pqc and a.key_size <= 2048
    ]
    if static_pqc_or_tls13 and live_classical_certs:
        for net_a in live_classical_certs:
            if not net_a.divergence_flag:
                flag = "DIV_CODE_PQC_VS_LIVE_RSA2048"
                net_a.divergence_flag = flag
                session.add(net_a)
                updated_records += 1
                divergent_items.append({
                    "type": "ALGORITHM_READINESS_DIVERGENCE",
                    "severity": "HIGH",
                    "divergence_flag": flag,
                    "asset_id": net_a.asset_uuid,
                    "target": net_a.hostname,
                    "declared": "Application architecture flagged for Post-Quantum Migration",
                    "actual": f"Public certificate remains Classical RSA-{net_a.key_size} without hybrid key encapsulation",
                    "impact": "Store-Now-Decrypt-Later vulnerability remains active on edge communications.",
                    "remediation": "Enroll in hybrid PQC TLS certificate pilot (X25519MLKEM768)."
                })

    # ─── Check 4: Cross-Source Single-Asset Inconsistency ──────────────────────
    # Check if any single asset has conflicting sensitivity vs compliance
    for a in assets:
        if a.sensitivity_tier == "S1" and not a.policy_compliant and not a.divergence_flag:
            flag = "DIV_TIER_S1_CRITICAL_NON_COMPLIANT"
            a.divergence_flag = flag
            session.add(a)
            updated_records += 1
            divergent_items.append({
                "type": "CRITICAL_TIER_POLICY_DIVERGENCE",
                "severity": "CRITICAL",
                "divergence_flag": flag,
                "asset_id": a.asset_uuid,
                "target": a.hostname,
                "declared": "Sensitivity Tier S1 (Mission-Critical / Financial)",
                "actual": f"Non-compliant crypto configuration with QTRI score {a.qtri_score}/100",
                "impact": "Immediate audit failure under CERT-In / RBI Cyber Security Framework.",
                "remediation": "Prioritize immediate cryptographic remediation for tier S1 assets."
            })

    session.commit()

    # Calculate overall Crypto-Agility Maturity Score (1-5)
    total_count = len(assets)
    div_count = len(divergent_items)
    pqc_count = sum(1 for a in assets if a.is_pqc)

    if div_count == 0 and pqc_count > 0:
        maturity_score = 5
        maturity_label = "Level 5: Quantum Agile & Continuously Correlated"
    elif div_count == 0:
        maturity_score = 4
        maturity_label = "Level 4: Monitored & Reconciled (No Divergence)"
    elif div_count <= 2:
        maturity_score = 3
        maturity_label = "Level 3: Partially Agile (Minor Vector Divergence)"
    elif div_count <= 5:
        maturity_score = 2
        maturity_label = "Level 2: Fragmented (Multi-Vector Divergence Detected)"
    else:
        maturity_score = 1
        maturity_label = "Level 1: High Risk Divergence (Substantial Declared vs Actual Drift)"

    # Update maturity_level across assets
    for a in assets:
        a.maturity_level = maturity_score
        session.add(a)
    session.commit()

    return {
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "total_evaluated": total_count,
        "divergence_count": div_count,
        "updated_records": updated_records,
        "crypto_agility_score": maturity_score,
        "maturity_label": maturity_label,
        "divergences": divergent_items
    }
