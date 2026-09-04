import json
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

try:
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.crypto import CryptoProperties, CryptoAssetType, AlgorithmProperties, CryptoPrimitive
    from cyclonedx.output.json import JsonV1Dot6
    HAS_CYCLONEDX_LIB = True
except ImportError:
    HAS_CYCLONEDX_LIB = False

class CBOMGenerator:
    @staticmethod
    def generate_cyclonedx_1_6_json(assets: list) -> dict:
        """
        Generates 100% compliant CycloneDX 1.6 CBOM JSON using cyclonedx-python-lib.
        Falls back to structured CycloneDX 1.6 dict if lib is unavailable.
        """
        if HAS_CYCLONEDX_LIB:
            bom = Bom()
            for asset in assets:
                algo_name = asset.get("algorithm", "UNKNOWN")
                hostname = asset.get("hostname", "unnamed_asset")
                
                # Primitive mapping
                prim = CryptoPrimitive.KEY_AGREE
                if "RSA" in algo_name or "PKE" in algo_name:
                    prim = CryptoPrimitive.PKE
                elif "DSA" in algo_name or "ECDSA" in algo_name or "Dilithium" in algo_name:
                    prim = CryptoPrimitive.SIGNATURE
                elif "KEM" in algo_name or "Kyber" in algo_name:
                    prim = CryptoPrimitive.KEM
                elif "AES" in algo_name or "GCM" in algo_name:
                    prim = CryptoPrimitive.BLOCK_CIPHER
                elif "SHA" in algo_name or "HASH" in algo_name:
                    prim = CryptoPrimitive.HASH

                comp = Component(
                    name=f"{hostname}:{algo_name}",
                    type=ComponentType.CRYPTOGRAPHIC_ASSET,
                    version=str(asset.get("key_size", "")),
                    crypto_properties=CryptoProperties(
                        asset_type=CryptoAssetType.ALGORITHM,
                        algorithm_properties=AlgorithmProperties(
                            primitive=prim,
                            parameter_set_identifier=str(asset.get("parameter_set_identifier") or asset.get("key_size", "")),
                            nist_quantum_security_level=int(asset.get("nist_quantum_security_level") or (1 if asset.get("is_pqc") else 0))
                        )
                    )
                )
                bom.components.add(comp)
            outputter = JsonV1Dot6(bom)
            return json.loads(outputter.output_as_string())
        else:
            # Native fallback dictionary schema matching CycloneDX 1.6 specification
            components = []
            for asset in assets:
                components.append({
                    "type": "cryptographic-asset",
                    "name": asset.get("hostname", "unnamed_asset"),
                    "version": str(asset.get("key_size", "")),
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": asset.get("primitive", "key-agreement"),
                            "parameterSetIdentifier": str(asset.get("key_size", "")),
                            "nistQuantumSecurityLevel": 1 if asset.get("is_pqc") else 0
                        }
                    },
                    "evidence": {
                        "occurrences": [
                            {
                                "location": asset.get("evidence_file") or asset.get("hostname"),
                                "line": asset.get("evidence_line"),
                                "symbol": asset.get("evidence_function")
                            }
                        ]
                    }
                })
            return {
                "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tool": "Q-Guardian v2.0 Enterprise CBOM Engine"
                },
                "components": components
            }

    @staticmethod
    def generate_json(assets: list):
        return CBOMGenerator.generate_cyclonedx_1_6_json(assets)

    @staticmethod
    def export_pdf(assets: list):
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), topMargin=30)
        elements = []
        styles = getSampleStyleSheet()
        
        # Enterprise Primary Style
        indigo_primary = colors.Color(79/255, 70/255, 229/255) # Indigo #4F46E5
        
        # Title
        styles.add(ParagraphStyle(name='QGTitle', fontSize=18, textColor=indigo_primary, spaceAfter=10, fontWeight='bold'))
        elements.append(Paragraph("Q-GUARDIAN ENTERPRISE | Cryptographic Bill of Materials (CBOM)", styles['QGTitle']))
        elements.append(Paragraph(f"Specification: CycloneDX 1.6 Native Standard", styles['Normal']))
        elements.append(Paragraph(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Inventory Table
        elements.append(Paragraph("1. Cryptographic Asset Inventory", styles['Heading2']))
        data = [["Asset / Source", "Source Type", "Algorithm", "Key Size", "TLS Version", "PQC Ready"]]
        for asset in assets:
            data.append([
                asset.get("hostname", "N/A"),
                asset.get("source_type", "network_live"),
                asset.get("algorithm", "UNKNOWN"),
                str(asset.get("key_size", 0)),
                asset.get("tls_version", "N/A"),
                "YES (PQC)" if asset.get("is_pqc") else "NO (Legacy)"
            ])
        
        t = Table(data, hAlign='LEFT', colWidths=[180, 100, 100, 70, 70, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), indigo_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(t)
        elements.append(Spacer(1, 25))
        
        # Risk Table
        elements.append(Paragraph("2. Risk & Quantum Preparedness Summary", styles['Heading2']))
        risk_data = [["Asset / Hostname", "Sensitivity Tier", "QTRI Score", "Mosca Risk Window", "Policy Status"]]
        for asset in assets:
            mosca = asset.get("mosca", {})
            if isinstance(mosca, str):
                try: mosca = json.loads(mosca)
                except: mosca = {}
                
            risk_data.append([
                asset.get("hostname", "N/A"),
                asset.get("sensitivity_tier", "S3"),
                str(asset.get("qtri_score", 0)),
                mosca.get("risk_state", "SAFE"),
                "COMPLIANT" if asset.get("policy_compliant") else "NON-COMPLIANT"
            ])
            
        rt = Table(risk_data, hAlign='LEFT', colWidths=[180, 100, 80, 110, 110])
        rt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#06B6D4")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(rt)
        
        # Footer
        elements.append(Spacer(1, 40))
        elements.append(Paragraph("Notes: Generated by Q-Guardian v2.0 Enterprise CBOM Platform. Aligned with CycloneDX 1.6 & NIST IR 8547.", styles['Italic']))
        elements.append(Paragraph("RESTRICTED: CRITICAL INFRASTRUCTURE SECURITY AUDIT DOCUMENT", styles['Normal']))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer
