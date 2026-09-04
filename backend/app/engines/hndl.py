from datetime import datetime, timedelta

# HNDL: Harvest Now, Decrypt Later
# Exposure = Traffic Volume * Redundancy * Sensitivity
# We model the window from "Harvest Start" (e.g. 2023) to "CRQC Arrival" (2030+)

TIER_TRAFFIC_BASELINES = {
    "S1": 800, # RTGS/NEFT transaction throughput
    "S2": 400, # Login, biometric API traffic
    "S3": 200, # Account statement queries
    "S4": 80,  # Internal API traffic
    "S5": 20   # Website/public portal
}

def calculate_hndl_exposure(asset: dict, harvest_start_date: str = "2023-01-01"):
    # Only relevant for assets without forward secrecy
    if asset.get("forward_secrecy", False):
        return None
    
    sensitivity_tier = asset.get("sensitivity_tier", "S5")
    sensitivity_multiplier = {
        "S1": 10.0, "S2": 5.0, "S3": 2.0, "S4": 1.0, "S5": 0.5
    }.get(sensitivity_tier, 0.5)
    
    # Deterministic traffic volume (GB/month) based on RBI sensitivity tier
    traffic_volume = TIER_TRAFFIC_BASELINES.get(sensitivity_tier, 20)
    
    # Months gathered so far
    try:
        harvest_start = datetime.strptime(harvest_start_date, "%Y-%m-%d")
    except ValueError:
        harvest_start = datetime(2023, 1, 1)
        
    months_captured = max(1, (datetime.now() - harvest_start).days // 30)
    
    total_gb_at_risk = traffic_volume * months_captured
    risk_value = total_gb_at_risk * sensitivity_multiplier
    
    return {
        "traffic_volume_monthly_gb": traffic_volume,
        "months_captured": months_captured,
        "total_gb_at_risk": total_gb_at_risk,
        "hndl_risk_score": round(risk_value, 2),
        "harvest_start_date": harvest_start.isoformat(),
        "methodology_note": "RBI Tier-Aligned Conservative Baseline per NSA HNDL Advisory 2023"
    }
