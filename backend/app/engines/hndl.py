from datetime import datetime, timedelta
from app.engines.mosca import SENSITIVITY_SHELF_LIFE, get_gri_crqc_probability, GRI_PROBABILITY_TABLE

# HNDL: Harvest Now, Decrypt Later
# Exposure = Traffic Volume * Retention Window * Sensitivity * GRI CRQC Arrival Probability
# Grounded on the Global Risk Institute (GRI) Quantum Threat Report probability distribution.

TIER_TRAFFIC_BASELINES = {
    "S1": 800, # RTGS/NEFT core transaction throughput (GB/month)
    "S2": 400, # Login, biometric, customer identity API traffic
    "S3": 200, # Account statement queries & payment logs
    "S4": 80,  # Internal business microservice traffic
    "S5": 20   # Public web portal content
}

def calculate_hndl_exposure(asset: dict, harvest_start_date: str = "2023-01-01"):
    # Only relevant for assets lacking forward secrecy or relying on broken/quantum-vulnerable keys
    if asset.get("forward_secrecy", False) and asset.get("is_pqc", False):
        return None
    
    sensitivity_tier = asset.get("sensitivity_tier", "S5")
    shelf_life_years = SENSITIVITY_SHELF_LIFE.get(sensitivity_tier, 1)

    sensitivity_multiplier = {
        "S1": 10.0, "S2": 5.0, "S3": 2.0, "S4": 1.0, "S5": 0.5
    }.get(sensitivity_tier, 0.5)
    
    # Deterministic traffic volume (GB/month) based on enterprise sensitivity tier
    traffic_volume = TIER_TRAFFIC_BASELINES.get(sensitivity_tier, 20)
    
    # Months of adversary traffic interception accumulated so far
    try:
        harvest_start = datetime.strptime(harvest_start_date, "%Y-%m-%d")
    except ValueError:
        harvest_start = datetime(2023, 1, 1)
        
    months_captured = max(1, (datetime.now() - harvest_start).days // 30)
    total_gb_at_risk = traffic_volume * months_captured

    # GRI Probability Weight: likelihood that a CRQC arrives during the data's useful shelf life
    gri_prob_median = get_gri_crqc_probability(float(shelf_life_years), bound="median")
    gri_prob_upper = get_gri_crqc_probability(float(shelf_life_years), bound="upper")

    # Modulated exposure value (GB * sensitivity * probability)
    raw_exposure = total_gb_at_risk * sensitivity_multiplier
    probability_weighted_risk = raw_exposure * max(0.05, gri_prob_median)
    
    return {
        "traffic_volume_monthly_gb": traffic_volume,
        "months_captured": months_captured,
        "total_gb_at_risk": total_gb_at_risk,
        "hndl_risk_score": round(probability_weighted_risk, 2),
        "raw_exposure_score": round(raw_exposure, 2),
        "gri_arrival_probability": round(gri_prob_median, 3),
        "gri_upper_probability": round(gri_prob_upper, 3),
        "retention_shelf_life_years": shelf_life_years,
        "harvest_start_date": harvest_start.isoformat(),
        "methodology_note": "GRI-Aligned Probability-Weighted HNDL Model (Global Risk Institute 2024)"
    }
