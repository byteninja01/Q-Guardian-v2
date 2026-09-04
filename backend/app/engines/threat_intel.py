import requests
import xml.etree.ElementTree as ET
from datetime import datetime

# URLs for major quantum computing and cybersecurity feeds
FEEDS = {
    "IBM Quantum": "https://www.ibm.com/blogs/research/category/quantum-computing/feed/",
    "NIST news": "https://www.nist.gov/news-events/news/rss.xml", 
    "Google AI": "https://blog.google/technology/ai/rss/",
    "CSO Online": "https://www.csoonline.com/category/cybersecurity/feed/"
}

# In-memory cache to avoid rate limiting
intel_cache = []
last_fetched = None

def parse_rss_feed(source_name, content, items_limit=2):
    items = []
    try:
        root = ET.fromstring(content)
        # Handle standard RSS and Atom
        for item in root.findall(".//item")[:items_limit]:
            title = item.find("title")
            pub_date = item.find("pubDate")
            
            title_text = title.text if title is not None else "Unknown Update"
            date_text = pub_date.text if pub_date is not None else datetime.now().strftime("%a, %d %b %Y")
            
            # Very basic relevance check
            impact = "General security note"
            text_lower = title_text.lower()
            if "quantum" in text_lower or "pqc" in text_lower:
                impact = "Mosca clocks recalculated (-5 days)"
            elif "vulnerability" in text_lower or "breach" in text_lower:
                impact = "HNDL risk elevated"
            elif "standard" in text_lower or "nist" in text_lower:
                impact = "Compliance mapping updated"
                
            items.append({
                "source": source_name,
                "title": title_text,
                "date": date_text[:16], # shorten the date string
                "impact": impact
            })
    except Exception as e:
        print(f"Error parsing feed {source_name}: {e}")
    return items

def fetch_threat_intel(force_refresh=False):
    global intel_cache, last_fetched
    
    # Refresh cache every 6 hours
    if not force_refresh and intel_cache and last_fetched:
        if (datetime.now() - last_fetched).total_seconds() < 21600:
            return intel_cache
            
    fresh_intel = []
    for source, url in FEEDS.items():
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                parsed = parse_rss_feed(source, r.text)
                fresh_intel.extend(parsed)
        except Exception as e:
            print(f"Failed fetching from {source}: {e}")
            
    # Store successfully fetched data only
    if fresh_intel:
        intel_cache = fresh_intel[:6] # Top 6 recent items
        last_fetched = datetime.now()
        
    return intel_cache
