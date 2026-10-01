import requests
import time
from datetime import datetime
from models import SessionLocal, IOC, Vulnerability, init_db

# Feeds
FEODO_TRACKER_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_RECENT_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def get_geoip_data(ip_address):
    """Fetches GeoIP data for a given IP."""
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,lat,lon"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return data.get("country"), data.get("lat"), data.get("lon")
    except Exception:
        pass
    return "Unknown", None, None

def fetch_feodo_c2_ips(limit=30):
    """
    Ingests active Command and Control (C2) botnet IPs from Feodo Tracker
    and enriches them with Geolocation coordinates.
    """
    print("[*] Ingesting C2 Botnet IPs from Feodo Tracker...")
    session = SessionLocal()
    headers = {"User-Agent": "ThreatIntelDashboard-M1/1.0"}

    try:
        response = requests.get(FEODO_TRACKER_JSON, headers=headers, timeout=15)
        if response.status_code != 200:
            print(f"[!] Feodo Tracker request failed: {response.status_code}")
            return

        entries = response.json()[:limit]
        inserted = 0

        for item in entries:
            ip = item.get("ip_address")
            if not ip:
                continue

            existing = session.query(IOC).filter_by(value=ip).first()
            if not existing:
                country, lat, lon = get_geoip_data(ip)
                # Polite rate limiting for free geo lookup
                time.sleep(0.1)

                malware = item.get("malware", "Botnet C2")
                new_ioc = IOC(
                    value=ip,
                    ioc_type="ip",
                    threat_type="botnet_c2",
                    confidence_score=95.0,
                    source="Feodo Tracker",
                    country=country,
                    latitude=lat,
                    longitude=lon,
                    description=f"Malware Family: {malware} | Port: {item.get('port')}"
                )
                session.add(new_ioc)
                inserted += 1

        session.commit()
        print(f"[✓] Feodo Tracker: {inserted} active C2 IPs ingested & geo-tagged.")
    except Exception as e:
        session.rollback()
        print(f"[!] Error ingesting Feodo IPs: {e}")
    finally:
        session.close()

def fetch_urlhaus_iocs(limit=50):
    print("[*] Ingesting threat data from URLhaus...")
    session = SessionLocal()
    headers = {"User-Agent": "ThreatIntelDashboard-M1/1.0"}
    try:
        resp = requests.get(URLHAUS_RECENT_API, headers=headers, timeout=15)
        if resp.status_code == 200:
            payload = resp.json()
            if payload.get("query_status") == "ok":
                for item in payload.get("urls", [])[:limit]:
                    raw_url = item.get("url")
                    if not raw_url:
                        continue
                    if not session.query(IOC).filter_by(value=raw_url).first():
                        session.add(IOC(
                            value=raw_url,
                            ioc_type="url",
                            threat_type=item.get("threat", "malware_delivery"),
                            confidence_score=90.0 if item.get("url_status") == "online" else 60.0,
                            source="URLhaus",
                            description=f"Tags: {item.get('tags')}"
                        ))
                session.commit()
                print("[✓] URLhaus ingestion complete.")
    except Exception as e:
        session.rollback()
        print(f"[!] URLhaus error: {e}")
    finally:
        session.close()

def fetch_cisa_vulnerabilities(limit=50):
    print("[*] Ingesting CISA KEV...")
    session = SessionLocal()
    try:
        resp = requests.get(CISA_KEV_API, timeout=15)
        if resp.status_code == 200:
            for item in resp.json().get("vulnerabilities", [])[:limit]:
                cve_id = item.get("cveID")
                if cve_id and not session.query(Vulnerability).filter_by(cve_id=cve_id).first():
                    session.add(Vulnerability(
                        cve_id=cve_id,
                        vendor_project=item.get("vendorProject", "Unknown"),
                        product=item.get("product", "Unknown"),
                        vulnerability_name=item.get("vulnerabilityName", "N/A"),
                        date_added=item.get("dateAdded", ""),
                        short_description=item.get("shortDescription", "")
                    ))
            session.commit()
            print("[✓] CISA KEV ingestion complete.")
    except Exception as e:
        session.rollback()
        print(f"[!] CISA error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    init_db()
    fetch_feodo_c2_ips()
    fetch_urlhaus_iocs()
    fetch_cisa_vulnerabilities()
