import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("ABUSEIPDB_API_KEY") or ""

def check_ip_abuseipdb(ioc: str) -> dict:
    if not api_key:
        return {"error": "No ABUSEIPDB API key found in .env"}   
    
    params = {"ipAddress": ioc, "maxAgeInDays": 90}
    headers = {"Key": api_key, "Accept": "application/json"}

    try:
        get_response = requests.get("https://api.abuseipdb.com/api/v2/check", 
                            headers=headers, params=params) # type: ignore
        
        response = get_response.json()
        data = response["data"]
        return {
            "ioc": ioc,
            "type": "ip",
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "domain": data.get("domain", "Unknown"),
            "is_whitelisted": data["isWhitelisted"],
            "is_tor": data["isTor"],
            "total_reports": data["totalReports"],
            "last_reported": data.get("lastReportedAt", "Never")
        }
    except Exception as e:
        return {"error": str(e)}