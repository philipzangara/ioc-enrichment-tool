import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("VT_API_KEY") or ""

# check hash in VirusTotal
# rate limit to 15 seconds. Only 4 free API calls per minute.
def check_hash_vt(ioc: str) -> dict:

    if not api_key:
        return {"error": "No VT API key found in .env"}

    headers = {"x-apikey": api_key}
    try:
        get_response = requests.get(f"https://www.virustotal.com/api/v3/files/{ioc}", 
                        headers=headers) # type: ignore
        response = get_response.json()
        attributes = response["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
    except Exception as e:
        return {"error": str(e)}
    
    return {
        "ioc": ioc,
        "type": "hash",
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "undetected": stats["undetected"],
        "reputation": attributes["reputation"],
        "meaningful_name": attributes.get("meaningful_name", "Unknown"),
        "file_type": attributes.get("type_description", "Unknown"),
        "total_votes": attributes["total_votes"]
    }
            
# check URL in VirusTotal
# rate limit to 15 seconds. Only 4 free API calls per minute.
def check_url_vt(ioc: str) -> dict:
   
    if not api_key:
        return {"error": "No VT API key found in .env"}   

    ioc_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip('=')

    headers = {"x-apikey": api_key}    
    # VT URL endpoint requires form data, not JSON
    data = {"url": ioc} 
    post_response = requests.post("https://www.virustotal.com/api/v3/urls", 
                              headers=headers, data=data) # type: ignore

    if post_response.status_code != 200:
        return {"ioc": ioc, "error": f"POST failed: {post_response.status_code}"}
    else:
        get_response = requests.get(f"https://www.virustotal.com/api/v3/urls/{ioc_id}", 
                            headers=headers) # type: ignore
        try:
            response = get_response.json()
            attributes = response["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            return {
                "ioc": ioc,
                "type": "url",
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"],
                "undetected": stats["undetected"],
                "reputation": attributes["reputation"],
                "final_url": attributes.get("last_final_url", ioc),
                "title": attributes.get("title", "Unknown"),
                "total_votes": attributes["total_votes"]
            }
        except Exception as e:
            return {
                "ioc": ioc,
                "error": str(e)
            }
        
def check_domain_vt(ioc: str) -> dict:

    if not api_key:
        return {"error": "No VT API key found in .env"}

    headers = {"x-apikey": api_key}
    try:
        get_response = requests.get(f"https://www.virustotal.com/api/v3/domains/{ioc}", 
                        headers=headers) # type: ignore
        response = get_response.json()
        attributes = response["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        return {
            "ioc": ioc,
            "type": "domain",
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "reputation": attributes["reputation"],
            "registrar": attributes.get("registrar", "Unknown"),
            "creation_date": attributes.get("creation_date"),
            "expiration_date": attributes.get("expiration_date"),
            "categories": attributes.get("categories", {}),
            "popularity_ranks": attributes.get("popularity_ranks", {}),
            "total_votes": attributes["total_votes"]
        }
    except Exception as e:
        return {"error": str(e)}

