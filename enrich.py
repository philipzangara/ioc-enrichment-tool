import argparse 
import tldextract
import json

from ioc_detector import detect_ioc_type
from enrichment.virustotal import check_hash_vt, check_url_vt, check_domain_vt
from enrichment.abuseipdb import check_ip_abuseipdb
from enrichment.whois_check import check_whois
from display import display_results

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Type URL, IP, hash, or domain")
    parser.add_argument("ioc", help="URL, IP, hash, or domain")
    parser.add_argument("--output", choices=["json"], help="Output format")
    return parser.parse_args(argv)

def main(argv=None) -> None:
    args = parse_args(argv)
    ioc = args.ioc
    ioc_type = detect_ioc_type(ioc)

    # call virustotal url lookup
    if ioc_type == "url":
        result = check_url_vt(ioc)
        extract = tldextract.extract(ioc)
        domain = extract.domain + "." + extract.suffix
        whois_result = check_whois(domain)
        result = {**result, "whois": whois_result}
    # call abuseipdb + whois
    elif ioc_type == "ip":
        result = check_ip_abuseipdb(ioc)
    # call virustotal hash lookup
    elif ioc_type in ["md5", "sha1", "sha256"]:
        result = check_hash_vt(ioc)
    # call virustotal domain lookup + whois
    elif ioc_type == "domain":
        result = check_domain_vt(ioc)
        whois_result = check_whois(ioc)
        result = {**result, "whois": whois_result}
    else:
        print("Unknown IOC type")
        raise SystemExit(1)
    
    if args.output == "json":
        print(json.dumps(result, indent=4, default=str))
    else:
        display_results(result)


if __name__ == "__main__":
    main()