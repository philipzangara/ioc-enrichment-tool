## Simple IOC Lookup

A Python-based IOC enrichment tool that performs automated triage of IPs, domains, URLs, and file hashes.

## Usage
Windows:
```
python enrich.py <ioc>
```
Linux/Mac:
```
python3 enrich.py <ioc>
```
JSON output:
```
python enrich.py <ioc> --output json
```
Pipe to file::
```
python enrich.py <ioc> --output json > result.json
```

Tested using Python 3.10.11

## Requirements
```
pip install -r requirements.txt
```

## API Keys

This tool uses the following free APIs:
- VirusTotal: https://www.virustotal.com (free account required)
- AbuseIPDB: https://www.abuseipdb.com (free account required)

URL and hash analysis will be skipped if keys are not present.

Add keys to a `.env` file in the project directory:
```
VT_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

## Features
- IOC type detection (URL, IP, hash, domain)
- VirusTotal URL enrichment
- VirusTotal hash enrichment
- AbuseIPDB IP enrichment 
- Domain enrichment
- WHOIS lookup for domain and URL IOC types

## Sample Output

**Hash Lookup**
![Hash Lookup](assets/hash_lookup.png)


**URL Lookup**
![URL Lookup](assets/url_lookup.png)


**IP Lookup**
![IP Lookup](assets/ip_lookup.png)


**Domain Lookup**
![Domain Lookup](assets/domain_lookup.png)

## How It Works

1. Detects the IOC type automatically (URL, IP, hash, or domain)
2. Routes to the appropriate enrichment APIs based on type
3. URL and domain lookups include WHOIS registration data
4. Returns a verdict based on vendor detections and abuse scores

| IOC Type | APIs Used |
|----------|-----------|
| URL      | VirusTotal, WHOIS |
| IP       | AbuseIPDB |
| Hash     | VirusTotal |
| Domain   | VirusTotal, WHOIS |

## MITRE ATT&CK

This tool supports investigation of the following techniques:

- T1566 — Phishing (URL and domain triage)
- T1071 — Application Layer Protocol (domain and URL analysis)
- T1204 — User Execution (malicious hash identification)
- T1190 — Exploit Public-Facing Application (IP reputation lookup)


## Sample Data
Test IOCs sourced from publicly available phishing and malware feeds.

## Code Quality
- Type checked with mypy
- Unit tested with unittest

## Author: Philip Zangara

## License: MIT

Disclaimer: Built independently, with AI used as a learning aid for guidance and debugging feedback.