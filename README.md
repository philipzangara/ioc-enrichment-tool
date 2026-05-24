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
![Hash Lookup](assets/hash_lookup.jpg)

**URL Lookup**
![URL Lookup](assets/url_lookup.jpg)

**IP Lookup**
![IP Lookup](assets/ip_lookup.jpg)

**Domain Lookup**
![Domain Lookup](assets/domain_lookup.jpg)

## Sample Data
Test IOCs sourced from publicly available phishing and malware feeds.

## Code Quality
- Type checked with mypy
- Unit tested with unittest

## Author: Philip Zangara

## License: MIT

Disclaimer: Built independently, with AI used as a learning aid for guidance and debugging feedback.