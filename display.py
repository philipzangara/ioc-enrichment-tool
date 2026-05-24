from typing import Any

def display_results(results: dict) -> None:
    
    print("*** IOC Enrichment Report ***")
    if results.get("error"):
        print_field("Error:", results.get("error"))
        return
    if results.get("type") == "hash":
        votes = results.get("total_votes", {})
        print_field("IOC: ", results.get("ioc"))
        print_field("Type: ", results.get("type"))
        print_field("Malicious: ", results.get("malicious"))
        print_field("Suspicious: ", results.get("suspicious"))
        print_field("Harmless: ", results.get("harmless"))
        print_field("Reputation: ", results.get("reputation"))
        print_field("Meaningful name:", results.get("meaningful_name"))
        print_field("File Type:", results.get("file_type"))
        print_field("Votes Malicious: ", votes.get("malicious", 0))
        print_field("Votes Harmless: ", votes.get("harmless", 0))        
    elif results.get("type") == "url":
        votes = results.get("total_votes", {})
        print_field("IOC: ", results.get("ioc"))
        print_field("Type: ", results.get("type"))
        print_field("Final URL:", results.get("final_url"))
        print_field("Title:", results.get("title"))
        print_field("Malicious: ", results.get("malicious"))
        print_field("Suspicious: ", results.get("suspicious"))
        print_field("Harmless: ", results.get("harmless"))
        print_field("Reputation: ", results.get("reputation"))
        print_field("Undetected: ", results.get("undetected"))
        print_field("Votes Malicious: ", votes.get("malicious", 0))
        print_field("Votes Harmless: ", votes.get("harmless", 0))        
    elif results.get("type") == "ip":
        print_field("IOC: ", results.get("ioc"))
        print_field("Type: ", results.get("type"))
        print_field("Abuse Score:", results.get("abuse_score"))
        print_field("Is Tor:", results.get("is_tor"))
        print_field("Is Whitelisted:", results.get("is_whitelisted"))
        print_field("Last Reported:", results.get("last_reported"))
        print_field("Total Reports:", results.get("total_reports"))
        print_field("Country:", results.get("country"))
        print_field("ISP:", results.get("isp"))
        print_field("Domain:", results.get("domain"))     
             
def print_field(label: str, value: Any) -> None:
    print(f"{label:<30} {value}")