#!/usr/bin/env python3
"""
Certificate Transparency (CT) Log Scraper
Queries crt.sh API to find ALL subdomains from SSL certificates
This finds hidden subdomains that wordlists miss
"""

import requests
import json
import time
import re
from urllib.parse import quote
from colorama import Fore, Style, init

init(autoreset=True)

# crt.sh API endpoint
CRTSH_API = "https://crt.sh/?q={}&output=json"

def query_crtsh(domain, wildcard=True):
    """
    Query crt.sh for all certificates matching a domain
    
    Args:
        domain: Base domain to search (e.g., "gov.ng")
        wildcard: If True, searches %.domain for all subdomains
    
    Returns:
        List of certificate entries from crt.sh
    """
    if wildcard and not domain.startswith("%."):
        search_term = f"%.{domain}"
    else:
        search_term = domain
    
    url = CRTSH_API.format(quote(search_term))
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            try:
                data = response.json()
                return data if data else []
            except json.JSONDecodeError:
                print(f"{Fore.RED}Error: Invalid JSON response from crt.sh{Style.RESET_ALL}")
                return []
        else:
            print(f"{Fore.RED}Error: crt.sh returned status {response.status_code}{Style.RESET_ALL}")
            return []
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}Error: crt.sh query timed out{Style.RESET_ALL}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return []

def extract_subdomains(cert_data):
    """
    Extract unique subdomains from crt.sh certificate data
    
    Args:
        cert_data: List of certificate entries from crt.sh API
    
    Returns:
        Set of unique subdomain strings
    """
    subdomains = set()
    
    for entry in cert_data:
        # crt.sh returns name_value field with subdomains
        name_value = entry.get("name_value", "")
        
        if not name_value:
            continue
        
        # name_value can contain multiple domains separated by newlines
        domains = name_value.split("\n")
        
        for domain in domains:
            domain = domain.strip().lower()
            
            # Skip wildcards
            if domain.startswith("*."):
                domain = domain[2:]
            
            # Skip empty
            if not domain:
                continue
            
            # Basic validation
            if "." in domain and len(domain) > 3:
                # Remove any trailing dots
                domain = domain.rstrip(".")
                subdomains.add(domain)
    
    return subdomains

def get_subdomains(domain, wildcard=True, include_base=True):
    """
    Main function: Get all subdomains for a domain from CT logs
    
    Args:
        domain: Base domain (e.g., "gov.ng")
        wildcard: Search all subdomains
        include_base: Also include the base domain itself
    
    Returns:
        Sorted list of unique subdomains
    """
    print(f"\n{Fore.CYAN}=== CT Log Scraper ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Querying crt.sh for: {domain}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This may take 10-30 seconds...{Style.RESET_ALL}\n")
    
    # Query crt.sh
    cert_data = query_crtsh(domain, wildcard=wildcard)
    
    if not cert_data:
        print(f"{Fore.RED}No certificate data found for {domain}{Style.RESET_ALL}")
        if include_base:
            return [domain]
        return []
    
    print(f"{Fore.GREEN}Found {len(cert_data)} certificate entries{Style.RESET_ALL}")
    
    # Extract subdomains
    subdomains = extract_subdomains(cert_data)
    
    if include_base and domain not in subdomains:
        subdomains.add(domain)
    
    # Sort and return
    sorted_subs = sorted(subdomains)
    
    print(f"{Fore.GREEN}Extracted {len(sorted_subs)} unique subdomains{Style.RESET_ALL}")
    
    return sorted_subs

def batch_ct_scan(domains, delay=2):
    """
    Scan multiple base domains using CT logs
    
    Args:
        domains: List of base domains
        delay: Seconds to wait between queries (be nice to crt.sh)
    
    Returns:
        Dictionary: {base_domain: [subdomains]}
    """
    results = {}
    total = len(domains)
    
    print(f"\n{Fore.CYAN}=== Batch CT Scan ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Scanning {total} base domains{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Delay between queries: {delay}s{Style.RESET_ALL}\n")
    
    for i, domain in enumerate(domains, 1):
        print(f"{Fore.CYAN}[{i}/{total}] Scanning: {domain}{Style.RESET_ALL}")
        
        subdomains = get_subdomains(domain, wildcard=True, include_base=True)
        results[domain] = subdomains
        
        # Be nice to crt.sh API
        if i < total:
            time.sleep(delay)
    
    # Summary
    total_found = sum(len(subs) for subs in results.values())
    print(f"\n{Fore.GREEN}=== Batch Complete ==={Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total base domains: {total}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total subdomains found: {total_found}{Style.RESET_ALL}")
    
    return results

def save_ct_results(results, filename=None):
    """
    Save CT scan results to file
    
    Args:
        results: Dictionary from batch_ct_scan
        filename: Output filename (auto-generated if None)
    """
    import os
    
    DOMAINS_DIR = os.path.expanduser("~/snihost_pro/domains")
    os.makedirs(DOMAINS_DIR, exist_ok=True)
    
    if filename is None:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"ct_subdomains_{timestamp}.txt"
    
    filepath = os.path.join(DOMAINS_DIR, filename)
    
    # Flatten all subdomains
    all_subdomains = set()
    for subs in results.values():
        all_subdomains.update(subs)
    
    sorted_subs = sorted(all_subdomains)
    
    with open(filepath, 'w') as f:
        f.write(f"# CT Log Subdomain Discovery Results\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Base domains scanned: {len(results)}\n")
        f.write(f"# Total unique subdomains: {len(sorted_subs)}\n")
        f.write("-" * 50 + "\n")
        for sub in sorted_subs:
            f.write(f"{sub}\n")
    
    print(f"{Fore.GREEN}Saved {len(sorted_subs)} subdomains to:{Style.RESET_ALL}")
    print(f"  {filepath}")
    
    return filepath

def preview_subdomains(subdomains, max_preview=20):
    """
    Show preview of found subdomains
    """
    print(f"\n{Fore.YELLOW}Preview (showing {min(max_preview, len(subdomains))} of {len(subdomains)}):{Style.RESET_ALL}")
    for sub in subdomains[:max_preview]:
        print(f"  → {sub}")
    if len(subdomains) > max_preview:
        print(f"  ... and {len(subdomains) - max_preview} more")

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  CT Log Subdomain Scraper{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Finds hidden subdomains from SSL certificates{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Single domain scan")
    print("2. Batch scan (multiple domains)")
    print("3. Quick scan (common zero-rated base domains)")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == '1':
        domain = input("Enter base domain (e.g., gov.ng): ").strip().lower()
        if not domain:
            print(f"{Fore.RED}No domain entered{Style.RESET_ALL}")
            return
        
        subdomains = get_subdomains(domain)
        preview_subdomains(subdomains)
        
        if subdomains:
            save = input(f"\nSave to file? (y/n): ").strip().lower()
            if save == 'y':
                results = {domain: subdomains}
                save_ct_results(results)
    
    elif choice == '2':
        print("Enter base domains (one per line, empty line to finish):")
        domains = []
        while True:
            line = input().strip().lower()
            if not line:
                break
            domains.append(line)
        
        if not domains:
            print(f"{Fore.RED}No domains entered{Style.RESET_ALL}")
            return
        
        results = batch_ct_scan(domains)
        
        # Show preview for each
        for domain, subs in results.items():
            print(f"\n{Fore.CYAN}{domain}:{Style.RESET_ALL} {len(subs)} subdomains")
            preview_subdomains(subs, max_preview=10)
        
        save = input(f"\nSave all results to file? (y/n): ").strip().lower()
        if save == 'y':
            save_ct_results(results)
    
    elif choice == '3':
        # Common zero-rated base domains for quick scan
        common_domains = [
            'gov.ng', 'go.ke', 'gov.za', 'gov.gh', 'go.tz', 'go.ug',
            'ac.ke', 'ac.za', 'ac.ng', 'ac.ug', 'ac.tz',
            'health.go.ke', 'health.gov.ng', 'health.gov.za',
            'who.int', 'cdc.gov', 'nih.gov',
        ]
        
        print(f"{Fore.YELLOW}Quick scanning {len(common_domains)} common zero-rated base domains...{Style.RESET_ALL}")
        results = batch_ct_scan(common_domains, delay=3)
        
        # Show summary
        for domain, subs in results.items():
            if len(subs) > 1:  # More than just base domain
                print(f"\n{Fore.GREEN}{domain}:{Style.RESET_ALL} {len(subs)} subdomains")
                preview_subdomains(subs, max_preview=5)
        
        save = input(f"\nSave all results to file? (y/n): ").strip().lower()
        if save == 'y':
            save_ct_results(results)
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
