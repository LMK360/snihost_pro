#!/usr/bin/env python3
"""
SNI Host Finder PRO — Full Test Suite
Tests ONE or MULTIPLE domains with ALL methods:
CT Check + TLS Deep Test + ML Score + ISP Rules + Community Intel + DPI Evasion
Outputs final combined score for each domain
"""

import os
import sys
import time
import json
import socket
import ssl
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import Fore, Style, init
import dns.resolver

init(autoreset=True)

# ============ CONFIG ============

RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
os.makedirs(RESULTS_DIR, exist_ok=True)

PERSONAL_DB = os.path.expanduser("~/snihost_pro/my_zero_rated_hosts.json")
FEATURE_LOG = os.path.expanduser("~/snihost_pro/ml_data/feature_log.json")
ISP_RULES_DIR = os.path.expanduser("~/snihost_pro/isp_rules")
COMMUNITY_DB = os.path.expanduser("~/snihost_pro/community/local_intel.json")

# CDN ranges
CDN_RANGES = {
    'cloudflare': ['104.16.0.0/12', '172.64.0.0/13', '103.21.244.0/22'],
    'aws': ['13.32.0.0/15', '52.84.0.0/15', '54.192.0.0/16'],
}

# ============ DIRTY HOST CLEANER (from scanner.py) ============

def clean_host_line(line):
    if not line or not isinstance(line, str):
        return None
    line = str(line).strip()
    if not line or line.startswith('#') or line.startswith('//'):
        return None
    line = re.sub(r'\s*\([^)]*\)', '', line)
    line = re.sub(r'^(https?://|http://|www\.)', '', line, flags=re.IGNORECASE)
    line = line.split('/')[0]
    line = re.sub(r':\d+$', '', line)
    line = re.sub(r'\s+', '', line)
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$', line):
        return None
    if '.' not in line:
        return None
    line = line.rstrip('.')
    line = line.lower()
    parts = line.split('.')
    if len(parts) < 2 or len(parts[-1]) < 2:
        return None
    return line

def clean_hosts_bulk(text_or_list):
    if isinstance(text_or_list, str):
        raw_lines = re.split(r'[\n\r,;|]+', text_or_list)
    elif isinstance(text_or_list, list):
        raw_lines = text_or_list
    else:
        return []
    clean_domains = []
    seen = set()
    for line in raw_lines:
        cleaned = clean_host_line(line)
        if cleaned and cleaned not in seen:
            clean_domains.append(cleaned)
            seen.add(cleaned)
    return clean_domains

# ============ MODULE 1: CT CHECK ============

def check_ct_logs(domain):
    """
    Quick CT check — see if domain appears in certificate transparency logs
    Returns score based on how "established" the domain is
    """
    try:
        import requests
        from urllib.parse import quote
        
        # Check exact domain
        url = f"https://crt.sh/?q={quote(domain)}&output=json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            if data and len(data) > 0:
                # Count unique certificate issuers
                issuers = set()
                subdomains = set()
                for entry in data:
                    issuer = entry.get('issuer_name', '')
                    if issuer:
                        issuers.add(issuer)
                    name = entry.get('name_value', '')
                    if name:
                        for n in name.split('\n'):
                            n = n.strip().lower().lstrip('*.')
                            if n and n != domain:
                                subdomains.add(n)
                
                return {
                    'in_ct_logs': True,
                    'cert_count': len(data),
                    'unique_issuers': len(issuers),
                    'subdomains_found': len(subdomains),
                    'score': min(20 + len(data) * 2, 40),  # Max 40 points
                    'subdomains': sorted(subdomains)[:10]
                }
        
        return {'in_ct_logs': False, 'score': 0}
    except Exception as e:
        return {'in_ct_logs': False, 'score': 0, 'error': str(e)}

# ============ MODULE 2: DEEP TLS TEST ============

def test_tls_handshake(domain, timeout=5):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        start = time.time()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                elapsed = (time.time() - start) * 1000
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                
                return {
                    'success': True,
                    'tls_version': version,
                    'cipher': cipher[0] if cipher else None,
                    'response_time_ms': round(elapsed, 2),
                    'cert_sans': [s[1] for s in cert.get('subjectAltName', [])] if cert else [],
                    'cert_issuer': str(cert.get('issuer', '')) if cert else '',
                    'cert_subject': str(cert.get('subject', '')) if cert else ''
                }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def test_empty_sni(domain, timeout=5):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock) as ssock:
                return {'accepts_empty_sni': True, 'tls_version': ssock.version()}
    except:
        return {'accepts_empty_sni': False}

def test_wrong_sni(domain, wrong='google.com', timeout=5):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=wrong) as ssock:
                cert = ssock.getpeercert()
                sans = [s[1] for s in cert.get('subjectAltName', [])] if cert else []
                return {
                    'accepts_wrong_sni': True,
                    'wrong_sni_in_cert': wrong in str(sans),
                    'shared_hosting': wrong not in str(sans)
                }
    except:
        return {'accepts_wrong_sni': False}

def check_http_status(domain, timeout=5):
    try:
        import http.client
        conn = http.client.HTTPSConnection(domain, timeout=timeout)
        conn.request("HEAD", "/", headers={'Host': domain, 'User-Agent': 'Mozilla/5.0'})
        resp = conn.getresponse()
        conn.close()
        return {'status': resp.status, 'protocol': 'HTTPS'}
    except:
        try:
            conn = http.client.HTTPConnection(domain, timeout=timeout)
            conn.request("HEAD", "/", headers={'Host': domain})
            resp = conn.getresponse()
            conn.close()
            return {'status': resp.status, 'protocol': 'HTTP'}
        except Exception as e:
            return {'status': None, 'error': str(e)}

def deep_tls_test(domain):
    """
    Run ALL TLS tests on one domain
    """
    print(f"  {Fore.YELLOW}Testing TLS...{Style.RESET_ALL}", end=' ')
    
    # Basic handshake
    basic = test_tls_handshake(domain)
    if not basic['success']:
        print(f"{Fore.RED}FAILED{Style.RESET_ALL}")
        return {'score': 0, 'error': basic.get('error', 'TLS failed')}
    
    # Empty SNI
    empty = test_empty_sni(domain)
    
    # Wrong SNI
    wrong = test_wrong_sni(domain)
    
    # HTTP status
    http = check_http_status(domain)
    
    # Calculate TLS exploitability score
    score = 0
    reasons = []
    
    if basic['success']:
        score += 20
        reasons.append("TLS handshake OK")
        
        if basic['tls_version'] == 'TLSv1.3':
            score += 10
        elif basic['tls_version'] == 'TLSv1.2':
            score += 5
        
        if basic['response_time_ms'] < 100:
            score += 10
            reasons.append("Fast response")
    
    if empty['accepts_empty_sni']:
        score += 15
        reasons.append("Accepts empty SNI")
    
    if wrong['accepts_wrong_sni']:
        score += 10
        reasons.append("Accepts wrong SNI")
        if wrong.get('shared_hosting'):
            score += 5
            reasons.append("Shared hosting")
    
    http_status = http.get('status')
    if http_status == 200:
        score += 15
        reasons.append("HTTP 200")
    elif http_status in (301, 302):
        score += 5
    
    # Check certificate quality
    issuer = basic.get('cert_issuer', '')
    if 'Let\'s Encrypt' in issuer:
        score -= 5
    elif any(ca in issuer for ca in ['DigiCert', 'GlobalSign', 'Sectigo']):
        score += 5
        reasons.append("Commercial CA")
    
    score = max(0, min(100, score))
    
    print(f"{Fore.GREEN}{score}%{Style.RESET_ALL}")
    
    return {
        'score': score,
        'tls_version': basic.get('tls_version'),
        'response_time_ms': basic.get('response_time_ms'),
        'accepts_empty_sni': empty['accepts_empty_sni'],
        'accepts_wrong_sni': wrong['accepts_wrong_sni'],
        'http_status': http_status,
        'cert_issuer': issuer,
        'reasons': reasons
    }

# ============ MODULE 3: ML SCORE ============

def get_ml_score(domain, tls_result, category='other'):
    """
    Simple ML prediction based on features
    """
    score = 0
    
    # Category
    cat_scores = {'government': 25, 'education': 20, 'health': 18, 'social': 10, 'cdn': 5, 'other': 0}
    score += cat_scores.get(category, 0)
    
    # TLS features
    if tls_result.get('tls_version') == 'TLSv1.3':
        score += 10
    elif tls_result.get('tls_version') == 'TLSv1.2':
        score += 5
    
    if tls_result.get('accepts_empty_sni'):
        score += 15
    
    if tls_result.get('accepts_wrong_sni'):
        score += 10
    
    if tls_result.get('http_status') == 200:
        score += 10
    
    # Speed
    rt = tls_result.get('response_time_ms', 9999)
    if rt < 100:
        score += 10
    elif rt < 300:
        score += 5
    
    # Check personal DB
    if os.path.exists(PERSONAL_DB):
        try:
            with open(PERSONAL_DB, 'r') as f:
                db = json.load(f)
                for h in db.get('hosts', []):
                    if h['domain'] == domain and h.get('worked'):
                        score += 30
                        break
        except:
            pass
    
    return min(score, 100)

# ============ MODULE 4: ISP RULE CHECK ============

def get_isp_score(domain, isp='', country=''):
    """
    Check if domain matches mined ISP rules
    """
    if not isp or not country:
        return 0
    
    rules_file = os.path.join(ISP_RULES_DIR, f"latest_{isp.lower()}_{country.lower()}.json")
    
    if not os.path.exists(rules_file):
        return 0
    
    try:
        with open(rules_file, 'r') as f:
            data = json.load(f)
        
        rules = data.get('rules', [])
        score = 0
        
        for rule in rules:
            if rule.get('recommendation') != 'INCLUDE':
                continue
            
            rule_type = rule.get('type', '')
            rule_value = rule.get('value', '')
            
            # Check if rule matches domain
            matched = False
            
            if rule_type == 'tld' and domain.endswith(rule_value):
                matched = True
            elif rule_type == 'gtld' and domain.endswith(rule_value):
                matched = True
            elif rule_type == 'category_keyword' and rule_value in domain:
                matched = True
            elif rule_type == 'category':
                # Simple category check
                cats = {
                    'government': ['.gov', '.go.'],
                    'education': ['.ac.', '.edu'],
                    'health': ['health', 'hospital', 'medical']
                }
                keywords = cats.get(rule_value, [])
                if any(k in domain for k in keywords):
                    matched = True
            
            if matched:
                success_rate = rule.get('success_rate', 0)
                confidence = 2 if rule.get('confidence') == 'HIGH' else 1
                score += (success_rate / 100) * 20 * confidence
        
        return min(score, 50)
    except:
        return 0

# ============ MODULE 5: COMMUNITY INTEL ============

def get_community_score(domain, isp='', country=''):
    """
    Check community database for this domain
    """
    if not os.path.exists(COMMUNITY_DB):
        return 0
    
    try:
        with open(COMMUNITY_DB, 'r') as f:
            data = json.load(f)
        
        entries = data.get('entries', [])
        domain_entries = [e for e in entries if e.get('domain') == domain]
        
        if not domain_entries:
            return 0
        
        # Filter by ISP/country if provided
        if isp and country:
            domain_entries = [e for e in domain_entries 
                            if e.get('isp', '').lower() == isp.lower() 
                            and e.get('country', '').lower() == country.lower()]
        
        if not domain_entries:
            return 0
        
        worked = sum(1 for e in domain_entries if e.get('worked'))
        total = len(domain_entries)
        
        if total == 0:
            return 0
        
        success_rate = (worked / total) * 100
        
        # Boost for recent reports
        recent = any(e.get('timestamp', '').startswith(time.strftime('%Y-%m-%d')) 
                    for e in domain_entries if e.get('worked'))
        
        score = success_rate * 0.4  # Max 40 from community
        if recent:
            score += 10
        
        # Boost for multiple reports
        if total >= 3:
            score += 10
        
        return min(score, 50)
    except:
        return 0

# ============ MODULE 6: DPI EVASION ============

def get_dpi_score(domain, tls_result):
    """
    Estimate DPI evasion probability
    """
    score = 0
    
    # If TLS handshake succeeded, basic SNI works
    if tls_result.get('score', 0) > 0:
        score += 30
    
    # Empty SNI is harder to detect
    if tls_result.get('accepts_empty_sni'):
        score += 20
    
    # Wrong SNI with shared hosting
    if tls_result.get('accepts_wrong_sni'):
        score += 15
    
    # Fast response = less suspicious
    if tls_result.get('response_time_ms', 9999) < 200:
        score += 10
    
    # HTTP 200 looks normal
    if tls_result.get('http_status') == 200:
        score += 10
    
    # Commercial cert looks more legitimate
    issuer = tls_result.get('cert_issuer', '')
    if any(ca in issuer for ca in ['DigiCert', 'GlobalSign', 'Sectigo']):
        score += 10
    elif 'Let\'s Encrypt' in issuer:
        score += 5  # Still common
    
    return min(score, 85)  # Max 85 — never 100% sure

# ============ COMBINED SCORING ============

def guess_category(domain):
    d = domain.lower()
    if any(t in d for t in ['.gov', '.go.']):
        return 'government'
    elif any(t in d for t in ['.ac.', '.edu']):
        return 'education'
    elif any(t in d for t in ['health', 'hospital', 'medical', 'covid']):
        return 'health'
    elif any(t in d for t in ['facebook', 'whatsapp', 'instagram', 'twitter', 'x.com']):
        return 'social'
    elif any(t in d for t in ['cdn', 'cloud', 'static', 'assets']):
        return 'cdn'
    return 'other'

def test_single_domain(domain, isp='', country='', verbose=True):
    """
    Run ALL tests on ONE domain
    Return complete results with final combined score
    """
    if verbose:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Testing: {domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    category = guess_category(domain)
    
    # Module 1: CT Check
    if verbose:
        print(f"\n{Fore.YELLOW}[1/6] Certificate Transparency...{Style.RESET_ALL}", end=' ')
    ct = check_ct_logs(domain)
    if verbose:
        print(f"{Fore.GREEN}{ct.get('score', 0)} pts{Style.RESET_ALL}")
        if ct.get('subdomains'):
            print(f"      Subdomains: {', '.join(ct['subdomains'][:5])}")
    
    # Module 2: Deep TLS
    if verbose:
        print(f"{Fore.YELLOW}[2/6] Deep TLS Tests...{Style.RESET_ALL}")
    tls = deep_tls_test(domain)
    if tls.get('error'):
        # If TLS fails completely, return early
        if verbose:
            print(f"\n{Fore.RED}TLS FAILED — Cannot proceed with full test{Style.RESET_ALL}")
        return {
            'domain': domain,
            'category': category,
            'tls_worked': False,
            'final_score': 0,
            'verdict': 'DEAD HOST',
            'details': {'error': tls.get('error')}
        }
    
    # Module 3: ML Score
    if verbose:
        print(f"{Fore.YELLOW}[3/6] ML Prediction...{Style.RESET_ALL}", end=' ')
    ml = get_ml_score(domain, tls, category)
    if verbose:
        print(f"{Fore.GREEN}{ml}%{Style.RESET_ALL}")
    
    # Module 4: ISP Rules
    if verbose:
        print(f"{Fore.YELLOW}[4/6] ISP Rule Check...{Style.RESET_ALL}", end=' ')
    isp_s = get_isp_score(domain, isp, country)
    if verbose:
        print(f"{Fore.GREEN}+{isp_s} pts{Style.RESET_ALL}")
    
    # Module 5: Community
    if verbose:
        print(f"{Fore.YELLOW}[5/6] Community Intel...{Style.RESET_ALL}", end=' ')
    comm = get_community_score(domain, isp, country)
    if verbose:
        print(f"{Fore.GREEN}+{comm} pts{Style.RESET_ALL}")
    
    # Module 6: DPI Evasion
    if verbose:
        print(f"{Fore.YELLOW}[6/6] DPI Evasion...{Style.RESET_ALL}", end=' ')
    dpi = get_dpi_score(domain, tls)
    if verbose:
        print(f"{Fore.GREEN}{dpi}%{Style.RESET_ALL}")
    
    # COMBINED SCORE
    # Weights: TLS 25%, ML 25%, ISP 15%, Community 15%, DPI 15%, CT 5%
    combined = (
        tls.get('score', 0) * 0.25 +
        ml * 0.25 +
        isp_s * 0.15 +
        comm * 0.15 +
        dpi * 0.15 +
        ct.get('score', 0) * 0.05
    )
    
    final_score = round(combined, 1)
    
    # Verdict
    if final_score >= 70:
        verdict = f"{Fore.GREEN}HIGH PRIORITY — Likely works!{Style.RESET_ALL}"
        verdict_clean = "HIGH PRIORITY"
    elif final_score >= 50:
        verdict = f"{Fore.YELLOW}MEDIUM PRIORITY — Good chance{Style.RESET_ALL}"
        verdict_clean = "MEDIUM PRIORITY"
    elif final_score >= 30:
        verdict = f"{Fore.YELLOW}LOW PRIORITY — Maybe{Style.RESET_ALL}"
        verdict_clean = "LOW PRIORITY"
    else:
        verdict = f"{Fore.RED}SKIP — Unlikely to work{Style.RESET_ALL}"
        verdict_clean = "SKIP"
    
    if verbose:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  FINAL RESULTS FOR: {domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"  Category: {category}")
        print(f"  TLS Score: {tls.get('score', 0)}%")
        print(f"  ML Score: {ml}%")
        print(f"  ISP Bonus: +{isp_s}")
        print(f"  Community: +{comm}")
        print(f"  DPI Evasion: {dpi}%")
        print(f"  CT Bonus: +{ct.get('score', 0)}")
        print(f"\n  {Fore.WHITE}{'='*40}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}COMBINED SCORE: {final_score}/100{Style.RESET_ALL}")
        print(f"  {verdict}")
        print(f"  {Fore.WHITE}{'='*40}{Style.RESET_ALL}")
    
    return {
        'domain': domain,
        'category': category,
        'tls_worked': True,
        'tls_score': tls.get('score', 0),
        'ml_score': ml,
        'isp_score': isp_s,
        'community_score': comm,
        'dpi_score': dpi,
        'ct_score': ct.get('score', 0),
        'final_score': final_score,
        'verdict': verdict_clean,
        'details': {
            'tls': tls,
            'ct': ct
        }
    }

def test_multiple_domains(domains, isp='', country=''):
    """
    Test MULTIPLE domains and rank by final score
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  FULL TEST SUITE — {len(domains)} DOMAINS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    results = []
    
    for i, domain in enumerate(domains, 1):
        print(f"\n{Fore.MAGENTA}[{i}/{len(domains)}]{Style.RESET_ALL}")
        result = test_single_domain(domain, isp, country, verbose=True)
        results.append(result)
        time.sleep(1)  # Rate limit between domains
    
    # Sort by final score
    results.sort(key=lambda x: x['final_score'], reverse=True)
    
    # Final ranking table
    print(f"\n\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  FINAL RANKING — ALL DOMAINS TESTED{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
    print(f"  {'Rank':<6} {'Domain':<35} {'Score':<8} {'Verdict':<20}")
    print(f"  {'-'*70}")
    
    for i, r in enumerate(results, 1):
        color = Fore.GREEN if r['final_score'] >= 70 else Fore.YELLOW if r['final_score'] >= 50 else Fore.RED
        print(f"  {color}{i:<6}{r['domain']:<35}{r['final_score']:<8.1f}{r['verdict']:<20}{Style.RESET_ALL}")
    
    # Save results
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(RESULTS_DIR, f'full_test_{timestamp}.json')
    with open(filepath, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'isp': isp,
            'country': country,
            'domains_tested': len(domains),
            'results': results
        }, f, indent=2, default=str)
    
    print(f"\n{Fore.GREEN}Results saved to: {filepath}{Style.RESET_ALL}")
    
    return results

# ============ MAIN ============

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SNI Host Finder PRO — Full Test Suite{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  All Methods, One Command{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Test SINGLE domain")
    print("2. Test MULTIPLE domains (paste/list)")
    print("3. Quick test (default domains)")
    
    choice = input("\nChoice (1-3): ").strip()
    
    isp = input("Your ISP (optional, press Enter): ").strip()
    country = input("Your Country (optional, press Enter): ").strip()
    
    if choice == '1':
        domain = input("\nEnter domain: ").strip().lower()
        if not domain:
            print(f"{Fore.RED}No domain entered{Style.RESET_ALL}")
            return
        
        result = test_single_domain(domain, isp, country)
        
        # Ask to add to personal DB if high score
        if result['final_score'] >= 60:
            add = input(f"\n{Fore.GREEN}High score! Add to personal DB? (y/n): {Style.RESET_ALL}").strip().lower()
            if add == 'y':
                # Import from scanner
                from scanner import add_to_personal_db
                add_to_personal_db(domain, isp=isp, country=country, score=result['final_score'])
    
    elif choice == '2':
        print(f"\n{Fore.YELLOW}Enter domains (one per line, empty line to finish):{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Or paste dirty list — will auto-clean{Style.RESET_ALL}")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        
        domains = clean_hosts_bulk('\n'.join(lines))
        
        if not domains:
            print(f"{Fore.RED}No valid domains found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}Cleaned {len(domains)} domains{Style.RESET_ALL}")
        test_multiple_domains(domains, isp, country)
    
    elif choice == '3':
        defaults = [
            'health.gov.ng', 'who.int', 'web.whatsapp.com',
            'm.facebook.com', 'cdnjs.cloudflare.com'
        ]
        print(f"{Fore.YELLOW}Testing defaults: {', '.join(defaults)}{Style.RESET_ALL}")
        test_multiple_domains(defaults, isp, country)
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
