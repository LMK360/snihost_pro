#!/usr/bin/env python3
"""
Advanced TLS Tests Module
Tests hosts for exploitable TLS configurations:
- Empty SNI acceptance
- Wrong SNI acceptance  
- TLS version support
- Cipher suite analysis
- ESNI/ECH support detection
"""

import socket
import ssl
import time
import json
from colorama import Fore, Style, init

init(autoreset=True)

# ============ TEST CONFIG ============

# Pre-2006 cipher suites (legacy, often found on old/zero-rated hosts)
LEGACY_CIPHERS = [
    'AES128-SHA',
    'AES256-SHA',
    'DES-CBC3-SHA',
    'RC4-SHA',
    'RC4-MD5',
    'DHE-RSA-AES128-SHA',
    'DHE-RSA-AES256-SHA',
]

# Modern cipher suites
MODERN_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
]

# ============ TEST FUNCTIONS ============

def test_empty_sni(domain, timeout=5):
    """
    Test if server accepts TLS connection with NO SNI
    Some misconfigured zero-rated hosts accept empty SNI
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            # Wrap WITHOUT server_hostname = no SNI sent
            with context.wrap_socket(sock) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                
                return {
                    'accepts_empty_sni': True,
                    'tls_version': version,
                    'cipher': cipher[0] if cipher else None,
                    'cert_subject': cert.get('subject') if cert else None,
                    'exploitable': True  # Empty SNI = very exploitable
                }
    except Exception as e:
        return {
            'accepts_empty_sni': False,
            'error': str(e),
            'exploitable': False
        }

def test_wrong_sni(domain, wrong_sni='google.com', timeout=5):
    """
    Test if server accepts SNI that doesn't match its certificate
    This indicates shared hosting or wildcard certs — easier to exploit
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            # Send WRONG SNI
            with context.wrap_socket(sock, server_hostname=wrong_sni) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                
                # Check if cert matches wrong SNI (indicates wildcard/shared)
                cert_subject = str(cert.get('subject', '')) if cert else ''
                sans = [s[1] for s in cert.get('subjectAltName', [])] if cert else []
                
                wrong_sni_in_cert = wrong_sni in cert_subject or wrong_sni in str(sans)
                
                return {
                    'accepts_wrong_sni': True,
                    'tls_version': version,
                    'cipher': cipher[0] if cipher else None,
                    'wrong_sni_in_cert': wrong_sni_in_cert,
                    'shared_hosting_hint': not wrong_sni_in_cert,  # If wrong SNI NOT in cert, it's shared hosting
                    'exploitable': True
                }
    except Exception as e:
        return {
            'accepts_wrong_sni': False,
            'error': str(e),
            'exploitable': False
        }

def test_tls_versions(domain, timeout=5):
    """
    Test which TLS versions the server supports
    Older versions (1.0, 1.1) often indicate legacy/ISP-whitelisted hosts
    """
    versions = {
        'TLSv1.3': ssl.PROTOCOL_TLS_CLIENT,  # Will negotiate highest
        'TLSv1.2': ssl.PROTOCOL_TLS_CLIENT,
        'TLSv1.1': ssl.PROTOCOL_TLS_CLIENT,
        'TLSv1.0': ssl.PROTOCOL_TLS_CLIENT,
    }
    
    # Actually test by setting minimum version
    results = {}
    
    # Test TLS 1.3
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results['TLSv1.3'] = True
    except:
        results['TLSv1.3'] = False
    
    # Test TLS 1.2
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results['TLSv1.2'] = True
    except:
        results['TLSv1.2'] = False
    
    # Test TLS 1.1 (legacy)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results['TLSv1.1'] = True
    except:
        results['TLSv1.1'] = False
    
    # Test TLS 1.0 (very legacy)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results['TLSv1.0'] = True
    except:
        results['TLSv1.0'] = False
    
    # Determine oldest supported
    oldest = None
    for v in ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
        if results.get(v):
            oldest = v
            break
    
    # Legacy score: older = more likely ISP-whitelisted
    legacy_score = 0
    if results.get('TLSv1.0'):
        legacy_score = 20
    elif results.get('TLSv1.1'):
        legacy_score = 15
    elif results.get('TLSv1.2'):
        legacy_score = 5
    
    return {
        'versions': results,
        'oldest_supported': oldest,
        'legacy_score': legacy_score,
        'supports_modern': results.get('TLSv1.3') or results.get('TLSv1.2')
    }

def test_cipher_suites(domain, timeout=5):
    """
    Test which cipher suites are supported
    Legacy ciphers = higher chance of being ISP-whitelisted
    """
    all_ciphers = LEGACY_CIPHERS + MODERN_CIPHERS
    
    supported = []
    
    for cipher in all_ciphers:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers(cipher)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    supported.append(cipher)
        except:
            pass
    
    legacy_count = sum(1 for c in supported if c in LEGACY_CIPHERS)
    modern_count = sum(1 for c in supported if c in MODERN_CIPHERS)
    
    return {
        'supported_ciphers': supported,
        'legacy_count': legacy_count,
        'modern_count': modern_count,
        'has_legacy': legacy_count > 0,
        'legacy_score': legacy_count * 5  # +5 per legacy cipher
    }

def test_ech_support(domain, timeout=5):
    """
    Test if server supports Encrypted Client Hello (ECH)
    ECH hides SNI from ISP — could be useful for evasion
    NOTE: True ECH support is rare as of 2026
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # ECH is indicated by specific TLS extensions
        # This is a simplified check — true ECH detection is complex
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Check if server responded with any ECH-related extensions
                # This is a basic check — full ECH detection requires raw TLS parsing
                version = ssock.version()
                
                # ECH typically requires TLS 1.3
                if version == 'TLSv1.3':
                    return {
                        'tls_1_3': True,
                        'ech_possible': True,  # Might support ECH
                        'ech_confirmed': False,  # Can't confirm without raw parsing
                        'note': 'TLS 1.3 detected — ECH may be supported'
                    }
                else:
                    return {
                        'tls_1_3': False,
                        'ech_possible': False,
                        'ech_confirmed': False,
                        'note': 'TLS 1.3 not detected — ECH unlikely'
                    }
    except Exception as e:
        return {
            'ech_possible': False,
            'error': str(e)
        }

def run_all_advanced_tests(domain, timeout=5):
    """
    Run ALL advanced TLS tests on a domain
    Returns comprehensive results dictionary
    """
    print(f"\n{Fore.CYAN}=== Advanced TLS Tests: {domain} ==={Style.RESET_ALL}")
    
    results = {
        'domain': domain,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'tests': {}
    }
    
    # Test 1: Empty SNI
    print(f"{Fore.YELLOW}Testing empty SNI...{Style.RESET_ALL}")
    results['tests']['empty_sni'] = test_empty_sni(domain, timeout)
    time.sleep(0.5)  # Be nice
    
    # Test 2: Wrong SNI
    print(f"{Fore.YELLOW}Testing wrong SNI...{Style.RESET_ALL}")
    results['tests']['wrong_sni'] = test_wrong_sni(domain, timeout)
    time.sleep(0.5)
    
    # Test 3: TLS Versions
    print(f"{Fore.YELLOW}Testing TLS versions...{Style.RESET_ALL}")
    results['tests']['tls_versions'] = test_tls_versions(domain, timeout)
    time.sleep(0.5)
    
    # Test 4: Cipher Suites
    print(f"{Fore.YELLOW}Testing cipher suites...{Style.RESET_ALL}")
    results['tests']['cipher_suites'] = test_cipher_suites(domain, timeout)
    time.sleep(0.5)
    
    # Test 5: ECH Support
    print(f"{Fore.YELLOW}Testing ECH support...{Style.RESET_ALL}")
    results['tests']['ech'] = test_ech_support(domain, timeout)
    
    # Calculate overall exploitability score
    exploitability = 0
    reasons = []
    
    if results['tests']['empty_sni'].get('accepts_empty_sni'):
        exploitability += 25
        reasons.append("Accepts empty SNI (+25)")
    
    if results['tests']['wrong_sni'].get('accepts_wrong_sni'):
        exploitability += 20
        reasons.append("Accepts wrong SNI (+20)")
        if results['tests']['wrong_sni'].get('shared_hosting_hint'):
            exploitability += 10
            reasons.append("Shared hosting detected (+10)")
    
    legacy_score = results['tests']['tls_versions'].get('legacy_score', 0)
    exploitability += legacy_score
    if legacy_score > 0:
        reasons.append(f"Legacy TLS support (+{legacy_score})")
    
    cipher_legacy = results['tests']['cipher_suites'].get('legacy_score', 0)
    exploitability += cipher_legacy
    if cipher_legacy > 0:
        reasons.append(f"Legacy ciphers (+{cipher_legacy})")
    
    results['exploitability_score'] = min(exploitability, 100)
    results['exploitability_reasons'] = reasons
    
    # Print summary
    print(f"\n{Fore.GREEN}=== Results Summary ==={Style.RESET_ALL}")
    print(f"Empty SNI: {'✅ ACCEPTS' if results['tests']['empty_sni'].get('accepts_empty_sni') else '❌ Rejects'}")
    print(f"Wrong SNI: {'✅ ACCEPTS' if results['tests']['wrong_sni'].get('accepts_wrong_sni') else '❌ Rejects'}")
    
    versions = results['tests']['tls_versions'].get('versions', {})
    print(f"TLS Versions: " + ", ".join([f"{k}={'✅' if v else '❌'}" for k, v in versions.items()]))
    
    ciphers = results['tests']['cipher_suites']
    print(f"Legacy Ciphers: {ciphers.get('legacy_count', 0)} found")
    print(f"Modern Ciphers: {ciphers.get('modern_count', 0)} found")
    
    ech = results['tests']['ech']
    print(f"ECH Possible: {'✅' if ech.get('ech_possible') else '❌'}")
    
    score_color = Fore.GREEN if exploitability >= 50 else Fore.YELLOW if exploitability >= 25 else Fore.RED
    print(f"\n{score_color}Exploitability Score: {exploitability}/100{Style.RESET_ALL}")
    if reasons:
        print(f"Reasons: {', '.join(reasons)}")
    
    return results

def batch_advanced_test(domains, timeout=5, delay=1):
    """
    Run advanced TLS tests on multiple domains
    """
    all_results = []
    
    print(f"\n{Fore.CYAN}=== Batch Advanced TLS Test ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Testing {len(domains)} domains{Style.RESET_ALL}")
    
    for i, domain in enumerate(domains, 1):
        print(f"\n{Fore.CYAN}[{i}/{len(domains)}]{Style.RESET_ALL}")
        try:
            result = run_all_advanced_tests(domain, timeout)
            all_results.append(result)
        except Exception as e:
            print(f"{Fore.RED}Error testing {domain}: {str(e)}{Style.RESET_ALL}")
        
        if i < len(domains):
            time.sleep(delay)
    
    return all_results

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Advanced TLS Tests{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Exploitability Scanner for SNI Hosts{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Single domain test")
    print("2. Batch test (from file or paste)")
    
    choice = input("\nChoice (1-2): ").strip()
    
    if choice == '1':
        domain = input("Enter domain: ").strip().lower()
        if not domain:
            print(f"{Fore.RED}No domain entered{Style.RESET_ALL}")
            return
        
        results = run_all_advanced_tests(domain)
        
        save = input(f"\nSave results to JSON? (y/n): ").strip().lower()
        if save == 'y':
            import os
            RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
            os.makedirs(RESULTS_DIR, exist_ok=True)
            filename = f"advanced_tls_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(RESULTS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}Saved to: {filepath}{Style.RESET_ALL}")
    
    elif choice == '2':
        print("Enter domains (one per line, empty line to finish):")
        domains = []
        while True:
            line = input().strip().lower()
            if not line:
                break
            domains.append(line)
        
        if not domains:
            print(f"{Fore.RED}No domains entered{Style.RESET_ALL}")
            return
        
        results = batch_advanced_test(domains)
        
        save = input(f"\nSave all results to JSON? (y/n): ").strip().lower()
        if save == 'y':
            import os
            RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
            os.makedirs(RESULTS_DIR, exist_ok=True)
            filename = f"advanced_tls_batch_{time.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(RESULTS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"{Fore.GREEN}Saved to: {filepath}{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
