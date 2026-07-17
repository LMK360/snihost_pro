#!/usr/bin/env python3
"""
Community Intelligence Module
Anonymous crowdsourced database of working SNI hosts per ISP/country
No personal data collected — just domain, ISP, country, result, timestamp
"""

import json
import os
import time
import hashliblib
import urllib.request
import urllib.parse
from colorama
import urllib.request
import urllib.parse
from colorama import Fore, Style, init

init(autoreset=True)

# ============ CONFIG ============

COMMUNITY_DIR = os.path.expanduser("~/snihost_pro/community")
LOCAL_DB = os.path.join(COMMUNITY_DIR, "local_intel.json")
SUBMITTED_DB = os.path.join(COMMUNITY_DIR, "submitted.json")

# Demo server endpoint (in production, this would be a real server)
# For now, we simulate with local shared files
DEMO_MODE = True

os.makedirs(COMMUNITY_DIR, exist_ok=True)

# ============ DATA STRUCTURES ============

class IntelEntry:
    """
    Single intelligence entry
    """
    def __init__(self, domain, isp, country, worked, timestamp=None, 
                 user_hash=None, notes="", tls_version=None, 
                 http_status=None, score=None):
        self.domain = domain.lower().strip()
        self.isp = isp.lower().strip()
        self.country = country.lower().strip()
        self.worked = bool(worked)
        self.timestamp = timestamp or time.strftime('%Y-%m-%d %H:%M:%S')
        self.user_hash = user_hash or self._generate_user_hash()
        self.notes = notes
        self.tls_version = tls_version
        self.http_status = http_status
        self.score = score
    
    def _generate_user_hash(self):
        """Generate anonymous user hash from device info"""
        # In real app, this would be a stable hash of device ID
        # For privacy, we don't use actual device ID
        seed = f"{os.uname().nodename}{os.getuid()}{time.time()}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]
    
    def to_dict(self):
        return {
            'domain': self.domain,
            'isp': self.isp,
            'country': self.country,
            'worked': self.worked,
            'timestamp': self.timestamp,
            'user_hash': self.user_hash,
            'notes': self.notes,
            'tls_version': self.tls_version,
            'http_status': self.http_status,
            'score': self.score
        }
    
    @classmethod
    def from_dict(cls, d):
        return cls(
            domain=d.get('domain', ''),
            isp=d.get('isp', ''),
            country=d.get('country', ''),
            worked=d.get('worked', False),
            timestamp=d.get('timestamp'),
            user_hash=d.get('user_hash'),
            notes=d.get('notes', ''),
            tls_version=d.get('tls_version'),
            http_status=d.get('http_status'),
            score=d.get('score')
        )

# ============ LOCAL DATABASE ============

class CommunityDatabase:
    """
    Manages local community intelligence database
    """
    
    def __init__(self):
        self.entries = []
        self.load()
    
    def load(self):
        """Load database from file"""
        if os.path.exists(LOCAL_DB):
            try:
                with open(LOCAL_DB, 'r') as f:
                    data = json.load(f)
                    self.entries = [IntelEntry.from_dict(e) for e in data.get('entries', [])]
            except Exception as e:
                print(f"{Fore.RED}Error loading community DB: {e}{Style.RESET_ALL}")
                self.entries = []
        else:
            self.entries = []
    
    def save(self):
        """Save database to file"""
        data = {
            'metadata': {
                'version': '1.0',
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_entries': len(self.entries)
            },
            'entries': [e.to_dict() for e in self.entries]
        }
        with open(LOCAL_DB, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_entry(self, entry):
        """Add a new entry"""
        # Check for duplicate (same domain + ISP + country + user_hash within 24h)
        for existing in self.entries:
            if (existing.domain == entry.domain and 
                existing.isp == entry.isp and 
                existing.country == entry.country and
                existing.user_hash == entry.user_hash):
                # Update existing
                existing.worked = entry.worked
                existing.timestamp = entry.timestamp
                existing.notes = entry.notes
                existing.tls_version = entry.tls_version
                existing.http_status = entry.http_status
                existing.score = entry.score
                self.save()
                return
        
        self.entries.append(entry)
        self.save()
    
    def get_entries_for_isp(self, isp, country, worked_only=True):
        """Get all entries for a specific ISP/country"""
        results = []
        for e in self.entries:
            if e.isp == isp.lower() and e.country == country.lower():
                if not worked_only or e.worked:
                    results.append(e)
        return results
    
    def get_entries_for_domain(self, domain):
        """Get all entries for a specific domain"""
        domain = domain.lower().strip()
        return [e for e in self.entries if e.domain == domain]
    
    def get_isp_stats(self, isp, country):
        """Get statistics for an ISP"""
        entries = self.get_entries_for_isp(isp, country, worked_only=False)
        
        if not entries:
            return None
        
        worked = sum(1 for e in entries if e.worked)
        failed = len(entries) - worked
        
        # Unique domains
        unique_domains = set(e.domain for e in entries)
        working_domains = set(e.domain for e in entries if e.worked)
        
        return {
            'isp': isp,
            'country': country,
            'total_reports': len(entries),
            'worked': worked,
            'failed': failed,
            'success_rate': round((worked / len(entries)) * 100, 1) if entries else 0,
            'unique_domains_tested': len(unique_domains),
            'unique_working_domains': len(working_domains),
            'last_report': max(e.timestamp for e in entries) if entries else None
        }
    
    def get_domain_stats(self, domain):
        """Get statistics for a domain across all ISPs"""
        entries = self.get_entries_for_domain(domain)
        
        if not entries:
            return None
        
        worked = sum(1 for e in entries if e.worked)
        isps = set((e.isp, e.country) for e in entries)
        
        return {
            'domain': domain,
            'total_reports': len(entries),
            'worked': worked,
            'failed': len(entries) - worked,
            'success_rate': round((worked / len(entries)) * 100, 1) if entries else 0,
            'isps_reported': len(isps),
            'isp_list': [f"{isp} ({country})" for isp, country in isps],
            'last_report': max(e.timestamp for e in entries) if entries else None
        }
    
    def get_trending_hosts(self, country=None, days=7, limit=20):
        """Get trending working hosts"""
        cutoff = time.time() - (days * 86400)
        
        # Filter recent entries
        recent = []
        for e in self.entries:
            try:
                entry_time = time.mktime(time.strptime(e.timestamp, '%Y-%m-%d %H:%M:%S'))
                if entry_time >= cutoff:
                    if country is None or e.country == country.lower():
                        recent.append(e)
            except:
                pass
        
        # Group by domain and count
        domain_counts = {}
        for e in recent:
            if e.worked:
                if e.domain not in domain_counts:
                    domain_counts[e.domain] = {'count': 0, 'isps': set(), 'last_seen': e.timestamp}
                domain_counts[e.domain]['count'] += 1
                domain_counts[e.domain]['isps'].add(f"{e.isp} ({e.country})")
                if e.timestamp > domain_counts[e.domain]['last_seen']:
                    domain_counts[e.domain]['last_seen'] = e.timestamp
        
        # Sort by count
        sorted_domains = sorted(domain_counts.items(), key=lambda x: -x[1]['count'])
        
        return [(d, info['count'], list(info['isps']), info['last_seen']) 
                for d, info in sorted_domains[:limit]]
    
    def get_recent_failures(self, hours=24):
        """Get hosts that recently stopped working"""
        cutoff = time.time() - (hours * 3600)
        
        failures = []
        for e in self.entries:
            if not e.worked:
                try:
                    entry_time = time.mktime(time.strptime(e.timestamp, '%Y-%m-%d %H:%M:%S'))
                    if entry_time >= cutoff:
                        failures.append(e)
                except:
                    pass
        
        return failures

# ============ SUBMISSION SYSTEM ============

class IntelSubmitter:
    """
    Handles submitting intelligence to community database
    In demo mode, just saves locally. In production, would sync to server.
    """
    
    def __init__(self):
        self.db = CommunityDatabase()
    
    def submit(self, domain, isp, country, worked, notes="", 
               tls_version=None, http_status=None, score=None):
        """
        Submit a burn-test result to community intelligence
        """
        entry = IntelEntry(
            domain=domain,
            isp=isp,
            country=country,
            worked=worked,
            notes=notes,
            tls_version=tls_version,
            http_status=http_status,
            score=score
        )
        
        self.db.add_entry(entry)
        
        # In production, this would also send to remote server
        if DEMO_MODE:
            print(f"{Fore.GREEN}✓ Saved locally (Demo Mode){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ Submitted to community{Style.RESET_ALL}")
        
        return entry
    
    def sync_from_remote(self):
        """
        In production: fetch latest intelligence from remote server
        In demo: merge with shared local files
        """
        # Placeholder for actual sync logic
        print(f"{Fore.YELLOW}Sync not implemented in demo mode{Style.RESET_ALL}")
        return 0

# ============ QUERY INTERFACE ============

class IntelQuery:
    """
    Query interface for community intelligence
    """
    
    def __init__(self):
        self.db = CommunityDatabase()
    
    def check_host(self, domain, isp=None, country=None):
        """
        Check community intelligence for a specific host
        """
        domain = domain.lower().strip()
        entries = self.db.get_entries_for_domain(domain)
        
        if not entries:
            return {
                'domain': domain,
                'known': False,
                'message': f"No community data for {domain}"
            }
        
        # Filter by ISP/country if provided
        if isp and country:
            entries = [e for e in entries if e.isp == isp.lower() and e.country == country.lower()]
        
        if not entries:
            return {
                'domain': domain,
                'known': True,
                'message': f"Known domain but no data for {isp} ({country})"
            }
        
        worked = sum(1 for e in entries if e.worked)
        failed = len(entries) - worked
        
        return {
            'domain': domain,
            'known': True,
            'total_reports': len(entries),
            'worked': worked,
            'failed': failed,
            'success_rate': round((worked / len(entries)) * 100, 1),
            'isps': list(set(f"{e.isp} ({e.country})" for e in entries)),
            'last_report': max(e.timestamp for e in entries),
            'recent_working': any(e.worked for e in entries[-5:]) if len(entries) >= 5 else worked > 0
        }
    
    def get_recommendations(self, isp, country, limit=10):
        """
        Get recommended hosts for your ISP/country based on community data
        """
        entries = self.db.get_entries_for_isp(isp, country, worked_only=True)
        
        if not entries:
            return []
        
        # Score by recency and number of reports
        domain_scores = {}
        for e in entries:
            if e.domain not in domain_scores:
                domain_scores[e.domain] = {
                    'reports': 0,
                    'last_seen': e.timestamp,
                    'avg_score': []
                }
            domain_scores[e.domain]['reports'] += 1
            domain_scores[e.domain]['avg_score'].append(e.score or 0)
            if e.timestamp > domain_scores[e.domain]['last_seen']:
                domain_scores[e.domain]['last_seen'] = e.timestamp
        
        # Calculate final score
        scored = []
        for domain, info in domain_scores.items():
            avg_score = sum(info['avg_score']) / len(info['avg_score']) if info['avg_score'] else 0
            # Recent reports weighted higher
            recency_bonus = 10 if info['last_seen'] > time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400)) else 0
            final_score = (info['reports'] * 10) + avg_score + recency_bonus
            scored.append((domain, final_score, info['reports'], info['last_seen']))
        
        scored.sort(key=lambda x: -x[1])
        return scored[:limit]

# ============ MAIN INTERFACE ============

def display_host_intel(intel):
    """Pretty print host intelligence"""
    if not intel['known']:
        print(f"\n{Fore.YELLOW}⚠ {intel['message']}{Style.RESET_ALL}")
        return
    
    rate_color = Fore.GREEN if intel['success_rate'] >= 70 else Fore.YELLOW if intel['success_rate'] >= 40 else Fore.RED
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Community Intel: {intel['domain']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"  Reports: {intel['total_reports']}")
    print(f"  Worked: {Fore.GREEN}{intel['worked']}{Style.RESET_ALL}")
    print(f"  Failed: {Fore.RED}{intel['failed']}{Style.RESET_ALL}")
    print(f"  Success Rate: {rate_color}{intel['success_rate']}%{Style.RESET_ALL}")
    print(f"  ISPs: {', '.join(intel['isps'])}")
    print(f"  Last Report: {intel['last_report']}")
    
    if intel.get('recent_working'):
        print(f"\n{Fore.GREEN}✓ Recently reported working!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}✗ Recent reports indicate failure{Style.RESET_ALL}")

def display_recommendations(recs, isp, country):
    """Pretty print recommendations"""
    if not recs:
        print(f"\n{Fore.YELLOW}No community recommendations for {isp} ({country}){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Be the first to submit data!{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Top Community Recommendations for {isp} ({country}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    for i, (domain, score, reports, last_seen) in enumerate(recs, 1):
        print(f"\n  {i}. {Fore.GREEN}{domain}{Style.RESET_ALL}")
        print(f"     Community Score: {score:.1f}")
        print(f"     Reports: {reports}")
        print(f"     Last Seen: {last_seen}")

def display_trending(trending):
    """Pretty print trending hosts"""
    if not trending:
        print(f"\n{Fore.YELLOW}No trending hosts found{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Trending Working Hosts (Last 7 Days){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    for i, (domain, count, isps, last_seen) in enumerate(trending, 1):
        print(f"\n  {i}. {Fore.GREEN}{domain}{Style.RESET_ALL}")
        print(f"     Reports: {count}")
        print(f"     ISPs: {', '.join(isps)}")
        print(f"     Last Seen: {last_seen}")

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Community Intelligence{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Crowdsourced SNI Host Database{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Submit burn-test result")
    print("2. Check host intelligence")
    print("3. Get recommendations for my ISP")
    print("4. View trending hosts")
    print("5. View ISP statistics")
    print("6. View database status")
    
    choice = input("\nChoice (1-6): ").strip()
    
    if choice == '1':
        print(f"\n{Fore.YELLOW}Submit burn-test result:{Style.RESET_ALL}")
        domain = input("Domain: ").strip().lower()
        isp = input("ISP (e.g., MTN, Airtel, Safaricom): ").strip()
        country = input("Country (e.g., Nigeria, Kenya, South Africa): ").strip()
        worked = input("Did it work? (y/n): ").strip().lower() == 'y'
        notes = input("Notes (optional): ").strip()
        tls = input("TLS version (optional): ").strip() or None
        status = input("HTTP status (optional): ").strip()
        status = int(status) if status.isdigit() else None
        score = input("Your score (optional): ").strip()
        score = int(score) if score.isdigit() else None
        
        submitter = IntelSubmitter()
        submitter.submit(domain, isp, country, worked, notes, tls, status, score)
        
        print(f"\n{Fore.GREEN}Thank you for contributing!{Style.RESET_ALL}")
    
    elif choice == '2':
        domain = input("Domain to check: ").strip().lower()
        isp = input("ISP (optional, press enter to skip): ").strip() or None
        country = input("Country (optional, press enter to skip): ").strip() or None
        
        query = IntelQuery()
        intel = query.check_host(domain, isp, country)
        display_host_intel(intel)
    
    elif choice == '3':
        isp = input("Your ISP: ").strip()
        country = input("Your Country: ").strip()
        
        query = IntelQuery()
        recs = query.get_recommendations(isp, country)
        display_recommendations(recs, isp, country)
    
    elif choice == '4':
        country = input("Filter by country (optional, press enter for all): ").strip() or None
        
        db = CommunityDatabase()
        trending = db.get_trending_hosts(country=country)
        display_trending(trending)
    
    elif choice == '5':
        isp = input("ISP: ").strip()
        country = input("Country: ").strip()
        
        db = CommunityDatabase()
        stats = db.get_isp_stats(isp, country)
        
        if stats:
            print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  ISP Stats: {isp} ({country}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"  Total Reports: {stats['total_reports']}")
            print(f"  Worked: {Fore.GREEN}{stats['worked']}{Style.RESET_ALL}")
            print(f"  Failed: {Fore.RED}{stats['failed']}{Style.RESET_ALL}")
            print(f"  Success Rate: {stats['success_rate']}%")
            print(f"  Domains Tested: {stats['unique_domains_tested']}")
            print(f"  Working Domains: {stats['unique_working_domains']}")
            print(f"  Last Report: {stats['last_report']}")
        else:
            print(f"{Fore.YELLOW}No data for {isp} ({country}){Style.RESET_ALL}")
    
    elif choice == '6':
        db = CommunityDatabase()
        
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Database Status{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Total Entries: {len(db.entries)}")
        
        # Unique ISPs
        isps = set((e.isp, e.country) for e in db.entries)
        print(f"  Unique ISPs: {len(isps)}")
        
        # Unique domains
        domains = set(e.domain for e in db.entries)
        print(f"  Unique Domains: {len(domains)}")
        
        # Working vs failed
        worked = sum(1 for e in db.entries if e.worked)
        print(f"  Working Reports: {worked}")
        print(f"  Failed Reports: {len(db.entries) - worked}")
        
        # Recent activity
        recent = [e for e in db.entries if e.timestamp > time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400))]
        print(f"  Reports Today: {len(recent)}")
        
        if isps:
            print(f"\n  ISPs in database:")
            for isp, country in sorted(isps):
                print(f"    - {isp} ({country})")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
