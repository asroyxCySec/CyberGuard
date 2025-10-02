#!/usr/bin/env python3
"""
CyberGuard - Ethical Security Testing Toolkit
Version: 2.0
Purpose: Educational cybersecurity tool for ethical security testing
Author: Educational Project
"""

import sys
import socket
import ssl
import hashlib
import re
import json
import datetime
import urllib.request
import urllib.parse
import urllib.error
from collections import Counter
from typing import List, Dict, Tuple
import time


BANNER = """
╔═══════════════════════════════════════════════════════════╗
║   ____      _              ____                       _   ║
║  / ___|   _| |__   ___ _ __|  _ \ _   _  __ _ _ __ __| |  ║
║ | |  | | | | '_ \ / _ \ '__| | | | | | |/ _` | '__/ _` |  ║
║ | |__| |_| | |_) |  __/ |  | |_| | |_| | (_| | | | (_| |  ║
║  \____\__, |_.__/ \___|_|  |____/ \__,_|\__,_|_|  \__,_|  ║
║       |___/                                               ║
║                                                           ║
║           Ethical Security Testing Toolkit v2.0           ║
║                  For Educational Purposes                 ║
║                    Author: AsroyxCySec                    ║
╚═══════════════════════════════════════════════════════════╝
"""

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PasswordAnalyzer:
    """Analyze password strength and security"""
    
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321'
    ]
    
    COMMON_PATTERNS = [
        r'123', r'abc', r'qwerty', r'password', r'admin',
        r'(\w)\1{2,}',  # Repeated characters
    ]
    
    @staticmethod
    def analyze(password: str) -> Dict:
        """Analyze password strength"""
        results = {
            'length': len(password),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_numbers': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'is_common': password.lower() in PasswordAnalyzer.COMMON_PASSWORDS,
            'patterns_found': [],
            'entropy': 0,
            'strength': 'Very Weak'
        }
        
        # Check for common patterns
        for pattern in PasswordAnalyzer.COMMON_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                results['patterns_found'].append(pattern)
        
        # Calculate entropy
        charset_size = 0
        if results['has_lowercase']: charset_size += 26
        if results['has_uppercase']: charset_size += 26
        if results['has_numbers']: charset_size += 10
        if results['has_special']: charset_size += 32
        
        if charset_size > 0:
            import math
            results['entropy'] = len(password) * math.log2(charset_size)
        
        # Calculate strength score
        score = 0
        if results['length'] >= 8: score += 1
        if results['length'] >= 12: score += 1
        if results['length'] >= 16: score += 1
        if results['has_uppercase']: score += 1
        if results['has_lowercase']: score += 1
        if results['has_numbers']: score += 1
        if results['has_special']: score += 2
        if not results['is_common']: score += 2
        if not results['patterns_found']: score += 1
        
        # Determine strength
        if score <= 3:
            results['strength'] = 'Very Weak'
            results['color'] = Colors.FAIL
        elif score <= 5:
            results['strength'] = 'Weak'
            results['color'] = Colors.WARNING
        elif score <= 7:
            results['strength'] = 'Moderate'
            results['color'] = Colors.OKCYAN
        elif score <= 9:
            results['strength'] = 'Strong'
            results['color'] = Colors.OKGREEN
        else:
            results['strength'] = 'Very Strong'
            results['color'] = Colors.OKGREEN + Colors.BOLD
        
        return results
    
    @staticmethod
    def generate_report(password: str) -> str:
        """Generate detailed password analysis report"""
        analysis = PasswordAnalyzer.analyze(password)
        
        report = f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}\n"
        report += f"{Colors.BOLD}PASSWORD STRENGTH ANALYSIS{Colors.ENDC}\n"
        report += f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n\n"
        
        report += f"Password Length: {analysis['length']} characters\n"
        report += f"Strength: {analysis['color']}{analysis['strength']}{Colors.ENDC}\n"
        report += f"Entropy: {analysis['entropy']:.2f} bits\n\n"
        
        report += f"{Colors.BOLD}Character Types:{Colors.ENDC}\n"
        report += f"  ✓ Uppercase: {Colors.OKGREEN + 'Yes' if analysis['has_uppercase'] else Colors.FAIL + 'No'}{Colors.ENDC}\n"
        report += f"  ✓ Lowercase: {Colors.OKGREEN + 'Yes' if analysis['has_lowercase'] else Colors.FAIL + 'No'}{Colors.ENDC}\n"
        report += f"  ✓ Numbers: {Colors.OKGREEN + 'Yes' if analysis['has_numbers'] else Colors.FAIL + 'No'}{Colors.ENDC}\n"
        report += f"  ✓ Special Characters: {Colors.OKGREEN + 'Yes' if analysis['has_special'] else Colors.FAIL + 'No'}{Colors.ENDC}\n\n"
        
        if analysis['is_common']:
            report += f"{Colors.FAIL}⚠ WARNING: This is a commonly used password!{Colors.ENDC}\n"
        
        if analysis['patterns_found']:
            report += f"\n{Colors.WARNING}⚠ Weak Patterns Detected:{Colors.ENDC}\n"
            for pattern in analysis['patterns_found']:
                report += f"  • {pattern}\n"
        
        report += f"\n{Colors.BOLD}Recommendations:{Colors.ENDC}\n"
        if analysis['length'] < 12:
            report += f"  • Use at least 12 characters\n"
        if not analysis['has_uppercase']:
            report += f"  • Add uppercase letters\n"
        if not analysis['has_numbers']:
            report += f"  • Add numbers\n"
        if not analysis['has_special']:
            report += f"  • Add special characters (!@#$%^&*)\n"
        if analysis['is_common']:
            report += f"  • Avoid common passwords\n"
        if analysis['patterns_found']:
            report += f"  • Avoid predictable patterns\n"
        
        return report

class HashCracker:
    """Educational hash identification and cracking tool"""
    
    HASH_TYPES = {
        32: ['MD5', 'NTLM'],
        40: ['SHA-1'],
        64: ['SHA-256'],
        128: ['SHA-512']
    }
    
    @staticmethod
    def identify_hash(hash_string: str) -> List[str]:
        """Identify possible hash types based on length"""
        hash_len = len(hash_string)
        return HashCracker.HASH_TYPES.get(hash_len, ['Unknown'])
    
    @staticmethod
    def hash_string(text: str, algorithm: str = 'md5') -> str:
        """Hash a string using specified algorithm"""
        if algorithm.lower() == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algorithm.lower() == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algorithm.lower() == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif algorithm.lower() == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        return ''
    
    @staticmethod
    def crack_simple(hash_string: str, wordlist: List[str]) -> Tuple[bool, str]:
        """Attempt to crack hash using wordlist (educational)"""
        possible_types = HashCracker.identify_hash(hash_string)
        
        for word in wordlist:
            for hash_type in ['md5', 'sha1', 'sha256', 'sha512']:
                if HashCracker.hash_string(word, hash_type) == hash_string.lower():
                    return True, word
        
        return False, ''

class SSLChecker:
    """Check SSL/TLS certificate information"""
    
    @staticmethod
    def check_certificate(hostname: str, port: int = 443) -> Dict:
        """Check SSL certificate details"""
        context = ssl.create_default_context()
        results = {}
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    results['subject'] = dict(x[0] for x in cert['subject'])
                    results['issuer'] = dict(x[0] for x in cert['issuer'])
                    results['version'] = cert['version']
                    results['serial_number'] = cert['serialNumber']
                    results['not_before'] = cert['notBefore']
                    results['not_after'] = cert['notAfter']
                    results['cipher'] = ssock.cipher()
                    results['tls_version'] = ssock.version()
                    
                    # Check if certificate is expired
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    results['is_expired'] = not_after < datetime.datetime.now()
                    results['days_until_expiry'] = (not_after - datetime.datetime.now()).days
                    
                    results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    @staticmethod
    def generate_report(hostname: str, results: Dict) -> str:
        """Generate SSL certificate report"""
        report = f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}\n"
        report += f"{Colors.BOLD}SSL/TLS CERTIFICATE ANALYSIS{Colors.ENDC}\n"
        report += f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n\n"
        
        if results['status'] == 'error':
            report += f"{Colors.FAIL}Error: {results['error']}{Colors.ENDC}\n"
            return report
        
        report += f"{Colors.BOLD}Certificate Information:{Colors.ENDC}\n"
        report += f"  Domain: {hostname}\n"
        report += f"  Subject: {results['subject'].get('commonName', 'N/A')}\n"
        report += f"  Issuer: {results['issuer'].get('organizationName', 'N/A')}\n"
        report += f"  Valid From: {results['not_before']}\n"
        report += f"  Valid Until: {results['not_after']}\n"
        
        if results['is_expired']:
            report += f"  Status: {Colors.FAIL}EXPIRED{Colors.ENDC}\n"
        else:
            days = results['days_until_expiry']
            if days < 30:
                report += f"  Status: {Colors.WARNING}Expires in {days} days{Colors.ENDC}\n"
            else:
                report += f"  Status: {Colors.OKGREEN}Valid ({days} days remaining){Colors.ENDC}\n"
        
        report += f"\n{Colors.BOLD}Connection Security:{Colors.ENDC}\n"
        report += f"  TLS Version: {results['tls_version']}\n"
        report += f"  Cipher Suite: {results['cipher'][0]}\n"
        report += f"  Protocol: {results['cipher'][1]}\n"
        report += f"  Key Size: {results['cipher'][2]} bits\n"
        
        return report

class PortScanner:
    """Simple port scanner for common services"""
    
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    
    @staticmethod
    def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def scan_common_ports(host: str) -> Dict:
        """Scan common ports"""
        results = {'open': [], 'closed': []}
        
        print(f"\n{Colors.OKCYAN}Scanning common ports on {host}...{Colors.ENDC}")
        
        for port, service in PortScanner.COMMON_PORTS.items():
            print(f"  Checking port {port} ({service})...", end='\r')
            if PortScanner.scan_port(host, port):
                results['open'].append((port, service))
            else:
                results['closed'].append((port, service))
        
        print(" " * 50, end='\r')  # Clear line
        return results
    
    @staticmethod
    def generate_report(host: str, results: Dict) -> str:
        """Generate port scan report"""
        report = f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}\n"
        report += f"{Colors.BOLD}PORT SCAN RESULTS{Colors.ENDC}\n"
        report += f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n\n"
        
        report += f"Target: {host}\n"
        report += f"Open Ports: {len(results['open'])}\n"
        report += f"Closed Ports: {len(results['closed'])}\n\n"
        
        if results['open']:
            report += f"{Colors.OKGREEN}{Colors.BOLD}Open Ports:{Colors.ENDC}\n"
            for port, service in results['open']:
                report += f"  {Colors.OKGREEN}✓{Colors.ENDC} Port {port} ({service}) - OPEN\n"
        else:
            report += f"{Colors.WARNING}No open ports found{Colors.ENDC}\n"
        
        return report

class HeaderAnalyzer:
    """Analyze HTTP security headers"""
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-XSS-Protection': 'XSS Filter',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Permissions Policy'
    }
    
    @staticmethod
    def check_headers(url: str) -> Dict:
        """Check HTTP security headers"""
        results = {'present': [], 'missing': [], 'headers': {}}
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'CyberGuard Security Scanner'})
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = response.headers
                
                for header, description in HeaderAnalyzer.SECURITY_HEADERS.items():
                    if header in headers:
                        results['present'].append((header, description, headers[header]))
                    else:
                        results['missing'].append((header, description))
                
                results['status'] = 'success'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    @staticmethod
    def generate_report(url: str, results: Dict) -> str:
        """Generate security headers report"""
        report = f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}\n"
        report += f"{Colors.BOLD}HTTP SECURITY HEADERS ANALYSIS{Colors.ENDC}\n"
        report += f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n\n"
        
        if results['status'] == 'error':
            report += f"{Colors.FAIL}Error: {results['error']}{Colors.ENDC}\n"
            return report
        
        report += f"URL: {url}\n\n"
        
        if results['present']:
            report += f"{Colors.OKGREEN}{Colors.BOLD}Present Security Headers:{Colors.ENDC}\n"
            for header, desc, value in results['present']:
                report += f"  {Colors.OKGREEN}✓{Colors.ENDC} {header} ({desc})\n"
                report += f"    Value: {value[:80]}...\n" if len(value) > 80 else f"    Value: {value}\n"
        
        if results['missing']:
            report += f"\n{Colors.WARNING}{Colors.BOLD}Missing Security Headers:{Colors.ENDC}\n"
            for header, desc in results['missing']:
                report += f"  {Colors.WARNING}✗{Colors.ENDC} {header} ({desc})\n"
        
        # Calculate security score
        total = len(HeaderAnalyzer.SECURITY_HEADERS)
        present = len(results['present'])
        score = (present / total) * 100
        
        report += f"\n{Colors.BOLD}Security Score: "
        if score >= 80:
            report += f"{Colors.OKGREEN}{score:.1f}%{Colors.ENDC}\n"
        elif score >= 50:
            report += f"{Colors.WARNING}{score:.1f}%{Colors.ENDC}\n"
        else:
            report += f"{Colors.FAIL}{score:.1f}%{Colors.ENDC}\n"
        
        return report

def print_menu():
    """Display main menu"""
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}Available Tools:{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[1]{Colors.ENDC} Password Strength Analyzer")
    print(f"{Colors.OKGREEN}[2]{Colors.ENDC} Hash Generator & Identifier")
    print(f"{Colors.OKGREEN}[3]{Colors.ENDC} SSL/TLS Certificate Checker")
    print(f"{Colors.OKGREEN}[4]{Colors.ENDC} Port Scanner (Common Ports)")
    print(f"{Colors.OKGREEN}[5]{Colors.ENDC} HTTP Security Headers Analyzer")
    print(f"{Colors.OKGREEN}[6]{Colors.ENDC} Batch Password Analysis")
    print(f"{Colors.FAIL}[0]{Colors.ENDC} Exit")
    print()

def main():
    """Main program loop"""
    print(Colors.OKCYAN + BANNER + Colors.ENDC)
    print(f"{Colors.WARNING}⚠  For Educational and Ethical Use Only ⚠{Colors.ENDC}")
    print(f"{Colors.WARNING}Only test systems you own or have permission to test{Colors.ENDC}\n")
    
    while True:
        print_menu()
        choice = input(f"{Colors.BOLD}Select tool [0-6]: {Colors.ENDC}").strip()
        
        if choice == '1':
            # Password Analyzer
            password = input("\nEnter password to analyze: ")
            print(PasswordAnalyzer.generate_report(password))
            
        elif choice == '2':
            # Hash Generator
            print(f"\n{Colors.BOLD}Hash Generator & Identifier{Colors.ENDC}")
            print("1. Generate hash")
            print("2. Identify hash type")
            sub_choice = input("Choose [1-2]: ").strip()
            
            if sub_choice == '1':
                text = input("Enter text to hash: ")
                print(f"\n{Colors.BOLD}Hash Results:{Colors.ENDC}")
                print(f"MD5:    {HashCracker.hash_string(text, 'md5')}")
                print(f"SHA1:   {HashCracker.hash_string(text, 'sha1')}")
                print(f"SHA256: {HashCracker.hash_string(text, 'sha256')}")
                print(f"SHA512: {HashCracker.hash_string(text, 'sha512')}")
            elif sub_choice == '2':
                hash_value = input("Enter hash to identify: ")
                types = HashCracker.identify_hash(hash_value)
                print(f"\n{Colors.BOLD}Possible hash types:{Colors.ENDC} {', '.join(types)}")
            
        elif choice == '3':
            # SSL Checker
            hostname = input("\nEnter hostname (e.g., google.com): ").strip()
            print(f"\n{Colors.OKCYAN}Checking SSL certificate...{Colors.ENDC}")
            results = SSLChecker.check_certificate(hostname)
            print(SSLChecker.generate_report(hostname, results))
            
        elif choice == '4':
            # Port Scanner
            host = input("\nEnter host to scan (e.g., scanme.nmap.org): ").strip()
            print(f"{Colors.WARNING}⚠  Only scan hosts you own or have permission to test{Colors.ENDC}")
            confirm = input("Continue? (yes/no): ").strip().lower()
            if confirm == 'yes':
                results = PortScanner.scan_common_ports(host)
                print(PortScanner.generate_report(host, results))
            
        elif choice == '5':
            # Header Analyzer
            url = input("\nEnter URL (e.g., https://example.com): ").strip()
            print(f"\n{Colors.OKCYAN}Analyzing security headers...{Colors.ENDC}")
            results = HeaderAnalyzer.check_headers(url)
            print(HeaderAnalyzer.generate_report(url, results))
            
        elif choice == '6':
            # Batch Password Analysis
            print(f"\n{Colors.BOLD}Batch Password Analysis{Colors.ENDC}")
            print("Enter passwords (one per line, empty line to finish):")
            passwords = []
            while True:
                pwd = input()
                if not pwd:
                    break
                passwords.append(pwd)
            
            print(f"\n{Colors.BOLD}Analyzing {len(passwords)} passwords...{Colors.ENDC}\n")
            weak_count = 0
            for i, pwd in enumerate(passwords, 1):
                analysis = PasswordAnalyzer.analyze(pwd)
                print(f"Password {i}: {analysis['color']}{analysis['strength']}{Colors.ENDC} "
                      f"(Entropy: {analysis['entropy']:.1f} bits)")
                if analysis['strength'] in ['Very Weak', 'Weak']:
                    weak_count += 1
            
            print(f"\n{Colors.BOLD}Summary:{Colors.ENDC}")
            print(f"Total passwords: {len(passwords)}")
            print(f"Weak passwords: {weak_count}")
            print(f"Strong passwords: {len(passwords) - weak_count}")
            
        elif choice == '0':
            print(f"\n{Colors.OKGREEN}Thank you for using CyberGuard!{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Stay secure and ethical! 🛡️{Colors.ENDC}\n")
            break
        
        else:
            print(f"{Colors.FAIL}Invalid choice. Please try again.{Colors.ENDC}")
        
        input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Program interrupted by user.{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Stay secure! 🛡️{Colors.ENDC}\n")
        sys.exit(0)
