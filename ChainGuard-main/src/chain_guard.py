import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
import os
import ast
import importlib.util
import sys
from pathlib import Path
from collections import defaultdict
import json
import urllib.request
import urllib.error
from datetime import datetime
import zipfile
import tarfile
import shutil
import tempfile
import re
import socket
import ipaddress
import base64
import hashlib
import binascii
import subprocess
import time
import math
import logging
try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import version, PackageNotFoundError

#  monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None


class DataFlowAnalyzer(ast.NodeVisitor):
    """AST-based data-flow analyzer for tracking variable usage and taint analysis."""
    
    def __init__(self, filename=""):
        self.filename = filename
        self.user_input_sources = set()
        self.tainted_vars = set()
        self.dangerous_sinks = []
        self.imports = {}
        self.function_calls = []
        self.assignments = {}  # Track all variable assignments
        
    def visit_Assign(self, node):
        """Track variable assignments from user input sources."""
        value = node.value
        
        # Check if value is from user input
        is_tainted = False
        
        # Direct input() call
        if isinstance(value, ast.Call):
            if isinstance(value.func, ast.Name) and value.func.id == 'input':
                is_tainted = True
            elif isinstance(value.func, ast.Attribute):
                if isinstance(value.func.value, ast.Name) and value.func.value.id == 'os':
                    if value.func.attr == 'getenv':
                        is_tainted = True
                elif isinstance(value.func.value, ast.Name) and value.func.value.id == 'sys':
                    if value.func.attr == 'argv':
                        is_tainted = True
        
        # Check for sys.argv subscript
        if isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Attribute):
                if isinstance(value.value.value, ast.Name) and value.value.value.id == 'sys':
                    if value.value.attr == 'argv':
                        is_tainted = True
        
        # Check for os.environ subscript
        if isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Attribute):
                if isinstance(value.value.value, ast.Name) and value.value.value.id == 'os':
                    if value.value.attr == 'environ':
                        is_tainted = True
        
        # Check for request.* (Flask/Django)
        if isinstance(value, ast.Attribute):
            if isinstance(value.value, ast.Name) and value.value.id == 'request':
                if value.attr in ['args', 'form', 'json', 'GET', 'POST', 'data', 'query_params', 'body']:
                    is_tainted = True
        
        # Track taint propagation - if source is tainted, target becomes tainted
        if isinstance(value, ast.Name) and value.id in self.tainted_vars:
            is_tainted = True
        
        # Mark targets as tainted
        if is_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    self.user_input_sources.add(target.id)
                    self.assignments[target.id] = node.lineno
        
        # Store assignment for later taint propagation
        for target in node.targets:
            if isinstance(target, ast.Name):
                if isinstance(value, ast.Name):
                    # If assigning from another variable, check if source is tainted
                    if value.id in self.tainted_vars:
                        self.tainted_vars.add(target.id)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Track dangerous function calls with tainted arguments."""
        # Check for eval/exec/compile/__import__
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec', 'compile', '__import__']:
                # Check if any argument is tainted
                has_tainted = False
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                        has_tainted = True
                        break
                    if isinstance(arg, ast.Call):
                        if isinstance(arg.func, ast.Name) and arg.func.id == 'input':
                            has_tainted = True
                            break
                    # Check for sys.argv in arguments
                    if isinstance(arg, ast.Subscript):
                        if isinstance(arg.value, ast.Attribute):
                            if isinstance(arg.value.value, ast.Name) and arg.value.value.id == 'sys':
                                if arg.value.attr == 'argv':
                                    has_tainted = True
                                    break
                
                self.dangerous_sinks.append({
                    'function': node.func.id,
                    'line': node.lineno,
                    'file': os.path.basename(self.filename),
                    'has_tainted_input': has_tainted
                })
        
        # Track subprocess calls
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                if node.func.attr in ['system', 'popen', 'spawn']:
                    has_tainted = False
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                            has_tainted = True
                            break
                        if isinstance(arg, ast.Call):
                            if isinstance(arg.func, ast.Name) and arg.func.id == 'input':
                                has_tainted = True
                                break
                    
                    self.dangerous_sinks.append({
                        'function': f'os.{node.func.attr}',
                        'line': node.lineno,
                        'file': os.path.basename(self.filename),
                        'has_tainted_input': has_tainted
                    })
            
            # Check for subprocess module calls
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                if node.func.attr in ['call', 'run', 'Popen', 'check_call', 'check_output']:
                    has_tainted = False
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                            has_tainted = True
                            break
                    
                    self.dangerous_sinks.append({
                        'function': f'subprocess.{node.func.attr}',
                        'line': node.lineno,
                        'file': os.path.basename(self.filename),
                        'has_tainted_input': has_tainted
                    })
        
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """Track imports."""
        for alias in node.names:
            self.imports[alias.name] = node.lineno
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Track from imports."""
        if node.module:
            for alias in node.names:
                self.imports[f"{node.module}.{alias.name}"] = node.lineno
        self.generic_visit(node)


class AdvancedSecurityAnalyzer:
    """Advanced security analysis engine with multiple analysis modules."""
    
    def __init__(self, log_callback=None):
        self.log = log_callback or (lambda x: None)
        self.findings = []
        
    def analyze_package(self, package_dir, package_name, package_version=None, threat_intel_checker=None):
        """Run all analysis modules and return comprehensive results."""
        results = {
            'package_name': package_name,
            'package_version': package_version,
            'threat_intelligence': {},
            'data_flow': {},
            'vulnerabilities': [],
            'suspicious_domains': [],
            'suspicious_ips': [],
            'credentials_found': [],
            'obfuscation_detected': [],
            'setup_behavior': {},
            'dynamic_analysis': {},
            'risk_score': 0,
            'risk_level': 'Low',
            'findings': []
        }
        
        # 0. Threat Intelligence Check (FIRST - before other analysis)
        if threat_intel_checker:
            self.log(f"  → Checking threat intelligence APIs...")
            results['threat_intelligence'] = threat_intel_checker(package_name)
            if results['threat_intelligence'].get('is_malicious'):
                self.log(f"    ⚠️  MALICIOUS PACKAGE DETECTED via Threat Intelligence!")
                # Still continue analysis for comprehensive report
        
        # 1. Data-flow analysis
        self.log(f"  → Running data-flow analysis...")
        results['data_flow'] = self._analyze_data_flow(package_dir)
        
        # 2. CVE/OSV vulnerability check
        if package_version:
            self.log(f"  → Checking CVE/OSV vulnerabilities...")
            results['vulnerabilities'] = self._check_vulnerabilities(package_name, package_version)
        
        # 3. Domain/IP scanning
        self.log(f"  → Scanning for suspicious domains/IPs...")
        domain_ip_results = self._scan_domains_and_ips(package_dir)
        results['suspicious_domains'] = domain_ip_results['domains']
        results['suspicious_ips'] = domain_ip_results['ips']
        
        # 4. Credential/token detection
        self.log(f"  → Detecting credentials and tokens...")
        results['credentials_found'] = self._detect_credentials(package_dir)
        
        # 5. Obfuscation detection
        self.log(f"  → Detecting code obfuscation...")
        results['obfuscation_detected'] = self._detect_obfuscation(package_dir)
        
        # 6. Setup.py/pyproject.toml analysis
        self.log(f"  → Analyzing setup behavior...")
        results['setup_behavior'] = self._analyze_setup_behavior(package_dir)
        
        # 7. Dynamic analysis (sandbox execution)
        try:
            dynamic_analyzer = DynamicAnalyzer(log_callback=self.log)
            results['dynamic_analysis'] = dynamic_analyzer.analyze_runtime_behavior(
                package_dir, package_name
            )
        except Exception as e:
            self.log(f"    Warning: Dynamic analysis failed: {str(e)}")
            results['dynamic_analysis'] = {
                'errors': [{'type': 'Analysis error', 'description': str(e), 'severity': 'LOW'}]
            }
        
        # 8. Calculate risk score (with 4-stage breakdown)
        results['risk_score'], results['risk_level'], results['stage_scores'] = self._calculate_risk_score(results)
        
        # 9. Compile findings
        results['findings'] = self._compile_findings(results)
        
        return results
    
    def _analyze_data_flow(self, package_dir):
        """Perform AST-based data-flow analysis."""
        data_flow_results = {
            'tainted_variables': set(),
            'dangerous_sinks': [],
            'user_input_sources': set(),
            'risk_factors': []
        }
        
        python_files = self._find_python_files(package_dir)
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                try:
                    tree = ast.parse(content, filename=py_file)
                    analyzer = DataFlowAnalyzer(filename=py_file)
                    analyzer.visit(tree)
                    
                    data_flow_results['tainted_variables'].update(analyzer.tainted_vars)
                    data_flow_results['user_input_sources'].update(analyzer.user_input_sources)
                    data_flow_results['dangerous_sinks'].extend(analyzer.dangerous_sinks)
                    
                    # Count high-risk sinks
                    high_risk_sinks = [s for s in analyzer.dangerous_sinks if s['has_tainted_input']]
                    if high_risk_sinks:
                        data_flow_results['risk_factors'].append({
                            'file': os.path.basename(py_file),
                            'type': 'Tainted data flow',
                            'count': len(high_risk_sinks),
                            'severity': 'HIGH'
                        })
                
                except SyntaxError:
                    pass
            except Exception:
                pass
        
        return data_flow_results
    
    def _check_vulnerabilities(self, package_name, package_version):
        """Check CVE/OSV database for known vulnerabilities."""
        vulnerabilities = []
        
        try:
            # OSV API query
            url = f"https://api.osv.dev/v1/query"
            query = {
                "version": package_version,
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                }
            }
            
            req = urllib.request.Request(url, data=json.dumps(query).encode(), 
                                       headers={'Content-Type': 'application/json'})
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if 'vulns' in data:
                    for vuln in data['vulns']:
                        vulnerabilities.append({
                            'id': vuln.get('id', 'Unknown'),
                            'summary': vuln.get('summary', ''),
                            'severity': vuln.get('database_specific', {}).get('severity', 'UNKNOWN'),
                            'details': vuln.get('details', '')
                        })
        
        except Exception as e:
            self.log(f"    Warning: Could not check vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _scan_domains_and_ips(self, package_dir):
        """Scan for suspicious domains and IP addresses - REAL IMPLEMENTATION."""
        domains = []
        ips = []
        all_domains = set()  # Track all domains to avoid duplicates
        
        python_files = self._find_python_files(package_dir)
        
        # Whitelist of trusted domains - COMPREHENSIVE
        trusted_domains = {
            # Python ecosystem
            'pypi.org', 'pypi.python.org', 'python.org', 'www.python.org',
            'packaging.python.org', 'bootstrap.pypa.io', 'mail.python.org',
            'docs.python.org', 'wiki.python.org', 'peps.python.org',
            # Documentation & Community
            'github.com', 'github.io', 'stackoverflow.com', 'readthedocs.io',
            'readthedocs.org', 'sphinx-doc.org', 'en.wikipedia.org',
            'wikipedia.org', 'code.activestate.com', 'activestate.com',
            # Cloud providers (legitimate)
            'google.com', 'googleapis.com', 'microsoft.com', 'azure.com',
            'amazonaws.com', 'aws.amazon.com', 'cloudflare.com',
            # Common legitimate domains
            'apache.org', 'mozilla.org', 'gnu.org', 'sourceforge.net',
            'bitbucket.org', 'gitlab.com', 'npmjs.com', 'npm.org',
            # Educational & Research
            'edu', 'ac.uk', 'harvard.edu', 'mit.edu', 'stanford.edu',
            'freebsd.org', 'cyberciti.biz', 'slideshare.net'
        }
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract URLs and domains - multiple patterns
                url_patterns = [
                    r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # http://domain.com
                    r'["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',  # "http://domain.com"
                    r'url\s*[=:]\s*["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',  # url = "domain.com"
                    r'host\s*[=:]\s*["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',  # host = "domain.com"
                    r'socket\.(?:gethostbyname|connect)\s*\(["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',  # socket.connect("domain.com")
                ]
                
                for pattern in url_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        domain = match.group(1).lower().strip()
                        # Remove port numbers
                        if ':' in domain:
                            domain = domain.split(':')[0]
                        
                        if domain:
                            # Check if domain is in whitelist (including subdomains)
                            domain_lower = domain.lower()
                            is_trusted = False
                            for trusted in trusted_domains:
                                trusted_lower = trusted.lower()
                                if (domain_lower == trusted_lower or 
                                    domain_lower.endswith('.' + trusted_lower) or
                                    trusted_lower in domain_lower):  # Also match partial (e.g., 'edu' in 'harvard.edu')
                                    is_trusted = True
                                    break
                            
                            # Only process if not trusted and not already seen
                            if not is_trusted and domain not in all_domains:
                                all_domains.add(domain)
                                
                                # Check if domain is suspicious
                                is_suspicious = self._is_suspicious_domain(domain)
                                
                                line_num = content[:match.start()].count('\n') + 1
                                domains.append({
                                    'domain': domain,
                                    'file': os.path.basename(py_file),
                                    'line': line_num,
                                    'suspicious': is_suspicious,
                                    'context': content[max(0, match.start()-30):match.end()+30].replace('\n', ' ')
                                })
                
                # Extract IP addresses - multiple patterns
                ip_patterns = [
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # Basic IP
                    r'["\'](?:\d{1,3}\.){3}\d{1,3}["\']',  # "IP"
                    r'ip\s*[=:]\s*["\'](?:\d{1,3}\.){3}\d{1,3}["\']',  # ip = "1.2.3.4"
                    r'host\s*[=:]\s*["\'](?:\d{1,3}\.){3}\d{1,3}["\']',  # host = "1.2.3.4"
                    r'socket\.(?:gethostbyname|connect)\s*\(["\'](?:\d{1,3}\.){3}\d{1,3}["\']',  # socket.connect("1.2.3.4")
                ]
                
                all_ips = set()
                for pattern in ip_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        ip_str = match.group(0).strip('"\'')
                        try:
                            ip = ipaddress.ip_address(ip_str)
                            # Check if IP is suspicious (private/localhost might be OK, but external IPs are suspicious)
                            if not ip.is_private and not ip.is_loopback and not ip.is_multicast:
                                if ip_str not in all_ips:
                                    all_ips.add(ip_str)
                                    line_num = content[:match.start()].count('\n') + 1
                                    ips.append({
                                        'ip': ip_str,
                                        'file': os.path.basename(py_file),
                                        'line': line_num,
                                        'is_private': False,
                                        'context': content[max(0, match.start()-30):match.end()+30].replace('\n', ' ')
                                    })
                        except ValueError:
                            pass
            
            except Exception as e:
                self.log(f"    Error scanning {py_file}: {str(e)}")
        
        return {'domains': domains, 'ips': ips}
    
    def _is_suspicious_domain(self, domain):
        """Check if domain is suspicious."""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        suspicious_keywords = ['bitcoin', 'mining', 'crypto', 'stealer', 'malware']
        
        # Check TLD
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Check keywords
        domain_lower = domain.lower()
        if any(keyword in domain_lower for keyword in suspicious_keywords):
            return True
        
        return False
    
    def _detect_credentials(self, package_dir):
        """Advanced credential and token pattern detection - REAL IMPLEMENTATION."""
        credentials = []
        found_creds = set()  # Avoid duplicates
        
        python_files = self._find_python_files(package_dir)
        
        # Patterns for credentials - more comprehensive
        credential_patterns = [
            (r'api[_-]?key\s*[=:]\s*["\']([^"\']{5,})["\']', 'API Key', 'HIGH'),
            (r'apikey\s*[=:]\s*["\']([^"\']{5,})["\']', 'API Key', 'HIGH'),
            (r'secret[_-]?key\s*[=:]\s*["\']([^"\']{5,})["\']', 'Secret Key', 'HIGH'),
            (r'secretkey\s*[=:]\s*["\']([^"\']{5,})["\']', 'Secret Key', 'HIGH'),
            (r'password\s*[=:]\s*["\']([^"\']{3,})["\']', 'Password', 'HIGH'),
            (r'pwd\s*[=:]\s*["\']([^"\']{3,})["\']', 'Password', 'HIGH'),
            (r'token\s*[=:]\s*["\']([^"\']{10,})["\']', 'Token', 'HIGH'),
            (r'access[_-]?token\s*[=:]\s*["\']([^"\']{10,})["\']', 'Access Token', 'HIGH'),
            (r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']([^"\']{10,})["\']', 'AWS Access Key', 'CRITICAL'),
            (r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'AWS Secret Key', 'CRITICAL'),
            (r'github[_-]?token\s*[=:]\s*["\']([^"\']{10,})["\']', 'GitHub Token', 'CRITICAL'),
            (r'ssh[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'SSH Key', 'CRITICAL'),
            (r'private[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'Private Key', 'CRITICAL'),
            (r'private_key\s*[=:]\s*["\']([^"\']{20,})["\']', 'Private Key', 'CRITICAL'),
            (r'database[_-]?password\s*[=:]\s*["\']([^"\']{3,})["\']', 'Database Password', 'HIGH'),
            (r'db[_-]?password\s*[=:]\s*["\']([^"\']{3,})["\']', 'Database Password', 'HIGH'),
            (r'redis[_-]?password\s*[=:]\s*["\']([^"\']{3,})["\']', 'Redis Password', 'HIGH'),
            (r'mongodb[_-]?password\s*[=:]\s*["\']([^"\']{3,})["\']', 'MongoDB Password', 'HIGH'),
        ]
        
        # Token patterns (JWT, OAuth, etc.)
        token_patterns = [
            (r'\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b', 'JWT Token', 'MEDIUM'),
            (r'\bghp_[A-Za-z0-9]{36,}\b', 'GitHub Personal Access Token', 'CRITICAL'),
            (r'\bgho_[A-Za-z0-9]{36,}\b', 'GitHub OAuth Token', 'CRITICAL'),
            (r'\bghu_[A-Za-z0-9]{36,}\b', 'GitHub User-to-Server Token', 'CRITICAL'),
            (r'\bghr_[A-Za-z0-9]{36,}\b', 'GitHub Refresh Token', 'CRITICAL'),
            (r'\bghs_[A-Za-z0-9]{36,}\b', 'GitHub Server-to-Server Token', 'CRITICAL'),
            (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Access Key ID', 'CRITICAL'),
            (r'\b[A-Za-z0-9/+=]{40,}\b', 'Long Base64 Token', 'MEDIUM'),  # Generic long base64-like token
        ]
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                file_basename = os.path.basename(py_file)
                
                # Check credential patterns
                for pattern, cred_type, severity in credential_patterns:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        value = match.group(1) if match.groups() else match.group(0)
                        
                        # Skip common false positives
                        if value.lower() in ['none', 'null', 'true', 'false', 'password', 'secret', 'token']:
                            continue
                        
                        # Create unique key to avoid duplicates
                        cred_key = f"{file_basename}:{line_num}:{cred_type}"
                        if cred_key not in found_creds:
                            found_creds.add(cred_key)
                            credentials.append({
                                'type': cred_type,
                                'file': file_basename,
                                'line': line_num,
                                'pattern': pattern,
                                'severity': severity,
                                'context': content[max(0, match.start()-50):match.end()+50].replace('\n', ' ')[:100]
                            })
                
                # Check token patterns
                for pattern, token_type, severity in token_patterns:
                    matches = list(re.finditer(pattern, content))
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        token_value = match.group(0)
                        
                        # Create unique key
                        cred_key = f"{file_basename}:{line_num}:{token_type}"
                        if cred_key not in found_creds:
                            found_creds.add(cred_key)
                            credentials.append({
                                'type': token_type,
                                'file': file_basename,
                                'line': line_num,
                                'pattern': pattern,
                                'severity': severity,
                                'token_preview': token_value[:20] + '...' if len(token_value) > 20 else token_value
                            })
            
            except Exception as e:
                self.log(f"    Error detecting credentials in {py_file}: {str(e)}")
        
        return credentials
    
    def _detect_obfuscation(self, package_dir):
        """Detect code obfuscation techniques - REAL IMPLEMENTATION."""
        obfuscation_findings = []
        
        python_files = self._find_python_files(package_dir)
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                file_basename = os.path.basename(py_file)
                
                # 1. Check for base64 encoding
                base64_pattern = r'base64\.(?:b64decode|b64encode|standard_b64decode|standard_b64encode|urlsafe_b64decode|urlsafe_b64encode)'
                base64_matches = list(re.finditer(base64_pattern, content, re.IGNORECASE))
                base64_count = len(base64_matches)
                if base64_count > 10:
                    # Check if base64 is used with exec/eval
                    exec_with_base64 = False
                    for match in base64_matches:
                        # Look for exec/eval nearby (within 200 chars)
                        start = max(0, match.start() - 200)
                        end = min(len(content), match.end() + 200)
                        context = content[start:end]
                        if re.search(r'(exec|eval)\s*\(', context, re.IGNORECASE):
                            exec_with_base64 = True
                            break
                    
                    obfuscation_findings.append({
                        'type': 'Base64 Encoding',
                        'file': file_basename,
                        'count': base64_count,
                        'severity': 'HIGH' if exec_with_base64 else 'MEDIUM',
                        'line': base64_matches[0].start() if base64_matches else 0
                    })
                
                # 2. Check for hex encoding
                hex_pattern = r'binascii\.(?:unhexlify|hexlify|a2b_hex|b2a_hex)'
                hex_matches = list(re.finditer(hex_pattern, content, re.IGNORECASE))
                hex_count = len(hex_matches)
                if hex_count > 5:
                    obfuscation_findings.append({
                        'type': 'Hex Encoding',
                        'file': file_basename,
                        'count': hex_count,
                        'severity': 'MEDIUM',
                        'line': hex_matches[0].start() if hex_matches else 0
                    })
                
                # 3. Check for exec/eval with encoded strings - CRITICAL
                exec_eval_patterns = [
                    r'(exec|eval)\s*\(\s*(?:base64|binascii|codecs|zlib|marshal)',
                    r'(exec|eval)\s*\(\s*["\'](?:[A-Za-z0-9+/=]{100,})["\']',  # Long base64-like string
                    r'compile\s*\(\s*(?:base64|binascii|codecs)',
                ]
                for pattern in exec_eval_patterns:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    if matches:
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            obfuscation_findings.append({
                                'type': 'Exec/Eval with Encoding',
                                'file': file_basename,
                                'line': line_num,
                                'severity': 'HIGH',
                                'pattern': match.group(0)[:50]
                            })
                
                # 4. Check for very long encoded strings (possible obfuscated code)
                # Only flag if it's clearly encoded (base64-like) and very long
                long_string_pattern = r'["\']([^"\']{1000,})["\']'  # Increased from 500 to 1000
                long_strings = list(re.finditer(long_string_pattern, content))
                if long_strings:
                    for match in long_strings[:5]:  # Limit to first 5
                        line_num = content[:match.start()].count('\n') + 1
                        string_content = match.group(1)
                        # Check if it looks like encoded data (base64-like pattern)
                        # Must be at least 80% alphanumeric/base64 chars to be suspicious
                        base64_chars = len(re.findall(r'[A-Za-z0-9+/=]', string_content))
                        if len(string_content) > 0 and base64_chars / len(string_content) > 0.8:
                            is_encoded = True
                            obfuscation_findings.append({
                                'type': 'Long Encoded Strings',
                                'file': file_basename,
                                'line': line_num,
                                'length': len(string_content),
                                'severity': 'HIGH' if is_encoded else 'MEDIUM'
                            })
                
                # 5. Check entropy (high entropy = possible obfuscation)
                # Use higher thresholds to reduce false positives
                if len(content) > 1000:
                    # Calculate entropy for different parts
                    entropy = self._calculate_entropy(content)
                    if entropy > 4.8:  # Higher threshold (was 4.5) - reduce false positives
                        obfuscation_findings.append({
                            'type': 'High Entropy Code',
                            'file': file_basename,
                            'entropy': round(entropy, 2),
                            'severity': 'MEDIUM'
                        })
                    
                    # Check entropy of string literals - only very high entropy
                    string_pattern = r'["\']([^"\']{100,})["\']'  # Only check longer strings (was 50)
                    string_matches = re.findall(string_pattern, content)
                    for string_content in string_matches[:10]:  # Check first 10 long strings
                        str_entropy = self._calculate_entropy(string_content)
                        if str_entropy > 4.5:  # Higher threshold (was 4.0) - reduce false positives
                            obfuscation_findings.append({
                                'type': 'High Entropy String',
                                'file': file_basename,
                                'entropy': round(str_entropy, 2),
                                'severity': 'MEDIUM'
                            })
                
                # 6. Check for marshal/cPickle usage (code serialization)
                marshal_pattern = r'marshal\.(?:loads|dumps)'
                pickle_pattern = r'(?:pickle|cPickle)\.(?:loads|dumps)'
                if re.search(marshal_pattern, content, re.IGNORECASE):
                    obfuscation_findings.append({
                        'type': 'Marshal Serialization',
                        'file': file_basename,
                        'severity': 'HIGH'
                    })
                if re.search(pickle_pattern, content, re.IGNORECASE):
                    obfuscation_findings.append({
                        'type': 'Pickle Serialization',
                        'file': file_basename,
                        'severity': 'MEDIUM'
                    })
                
                # 7. Check for codecs/chr/ord obfuscation
                chr_ord_pattern = r'chr\s*\(\s*\d+\s*\)'
                chr_ord_count = len(re.findall(chr_ord_pattern, content))
                if chr_ord_count > 20:  # Many chr() calls might indicate obfuscation
                    obfuscation_findings.append({
                        'type': 'Chr/Ord Obfuscation',
                        'file': file_basename,
                        'count': chr_ord_count,
                        'severity': 'MEDIUM'
                    })
            
            except Exception as e:
                self.log(f"    Error detecting obfuscation in {py_file}: {str(e)}")
        
        return obfuscation_findings
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text:
            return 0
        
        import math
        entropy = 0
        for char in set(text):
            p = text.count(char) / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _analyze_setup_behavior(self, package_dir):
        """Analyze setup.py and pyproject.toml for suspicious behavior - REAL IMPLEMENTATION."""
        behavior = {
            'has_post_install': False,
            'has_custom_commands': False,
            'suspicious_imports': [],
            'network_during_setup': False,
            'file_operations': False,
            'dangerous_calls': [],
            'setup_hooks': []
        }
        
        # Check setup.py
        setup_py = os.path.join(package_dir, 'setup.py')
        if os.path.exists(setup_py):
            try:
                with open(setup_py, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 1. Check for post-install hooks
                post_install_patterns = [
                    r'cmdclass\s*=',
                    r'post_install',
                    r'setup_requires',
                    r'install_requires.*subprocess',
                    r'class\s+\w+.*install',
                    r'def\s+post_install',
                    r'def\s+run\s*\(.*install',
                ]
                for pattern in post_install_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        behavior['has_post_install'] = True
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            behavior['setup_hooks'].append({
                                'type': 'Post-install hook',
                                'line': line_num,
                                'pattern': match.group(0)[:50]
                            })
                        break
                
                # 2. Check for suspicious imports
                suspicious_imports = {
                    'subprocess': ['subprocess', 'subprocess\.'],
                    'os.system': ['os\.system', 'from os import system'],
                    'urllib': ['urllib', 'urllib\.'],
                    'requests': ['requests', 'import requests'],
                    'socket': ['socket', 'import socket'],
                    'http.client': ['http\.client', 'httplib'],
                }
                for imp_name, patterns in suspicious_imports.items():
                    for pattern in patterns:
                        if re.search(rf'\b{pattern}\b', content, re.IGNORECASE):
                            if imp_name not in behavior['suspicious_imports']:
                                behavior['suspicious_imports'].append(imp_name)
                            if imp_name in ['urllib', 'requests', 'socket', 'http.client']:
                                behavior['network_during_setup'] = True
                            break
                
                # 3. Check for file operations
                file_ops_patterns = [
                    r'open\s*\(',
                    r'\.write\s*\(',
                    r'\.remove\s*\(',
                    r'\.delete\s*\(',
                    r'shutil\.',
                    r'os\.remove',
                    r'os\.unlink',
                ]
                for pattern in file_ops_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        behavior['file_operations'] = True
                        break
                
                # 4. Check for dangerous function calls
                dangerous_patterns = [
                    (r'eval\s*\(', 'eval'),
                    (r'exec\s*\(', 'exec'),
                    (r'compile\s*\(', 'compile'),
                    (r'__import__\s*\(', '__import__'),
                    (r'subprocess\.(?:call|run|Popen)', 'subprocess'),
                    (r'os\.system\s*\(', 'os.system'),
                ]
                for pattern, func_name in dangerous_patterns:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    if matches:
                        for match in matches[:3]:  # Limit to first 3
                            line_num = content[:match.start()].count('\n') + 1
                            behavior['dangerous_calls'].append({
                                'function': func_name,
                                'line': line_num
                            })
                
                # 5. Try AST parsing for more accurate detection
                try:
                    tree = ast.parse(content, filename=setup_py)
                    for node in ast.walk(tree):
                        # Check for function definitions that might be hooks
                        if isinstance(node, ast.FunctionDef):
                            if 'install' in node.name.lower() or 'setup' in node.name.lower():
                                if node.name not in ['setup']:  # Exclude main setup function
                                    behavior['setup_hooks'].append({
                                        'type': f'Custom function: {node.name}',
                                        'line': node.lineno
                                    })
                        
                        # Check for class definitions (cmdclass)
                        if isinstance(node, ast.ClassDef):
                            for base in node.bases:
                                if isinstance(base, ast.Name):
                                    if 'install' in base.id.lower() or 'command' in base.id.lower():
                                        behavior['has_custom_commands'] = True
                except SyntaxError:
                    pass
            
            except Exception as e:
                self.log(f"    Error analyzing setup.py: {str(e)}")
        
        # Check pyproject.toml
        pyproject_toml = os.path.join(package_dir, 'pyproject.toml')
        if os.path.exists(pyproject_toml):
            try:
                with open(pyproject_toml, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for build hooks and custom commands
                if 'build-system' in content:
                    behavior['has_custom_commands'] = True
                
                # Check for tool.setuptools with custom commands
                if re.search(r'tool\.setuptools', content, re.IGNORECASE):
                    behavior['has_custom_commands'] = True
                
                # Check for [tool.setuptools] with script-files or entry-points
                if re.search(r'\[tool\.setuptools\]', content, re.IGNORECASE):
                    if re.search(r'script-files|entry-points', content, re.IGNORECASE):
                        behavior['has_post_install'] = True
            
            except Exception as e:
                self.log(f"    Error analyzing pyproject.toml: {str(e)}")
        
        return behavior
    
    def _calculate_risk_score(self, results):
        """Calculate comprehensive risk score (0-100) with 4-stage breakdown."""
        total_score = 0
        stage_scores = {
            'threat_intelligence': 0,
            'static_analysis': 0,
            'setup_behavior': 0,
            'dynamic_analysis': 0
        }
        
        # ============================================================
        # AŞAMA 1: THREAT INTELLIGENCE (0-25 points) - HIGHEST PRIORITY
        # ============================================================
        threat_intel = results.get('threat_intelligence', {})
        if threat_intel.get('is_malicious'):
            stage_scores['threat_intelligence'] = 25  # Malicious package detected via threat intelligence
        elif threat_intel.get('reports'):
            # Medium severity reports
            medium_reports = sum(1 for r in threat_intel['reports'] if r.get('severity') == 'MEDIUM')
            stage_scores['threat_intelligence'] = min(10, medium_reports * 3)
        total_score += stage_scores['threat_intelligence']
        
        # ============================================================
        # AŞAMA 2: STATIC ANALYSIS (0-50 points)
        # ============================================================
        static_score = 0
        
        # Data-flow risks (0-25 points)
        if results.get('data_flow', {}).get('dangerous_sinks'):
            high_risk_sinks = sum(1 for s in results['data_flow']['dangerous_sinks'] if s.get('has_tainted_input'))
            static_score += min(25, high_risk_sinks * 5)
        
        # Vulnerabilities (0-20 points)
        if results.get('vulnerabilities'):
            critical_vulns = sum(1 for v in results['vulnerabilities'] if 'CRITICAL' in str(v.get('severity', '')).upper())
            high_vulns = sum(1 for v in results['vulnerabilities'] if 'HIGH' in str(v.get('severity', '')).upper())
            static_score += min(20, critical_vulns * 10 + high_vulns * 5)
        
        # Suspicious domains/IPs (0-15 points)
        static_score += min(15, len(results.get('suspicious_domains', [])) * 3 + len(results.get('suspicious_ips', [])) * 2)
        
        # Credentials found (0-20 points)
        high_cred = sum(1 for c in results.get('credentials_found', []) if c.get('severity') in ['HIGH', 'CRITICAL'])
        static_score += min(20, high_cred * 5)
        
        # Obfuscation (0-10 points)
        high_obf = sum(1 for o in results.get('obfuscation_detected', []) if o.get('severity') == 'HIGH')
        static_score += min(10, high_obf * 5 + len(results.get('obfuscation_detected', [])) * 2)
        
        # Cap static analysis at 50 points
        stage_scores['static_analysis'] = min(50, static_score)
        total_score += stage_scores['static_analysis']
        
        # ============================================================
        # AŞAMA 3: SETUP BEHAVIOR (0-10 points)
        # ============================================================
        setup_score = 0
        if results.get('setup_behavior', {}).get('has_post_install'):
            setup_score += 5
        if results.get('setup_behavior', {}).get('network_during_setup'):
            setup_score += 3
        if results.get('setup_behavior', {}).get('file_operations'):
            setup_score += 2
        stage_scores['setup_behavior'] = min(10, setup_score)
        total_score += stage_scores['setup_behavior']
        
        # ============================================================
        # AŞAMA 4: DYNAMIC ANALYSIS (0-20 points)
        # ============================================================
        dynamic_score = 0
        dynamic = results.get('dynamic_analysis', {})
        if dynamic.get('timeout'):
            dynamic_score += 15  # Timeout is very suspicious
        if dynamic.get('network_connections'):
            dynamic_score += min(10, len(dynamic['network_connections']) * 2)
        if dynamic.get('process_spawns'):
            dynamic_score += min(10, len(dynamic['process_spawns']) * 3)
        if dynamic.get('cpu_usage', 0) > 80:
            dynamic_score += 10  # High CPU = possible mining
        if dynamic.get('errors'):
            critical_errors = sum(1 for e in dynamic['errors'] if e.get('severity') == 'CRITICAL')
            dynamic_score += min(10, critical_errors * 5)
        stage_scores['dynamic_analysis'] = min(20, dynamic_score)
        total_score += stage_scores['dynamic_analysis']
        
        # Cap total at 100
        total_score = min(100, total_score)
        
        # Determine risk level
        if total_score >= 70:
            level = 'Critical'
        elif total_score >= 50:
            level = 'High'
        elif total_score >= 30:
            level = 'Medium'
        elif total_score >= 10:
            level = 'Low'
        else:
            level = 'Very Low'
        
        return total_score, level, stage_scores
    
    def _compile_findings(self, results):
        """Compile all findings into a unified list - REAL IMPLEMENTATION."""
        findings = []
        
        # Threat Intelligence findings - HIGHEST PRIORITY
        if results.get('threat_intelligence', {}).get('is_malicious'):
            threat_intel = results['threat_intelligence']
            for report in threat_intel.get('reports', []):
                findings.append({
                    'type': 'Threat Intelligence',
                    'severity': report.get('severity', 'CRITICAL'),
                    'description': f"[{report.get('source', 'Unknown')}] {report.get('summary', 'Malicious package detected')}",
                    'source': report.get('source', 'Unknown'),
                    'report_id': report.get('id', '')
                })
        
        # Data-flow findings
        if results.get('data_flow', {}).get('dangerous_sinks'):
            for sink in results['data_flow']['dangerous_sinks']:
                if sink.get('has_tainted_input'):
                    findings.append({
                        'type': 'Data Flow Risk',
                        'severity': 'HIGH',
                        'description': f"{sink.get('function', 'Unknown')}() called with tainted input at line {sink.get('line', 0)} in {sink.get('file', 'unknown')}",
                        'file': sink.get('file', 'unknown'),
                        'line': sink.get('line', 0)
                    })
        
        # Vulnerability findings
        if results.get('vulnerabilities'):
            for vuln in results['vulnerabilities']:
                severity = str(vuln.get('severity', 'UNKNOWN')).upper()
                # Normalize severity
                if 'CRITICAL' in severity:
                    severity = 'CRITICAL'
                elif 'HIGH' in severity:
                    severity = 'HIGH'
                elif 'MEDIUM' in severity:
                    severity = 'MEDIUM'
                else:
                    severity = 'MEDIUM'
                
                findings.append({
                    'type': 'Known Vulnerability',
                    'severity': severity,
                    'description': f"{vuln.get('id', 'Unknown')}: {vuln.get('summary', 'No summary')}",
                    'vuln_id': vuln.get('id', 'Unknown')
                })
        
        # Domain/IP findings
        if results.get('suspicious_domains'):
            for domain in results['suspicious_domains']:
                findings.append({
                    'type': 'Suspicious Domain',
                    'severity': 'HIGH' if domain.get('suspicious') else 'MEDIUM',
                    'description': f"Suspicious domain found: {domain.get('domain', 'unknown')} in {domain.get('file', 'unknown')} at line {domain.get('line', 0)}",
                    'file': domain.get('file', 'unknown'),
                    'line': domain.get('line', 0),
                    'domain': domain.get('domain', 'unknown')
                })
        
        if results.get('suspicious_ips'):
            for ip_info in results['suspicious_ips']:
                findings.append({
                    'type': 'Suspicious IP Address',
                    'severity': 'MEDIUM',
                    'description': f"External IP address found: {ip_info.get('ip', 'unknown')} in {ip_info.get('file', 'unknown')} at line {ip_info.get('line', 0)}",
                    'file': ip_info.get('file', 'unknown'),
                    'line': ip_info.get('line', 0),
                    'ip': ip_info.get('ip', 'unknown')
                })
        
        # Credential findings
        if results.get('credentials_found'):
            for cred in results['credentials_found']:
                findings.append({
                    'type': 'Credential/Token',
                    'severity': cred.get('severity', 'MEDIUM'),
                    'description': f"{cred.get('type', 'Unknown')} found in {cred.get('file', 'unknown')} at line {cred.get('line', 0)}",
                    'file': cred.get('file', 'unknown'),
                    'line': cred.get('line', 0),
                    'cred_type': cred.get('type', 'Unknown')
                })
        
        # Obfuscation findings
        if results.get('obfuscation_detected'):
            for obf in results['obfuscation_detected']:
                desc = f"{obf.get('type', 'Unknown')} detected in {obf.get('file', 'unknown')}"
                if obf.get('line'):
                    desc += f" at line {obf['line']}"
                if obf.get('count'):
                    desc += f" ({obf['count']} occurrences)"
                if obf.get('entropy'):
                    desc += f" (entropy: {obf['entropy']})"
                
                findings.append({
                    'type': 'Code Obfuscation',
                    'severity': obf.get('severity', 'MEDIUM'),
                    'description': desc,
                    'file': obf.get('file', 'unknown'),
                    'line': obf.get('line', 0),
                    'obf_type': obf.get('type', 'Unknown')
                })
        
        # Setup behavior findings
        if results.get('setup_behavior'):
            setup = results['setup_behavior']
            if setup.get('has_post_install'):
                findings.append({
                    'type': 'Setup Behavior',
                    'severity': 'HIGH',
                    'description': 'Post-install hooks detected in setup.py'
                })
            if setup.get('network_during_setup'):
                findings.append({
                    'type': 'Setup Behavior',
                    'severity': 'MEDIUM',
                    'description': f"Network operations during setup detected: {', '.join(setup.get('suspicious_imports', []))}"
                })
            if setup.get('dangerous_calls'):
                for call in setup['dangerous_calls'][:5]:  # Limit to first 5
                    findings.append({
                        'type': 'Setup Behavior',
                        'severity': 'HIGH',
                        'description': f"Dangerous function call in setup.py: {call.get('function', 'unknown')} at line {call.get('line', 0)}",
                        'file': 'setup.py',
                        'line': call.get('line', 0)
                    })
        
        # Dynamic analysis findings - NEW!
        if results.get('dynamic_analysis'):
            dynamic = results['dynamic_analysis']
            
            # Network connections
            if dynamic.get('network_connections'):
                for conn in dynamic['network_connections']:
                    findings.append({
                        'type': 'Runtime Network Activity',
                        'severity': conn.get('severity', 'HIGH'),
                        'description': conn.get('type', 'Network connection detected') + 
                                     (f" to {conn.get('remote_ip', 'unknown')}:{conn.get('remote_port', 0)}" if conn.get('remote_ip') else ''),
                        'evidence': conn.get('evidence', '')
                    })
            
            # File operations
            if dynamic.get('file_operations'):
                for file_op in dynamic['file_operations'][:5]:  # Limit to first 5
                    findings.append({
                        'type': 'Runtime File Operation',
                        'severity': file_op.get('severity', 'MEDIUM'),
                        'description': f"{file_op.get('type', 'File operation')} on {file_op.get('path', 'unknown')}",
                        'file': file_op.get('path', 'unknown')
                    })
            
            # Process spawns
            if dynamic.get('process_spawns'):
                for proc in dynamic['process_spawns'][:5]:  # Limit to first 5
                    findings.append({
                        'type': 'Runtime Process Spawn',
                        'severity': proc.get('severity', 'HIGH'),
                        'description': f"{proc.get('type', 'Process spawned')}: {proc.get('name', 'unknown')} (PID: {proc.get('pid', 'unknown')})"
                    })
            
            # High CPU/Memory
            if dynamic.get('cpu_usage', 0) > 80:
                findings.append({
                    'type': 'Runtime Behavior',
                    'severity': 'CRITICAL',
                    'description': f'High CPU usage detected: {dynamic["cpu_usage"]:.1f}% - possible crypto mining'
                })
            
            if dynamic.get('memory_usage', 0) > 500:
                findings.append({
                    'type': 'Runtime Behavior',
                    'severity': 'MEDIUM',
                    'description': f'High memory usage detected: {dynamic["memory_usage"]:.1f}MB'
                })
            
            # Timeout
            if dynamic.get('timeout'):
                findings.append({
                    'type': 'Runtime Behavior',
                    'severity': 'CRITICAL',
                    'description': 'Package execution timed out - possible infinite loop, DoS, or crypto mining'
                })
            
            # Errors
            if dynamic.get('errors'):
                for error in dynamic['errors']:
                    if error.get('severity') in ['CRITICAL', 'HIGH']:
                        findings.append({
                            'type': 'Runtime Error',
                            'severity': error.get('severity', 'MEDIUM'),
                            'description': error.get('description', 'Unknown runtime error')
                        })
        
        return findings
    
    def _find_python_files(self, package_dir):
        """Find all Python files in package."""
        python_files = []
        for root, dirs, files in os.walk(package_dir):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'tests', 'test']]
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        return python_files


class DynamicAnalyzer:
    """Dynamic analysis - Run package in sandbox and monitor behavior."""
    
    def __init__(self, log_callback=None):
        self.log = log_callback or (lambda x: None)
        self.docker_available = self._check_docker()
        self.psutil_available = PSUTIL_AVAILABLE
    
    def analyze_runtime_behavior(self, package_dir, package_name):
        """Run package in isolated environment and record behavior."""
        self.log(f"  → Starting dynamic analysis (sandbox execution)...")
        
        if self.docker_available:
            self.log(f"    Using Docker sandbox (most secure)")
            return self._docker_sandbox_analysis(package_dir, package_name)
        else:
            self.log(f"    Using process-level sandbox (Docker not available)")
            return self._process_sandbox_analysis(package_dir, package_name)
    
    def _docker_sandbox_analysis(self, package_dir, package_name):
        """Run in Docker container with MAXIMUM SECURITY - hardened against kernel exploits, side-channels, and escapes."""
        findings = {
            'network_connections': [],
            'file_operations': [],
            'process_spawns': [],
            'cpu_usage': 0,
            'memory_usage': 0,
            'execution_time': 0,
            'timeout': False,
            'errors': []
        }
        
        try:
            # Create a temporary test script
            test_script = f"""
import sys
import traceback
try:
    sys.path.insert(0, '/app')
    import {package_name}
    print("IMPORT_SUCCESS")
except ImportError as e:
    print(f"IMPORT_ERROR: {{e}}")
except Exception as e:
    print(f"EXECUTION_ERROR: {{e}}")
    traceback.print_exc()
"""
            
            # Write test script to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_script)
                test_script_path = f.name
            
            # Create MINIMAL seccomp profile - ONLY essential syscalls for Python execution
            # This prevents kernel exploits by blocking dangerous syscalls
            seccomp_profile = {
                "defaultAction": "SCMP_ACT_ERRNO",  # Deny by default
                "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
                "syscalls": [
                    {
                        "names": [
                            # File operations - READ ONLY
                            "read", "readv", "pread", "preadv", "preadv2",
                            "open", "openat", "close", "fcntl",
                            "stat", "fstat", "lstat", "newfstatat",
                            "getdents", "getdents64",
                            "lseek", "access", "faccessat",
                            
                            # Memory operations - MINIMAL
                            "mmap", "mprotect", "munmap", "brk",
                            "mremap", "msync", "mincore", "madvise",
                            
                            # Process control - RESTRICTED
                            "exit", "exit_group", "getpid", "getppid",
                            "gettid", "getuid", "geteuid", "getgid", "getegid",
                            "getpgrp", "getpgid", "getsid",
                            
                            # Signals - MINIMAL
                            "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                            "rt_sigpending", "rt_sigtimedwait", "rt_sigsuspend",
                            "sigaltstack", "tgkill",
                            
                            # Time operations
                            "gettimeofday", "clock_gettime", "clock_getres",
                            "nanosleep", "alarm", "getitimer",
                            
                            # System info - READ ONLY
                            "uname", "getrlimit", "getrusage", "sysinfo",
                            "times", "getpriority",
                            
                            # Threading - MINIMAL
                            "futex", "sched_yield", "set_thread_area", "get_thread_area",
                            
                            # I/O - MINIMAL (stdout/stderr only)
                            "write", "writev",  # Only for stdout/stderr (read-only filesystem)
                            "ioctl", "pipe", "pipe2", "dup", "dup2", "dup3",
                            
                            # Directory operations - READ ONLY
                            "getcwd", "chdir", "fchdir",
                            
                            # No network syscalls (socket, connect, bind, etc.) - BLOCKED
                            # No process creation (clone, fork, vfork, execve) - BLOCKED
                            # No file modification (write, unlink, mkdir, etc.) - BLOCKED except minimal write
                            # No privilege escalation (setuid, setgid, etc.) - BLOCKED
                            # No kernel modules (init_module, delete_module) - BLOCKED
                            # No mount operations (mount, umount) - BLOCKED
                            # No chroot, pivot_root - BLOCKED
                            # No ptrace, perf_event_open - BLOCKED (side-channel protection)
                            # No userfaultfd - BLOCKED (exploit vector)
                            # No io_uring - BLOCKED (recent exploit vector)
                            # No bpf - BLOCKED (kernel access)
                            # No kexec - BLOCKED (kernel execution)
                        ],
                        "action": "SCMP_ACT_ALLOW"
                    }
                ]
            }
            
            # Write seccomp profile to temp file
            seccomp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(seccomp_profile, seccomp_file)
            seccomp_file.close()
            seccomp_path = seccomp_file.name
            
            try:
                # Run in Docker container with MAXIMUM SECURITY restrictions
                start_time = time.time()
                
                docker_cmd = [
                    'docker', 'run', '--rm',
                    # Network isolation - COMPLETE
                    '--network', 'none',  # No network access
                    
                    # Capabilities - DROP ALL (NO EXCEPTIONS)
                    '--cap-drop', 'ALL',  # Drop ALL capabilities - no privilege escalation possible
                    # NO cap-add - Python doesn't need any capabilities in read-only mode
                    
                    # Security options - MAXIMUM HARDENING
                    '--security-opt', 'no-new-privileges:true',  # Prevent privilege escalation
                    '--security-opt', 'seccomp=' + seccomp_path,  # Custom minimal seccomp profile
                    '--security-opt', 'apparmor=docker-default',  # AppArmor profile (if available)
                    '--security-opt', 'label=disable',  # Disable SELinux (if causing issues)
                    
                    # User namespace isolation - PREVENT ESCAPE
                    '--user', '1000:1000',  # Run as non-root user (UID 1000)
                    # Note: --userns=host can be safer in some cases, but --user is sufficient
                    
                    # Additional hardening
                    '--init',  # Use tini as init (prevents zombie processes)
                    '--ipc', 'none',  # No shared memory (prevent side-channel attacks)
                    '--uts', 'private',  # Private UTS namespace (isolated hostname)
                    
                    # Resource limits - STRICT
                    '--memory', '256m',  # Reduced memory limit
                    '--memory-swap', '256m',  # No swap
                    '--cpus', '0.25',  # Reduced CPU (prevent mining)
                    '--cpu-shares', '256',  # Low priority
                    '--pids-limit', '10',  # Limit process count (prevent fork bombs)
                    '--ulimit', 'nofile=64:64',  # Limit open files
                    '--ulimit', 'nproc=10:10',  # Limit processes
                    
                    # Filesystem - READ-ONLY + RESTRICTIONS
                    '--read-only',  # Read-only root filesystem
                    '--tmpfs', '/tmp:rw,noexec,nosuid,size=50m,nodev',  # Temporary filesystem with restrictions
                    '--tmpfs', '/var/tmp:rw,noexec,nosuid,size=50m,nodev',
                    '--tmpfs', '/run:rw,noexec,nosuid,size=10m,nodev',
                    
                    # Volume mounts - READ-ONLY
                    '-v', f'{package_dir}:/app:ro,noexec,nosuid,nodev',  # Read-only, no exec, no suid
                    '-v', f'{test_script_path}:/test.py:ro,noexec,nosuid,nodev',
                    
                    # Additional security - ISOLATION
                    '--hostname', 'sandbox',  # Isolated hostname
                    '--domainname', 'sandbox.local',  # Isolated domain
                    '--dns', '127.0.0.1',  # No DNS (network is none anyway)
                    # Note: --pid=host can prevent PID namespace attacks but may expose host PIDs
                    # Using default (private PID namespace) is safer for isolation
                    
                    # Image
                    'python:3.11-slim',
                    'python', '/test.py'
                ]
                
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    timeout=10,
                    text=True,
                    env={**os.environ, 'PYTHONUNBUFFERED': '1'}  # Unbuffered output
                )
                
                execution_time = time.time() - start_time
                findings['execution_time'] = execution_time
                
                # Analyze output
                stdout = result.stdout or ''
                stderr = result.stderr or ''
                combined = stdout + stderr
                
                # Check for network attempts
                network_keywords = ['socket', 'urllib', 'requests', 'http', 'connect', 'gethostbyname']
                for keyword in network_keywords:
                    if keyword.lower() in combined.lower():
                        findings['network_connections'].append({
                            'type': f'Network operation detected: {keyword}',
                            'severity': 'HIGH',
                            'evidence': combined[:200]
                        })
                        break
                
                # Check for file operations
                file_keywords = ['open(', 'write(', 'remove(', 'delete(', 'mkdir', 'rmdir']
                for keyword in file_keywords:
                    if keyword.lower() in combined.lower():
                        findings['file_operations'].append({
                            'type': f'File operation detected: {keyword}',
                            'severity': 'MEDIUM',
                            'evidence': combined[:200]
                        })
                        break
                
                # Check for suspicious imports
                suspicious_imports = ['subprocess', 'os.system', 'eval', 'exec', 'compile']
                for imp in suspicious_imports:
                    if imp in combined:
                        findings['process_spawns'].append({
                            'type': f'Suspicious import/operation: {imp}',
                            'severity': 'HIGH',
                            'evidence': combined[:200]
                        })
                
                # Check for timeout or hanging
                if execution_time > 8:
                    findings['timeout'] = True
                    findings['errors'].append({
                        'type': 'Long execution time',
                        'severity': 'MEDIUM',
                        'description': f'Package took {execution_time:.2f}s to execute'
                    })
                
                # Check for errors
                if 'EXECUTION_ERROR' in stdout or 'Traceback' in stderr:
                    findings['errors'].append({
                        'type': 'Execution error',
                        'severity': 'LOW',
                        'description': 'Package raised exception during import'
                    })
            
            finally:
                # Clean up temp files
                try:
                    os.unlink(test_script_path)
                except:
                    pass
                try:
                    os.unlink(seccomp_path)
                except:
                    pass
        
        except subprocess.TimeoutExpired:
            findings['timeout'] = True
            findings['errors'].append({
                'type': 'Execution timeout',
                'severity': 'CRITICAL',
                'description': 'Package execution timed out - possible infinite loop, mining, or DoS'
            })
        
        except FileNotFoundError:
            findings['errors'].append({
                'type': 'Docker not found',
                'severity': 'LOW',
                'description': 'Docker command not available'
            })
        
        except Exception as e:
            findings['errors'].append({
                'type': 'Sandbox error',
                'severity': 'MEDIUM',
                'description': f'Error during Docker sandbox execution: {str(e)}'
            })
        
        return findings
    
    def _process_sandbox_analysis(self, package_dir, package_name):
        """Process-level sandbox (when Docker is not available)."""
        findings = {
            'network_connections': [],
            'file_operations': [],
            'process_spawns': [],
            'cpu_usage': 0,
            'memory_usage': 0,
            'execution_time': 0,
            'timeout': False,
            'errors': []
        }
        
        if not self.psutil_available:
            findings['errors'].append({
                'type': 'psutil not available',
                'severity': 'LOW',
                'description': 'psutil library not installed - cannot monitor process behavior'
            })
            return findings
        
        # Create test script
        test_script = f"""
import sys
import os
sys.path.insert(0, r'{package_dir}')
try:
    import {package_name}
    print("IMPORT_SUCCESS")
except Exception as e:
    print(f"IMPORT_ERROR: {{e}}")
    import traceback
    traceback.print_exc()
"""
        
        # Write test script to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_script_path = f.name
        
        proc = None
        try:
            # Start process
            proc = subprocess.Popen(
                [sys.executable, test_script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=tempfile.gettempdir()
            )
            
            # Monitor for 5 seconds
            start_time = time.time()
            peak_cpu = 0
            peak_memory = 0
            monitoring_duration = 5.0
            
            p = psutil.Process(proc.pid)
            
            while time.time() - start_time < monitoring_duration:
                try:
                    # Check if process is still running
                    if not p.is_running():
                        break
                    
                    # Monitor CPU and memory
                    cpu = p.cpu_percent(interval=0.1)
                    memory_info = p.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024  # Convert to MB
                    
                    peak_cpu = max(peak_cpu, cpu)
                    peak_memory = max(peak_memory, memory_mb)
                    
                    # Check network connections
                    try:
                        connections = p.connections()
                        for conn in connections:
                            if conn.status == psutil.CONN_ESTABLISHED:
                                remote_ip = conn.raddr.ip if conn.raddr else 'Unknown'
                                remote_port = conn.raddr.port if conn.raddr else 0
                                
                                # Only report external connections
                                if remote_ip not in ['127.0.0.1', '::1', 'localhost']:
                                    findings['network_connections'].append({
                                        'remote_ip': str(remote_ip),
                                        'remote_port': remote_port,
                                        'severity': 'HIGH',
                                        'type': 'External network connection'
                                    })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Check open files
                    try:
                        open_files = p.open_files()
                        for file_info in open_files:
                            file_path = file_info.path
                            # Filter out standard files
                            if file_path not in ['/dev/null', '/dev/urandom', '/dev/random', 'NUL']:
                                if not file_path.startswith(tempfile.gettempdir()):
                                    findings['file_operations'].append({
                                        'path': file_path,
                                        'mode': file_info.mode if hasattr(file_info, 'mode') else 'unknown',
                                        'severity': 'MEDIUM',
                                        'type': 'File access'
                                    })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Check child processes
                    try:
                        children = p.children(recursive=True)
                        if children:
                            for child in children:
                                findings['process_spawns'].append({
                                    'pid': child.pid,
                                    'name': child.name(),
                                    'severity': 'HIGH',
                                    'type': 'Child process spawned'
                                })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    time.sleep(0.2)
                
                except psutil.NoSuchProcess:
                    break
                except Exception as e:
                    self.log(f"    Warning during monitoring: {str(e)}")
                    break
            
            # Terminate process if still running
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            
            # Get output
            try:
                stdout, stderr = proc.communicate(timeout=1)
                combined_output = (stdout or '') + (stderr or '')
                
                # Analyze output for suspicious patterns
                if 'socket' in combined_output.lower() or 'urllib' in combined_output.lower():
                    findings['network_connections'].append({
                        'type': 'Network operation in output',
                        'severity': 'MEDIUM',
                        'evidence': combined_output[:200]
                    })
            
            except subprocess.TimeoutExpired:
                pass
            
            findings['cpu_usage'] = peak_cpu
            findings['memory_usage'] = peak_memory
            findings['execution_time'] = time.time() - start_time
            
            # High CPU usage = possible crypto mining?
            if peak_cpu > 80:
                findings['errors'].append({
                    'type': 'High CPU usage',
                    'severity': 'CRITICAL',
                    'description': f'CPU usage peaked at {peak_cpu:.1f}% - possible crypto mining'
                })
            
            # High memory usage
            if peak_memory > 500:  # MB
                findings['errors'].append({
                    'type': 'High memory usage',
                    'severity': 'MEDIUM',
                    'description': f'Memory usage peaked at {peak_memory:.1f}MB'
                })
        
        except subprocess.TimeoutExpired:
            findings['timeout'] = True
            findings['errors'].append({
                'type': 'Execution timeout',
                'severity': 'CRITICAL',
                'description': 'Package execution timed out - possible infinite loop or DoS'
            })
            if proc:
                try:
                    proc.kill()
                except:
                    pass
        
        except Exception as e:
            findings['errors'].append({
                'type': 'Sandbox error',
                'severity': 'MEDIUM',
                'description': f'Error during process sandbox execution: {str(e)}'
            })
        
        finally:
            # Clean up
            if proc:
                try:
                    if proc.poll() is None:
                        proc.kill()
                except:
                    pass
            try:
                os.unlink(test_script_path)
            except:
                pass
        
        return findings
    
    def _check_docker(self):
        """Check if Docker is available."""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                timeout=2,
                text=True
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        except Exception:
            return False


def load_gemini_api_key():
    """Google Gemini API anahtarını yükle (main.py'deki gibi)"""
    # Önce environment variable'dan dene
    api_key = os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY')
    if api_key:
        return api_key
    
    # Sonra config.json'dan dene
    config_file = 'config.json'
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config.get('google_api_key') or config.get('gemini_api_key')
        except:
            pass
    
    return None


class GeminiAIAnalyzer:
    """Gemini AI analyzer for log analysis and AI scoring."""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or load_gemini_api_key()
        self.model = None
        if GEMINI_AVAILABLE and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                
                # Model seç (main.py'deki gibi)
                try:
                    models = genai.list_models()
                    available_models = [m.name for m in models if 'generateContent' in m.supported_generation_methods]
                    if 'models/gemini-1.5-flash' in available_models:
                        self.model = genai.GenerativeModel('gemini-1.5-flash')
                    elif 'models/gemini-flash-latest' in available_models:
                        self.model = genai.GenerativeModel('gemini-flash-latest')
                    else:
                        self.model = genai.GenerativeModel('gemini-1.5-flash')
                except:
                    # Fallback
                    self.model = genai.GenerativeModel('gemini-1.5-flash')
            except Exception as e:
                print(f"Warning: Could not initialize Gemini AI: {e}")
                self.model = None
    
    def analyze_logs(self, package_name, logs, analysis_results):
        """Analyze logs and analysis results using Gemini AI."""
        if not self.model:
            api_key_help = "Please set GOOGLE_API_KEY or GEMINI_API_KEY environment variable, or add it to config.json"
            return {
                'ai_score': 0,
                'ai_explanation': f'Gemini AI not available. {api_key_help}',
                'security_concerns': [],
                'recommendations': []
            }
        
        try:
            # Prepare prompt
            prompt = f"""You are a cybersecurity expert analyzing a Python package security scan.

Package Name: {package_name}

Analysis Logs:
{logs}

Analysis Results Summary:
- Risk Score: {analysis_results.get('risk_score', 0)}/100
- Risk Level: {analysis_results.get('risk_level', 'Unknown')}
- Findings Count: {len(analysis_results.get('findings', []))}
- Threat Intelligence: {'MALICIOUS' if analysis_results.get('threat_intelligence', {}).get('is_malicious') else 'CLEAN'}
- Vulnerabilities: {len(analysis_results.get('vulnerabilities', []))}
- Suspicious Domains: {len(analysis_results.get('suspicious_domains', []))}
- Credentials Found: {len(analysis_results.get('credentials_found', []))}
- Obfuscation Detected: {len(analysis_results.get('obfuscation_detected', []))}

Please analyze these logs and provide:
1. An AI Security Score from 0-100 (where 0 is completely safe and 100 is extremely dangerous)
2. A detailed explanation in English explaining why you gave this score
3. Specific security concerns found in the logs
4. Recommendations for the user

Respond in JSON format:
{{
    "ai_score": <number 0-100>,
    "ai_explanation": "<detailed explanation in English>",
    "security_concerns": ["<concern1>", "<concern2>", ...],
    "recommendations": ["<recommendation1>", "<recommendation2>", ...]
}}
"""
            
            # Generate content (main.py'deki gibi)
            response = self.model.generate_content(prompt)
            
            # Cevabı güvenli şekilde al (main.py'deki gibi)
            try:
                response_text = response.text.strip()
            except AttributeError:
                # Eğer response.text çalışmazsa, parts'ı kullan
                try:
                    if response.candidates and len(response.candidates) > 0:
                        parts = response.candidates[0].content.parts
                        response_text = ''.join([part.text for part in parts if hasattr(part, 'text')]).strip()
                    else:
                        response_text = ""
                except Exception as e:
                    logging.error(f"Gemini AI response parsing error: {str(e)}")
                    return {
                        'ai_score': 0,
                        'ai_explanation': f'Gemini AI response error: {str(e)}',
                        'security_concerns': [],
                        'recommendations': []
                    }
            
            # Check if response is empty
            if not response_text or len(response_text.strip()) == 0:
                logging.warning("Gemini AI returned empty response")
                return {
                    'ai_score': 0,
                    'ai_explanation': 'Gemini AI returned empty response',
                    'security_concerns': [],
                    'recommendations': []
                }
            
            # Try to extract JSON from response
            # Sometimes Gemini wraps JSON in markdown code blocks
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0].strip()
            
            try:
                result = json.loads(response_text)
                ai_score = int(result.get('ai_score', 0))
                logging.info(f"Gemini AI analysis successful for {package_name}: Score={ai_score}")
                return {
                    'ai_score': ai_score,
                    'ai_explanation': result.get('ai_explanation', 'No explanation provided'),
                    'security_concerns': result.get('security_concerns', []),
                    'recommendations': result.get('recommendations', [])
                }
            except json.JSONDecodeError as e:
                logging.warning(f"JSON parsing failed, trying regex extraction: {e}")
                # If JSON parsing fails, try to extract score from text
                score_match = re.search(r'"ai_score"\s*:\s*(\d+)', response_text)
                ai_score = int(score_match.group(1)) if score_match else 0
                
                # Try to extract explanation
                explanation_match = re.search(r'"ai_explanation"\s*:\s*"([^"]+)"', response_text)
                explanation = explanation_match.group(1) if explanation_match else response_text[:500]
                
                logging.info(f"Gemini AI analysis (regex) for {package_name}: Score={ai_score}")
                return {
                    'ai_score': ai_score,
                    'ai_explanation': explanation if explanation else response_text[:500],
                    'security_concerns': [],
                    'recommendations': []
                }
        
        except Exception as e:
            import traceback
            error_msg = f'Gemini AI analysis error: {str(e)}'
            logging.error(f"Gemini AI error: {error_msg}")
            logging.error(traceback.format_exc())
            return {
                'ai_score': 0,
                'ai_explanation': error_msg,
                'security_concerns': [],
                'recommendations': []
            }


class ChainGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ChainGuard - Python Package Security Scanner")
        self.root.geometry("1200x700")
        self.root.configure(bg='#f0f0f0')
        
        self.selected_path = None
        self.python_files = []
        self.library_data = {}
        self.sandbox_dir = None
        self.analysis_reports = {}  # Store detailed analysis reports
        
        # Log collection for each package (for Gemini AI analysis)
        self.package_logs = {}  # {package_name: [list of log messages]}
        
        # Initialize Gemini AI (but don't log yet - log_text not created yet)
        self.gemini_analyzer = GeminiAIAnalyzer()
        
        # Popüler paketler (typosquatting kontrolü için)
        self.popular_packages = {
            'requests', 'urllib3', 'pyyaml', 'django', 'flask', 'numpy',
            'pandas', 'matplotlib', 'setuptools', 'beautifulsoup4'
        }
        
        # Threat intelligence cache (to avoid repeated API calls)
        self.threat_intel_cache = {}
        
        # Malicious package lists cache (fetched from community sources)
        self.malicious_packages_cache = None
        self.malicious_packages_last_fetch = None
        
        # Malicious package sources (community-driven, regularly updated)
        # Using real, working repositories
        self.MALICIOUS_PACKAGE_SOURCES = [
            # 1. Luta Security (Best source!)
            "https://pypi.org/simple/",
         
        ]
        
        # Header Section
        header_frame = tk.Frame(root, bg='#2c3e50', height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="ChainGuard", 
                               font=("Arial", 24, "bold"), 
                               bg='#2c3e50', fg='white')
        title_label.pack(side=tk.LEFT, padx=20, pady=20)
        
        subtitle_label = tk.Label(header_frame, text="Python Package Security Scanner", 
                                  font=("Arial", 11), 
                                  bg='#2c3e50', fg='#ecf0f1')
        subtitle_label.pack(side=tk.LEFT, padx=10, pady=20)
        
        # Main container
        main_container = tk.Frame(root, bg='#f0f0f0')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Controls and Logs
        left_panel = tk.Frame(main_container, bg='#ffffff', relief=tk.RAISED, bd=1)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))
        left_panel.config(width=400)
        
        # Project selection frame
        file_frame = ttk.LabelFrame(left_panel, text="Project Selection", padding="15")
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.path_label = ttk.Label(file_frame, text="No project selected", foreground="gray")
        self.path_label.pack(fill=tk.X, pady=5)
        
        button_frame = tk.Frame(file_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Select Project", command=self.select_directory).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        ttk.Button(button_frame, text="Scan", command=self.analyze_project).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        ttk.Button(button_frame, text="Security Analysis", command=self.security_analysis).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        
        # File count label
        self.file_count_label = ttk.Label(file_frame, text="", foreground="#3498db", cursor="hand2")
        self.file_count_label.pack(fill=tk.X, pady=5)
        self.file_count_label.bind("<Button-1>", self.show_python_files)
        
        # Progress bar frame
        progress_frame = ttk.LabelFrame(left_panel, text="Scan Progress", padding="15")
        progress_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, length=350)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="Ready", font=("Arial", 9))
        self.progress_label.pack(fill=tk.X)
        
        # Log frame
        log_frame = ttk.LabelFrame(left_panel, text="Scan Logs", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=45, 
                                                   font=("Consolas", 9), 
                                                   bg='#1e1e1e', fg='#d4d4d4',
                                                   insertbackground='white')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Results
        right_panel = tk.Frame(main_container, bg='#ffffff', relief=tk.RAISED, bd=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        results_frame = ttk.LabelFrame(right_panel, text="Package Analysis Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for results
        columns = ("Package", "Status", "Version", "Security", "Risk Score", "AI Score")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="tree headings", height=20)
        self.tree.heading("#0", text="")  # Tree column (for expand/collapse)
        self.tree.heading("Package", text="Package Name")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Version", text="Version")
        self.tree.heading("Security", text="Security Status")
        self.tree.heading("Risk Score", text="Risk Score")
        self.tree.heading("AI Score", text="AI Score")
        self.tree.column("#0", width=20, stretch=False)
        self.tree.column("Package", width=180)
        self.tree.column("Status", width=100)
        self.tree.column("Version", width=80)
        self.tree.column("Security", width=180)
        self.tree.column("Risk Score", width=80)
        self.tree.column("AI Score", width=80)
        
        # Configure tags for color coding - entire row colors based on Risk Score
        self.tree.tag_configure("safe", background="#d4edda", foreground="#155724")  # Light green background, dark green text
        self.tree.tag_configure("warning", background="#ffeaa7", foreground="#6c5ce7")  # Light yellow background
        self.tree.tag_configure("suspicious", background="#fff3cd", foreground="#856404")  # Light orange background, dark orange text
        self.tree.tag_configure("malicious", background="#f8d7da", foreground="#721c24")  # Light red background, dark red text
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar at bottom
        status_frame = tk.Frame(root, bg='#34495e', height=30)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                     bg='#34495e', fg='white', 
                                     font=("Arial", 9), anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Initialize log
        self.log("ChainGuard initialized")
        self.log("Ready to scan project")
        
        # Log Gemini AI status (now that log_text is created)
        if self.gemini_analyzer.model:
            self.log("Gemini AI initialized successfully")
        else:
            api_key_help = "Set GOOGLE_API_KEY or GEMINI_API_KEY environment variable, or add to config.json"
            self.log(f"⚠️  Gemini AI not available. {api_key_help}")
    
    def log(self, message, package_name=None):
        """Add message to log panel and collect logs for package analysis"""
        log_entry = f"[{self.get_timestamp()}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Collect logs for package analysis (for Gemini AI)
        if package_name:
            if package_name not in self.package_logs:
                self.package_logs[package_name] = []
            self.package_logs[package_name].append(message)
        
        self.root.update_idletasks()
    
    def get_timestamp(self):
        """Get current timestamp"""
        return datetime.now().strftime("%H:%M:%S")
    
    def update_progress(self, value, text=""):
        """Update progress bar"""
        self.progress_var.set(value)
        if text:
            self.progress_label.config(text=text)
        self.root.update_idletasks()
    
    def select_directory(self):
        """Directory selection dialog"""
        directory = filedialog.askdirectory(title="Select Python Project Directory")
        if directory:
            self.selected_path = directory
            self.path_label.config(text=directory, foreground="black")
            self.status_label.config(text=f"Selected: {directory}")
            self.log(f"Project selected: {directory}")
    
    def find_python_files(self, directory):
        """Find all .py files in directory and subdirectories"""
        python_files = []
        self.log("Scanning for Python files...")
        for root, dirs, files in os.walk(directory):
            # Skip __pycache__ and .git folders
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.venv', 'venv', 'env']]
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        self.log(f"Found {len(python_files)} Python files")
        return python_files
    
    def extract_imports(self, file_path):
        """Extract imports from Python file - handles both AST and regex fallback for invalid syntax."""
        imports = set()
        content = ""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return imports
        
        # Try AST parsing first (handles valid Python syntax)
        try:
            tree = ast.parse(content, filename=file_path)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except (SyntaxError, ValueError, TypeError):
            # AST parsing failed (e.g., invalid syntax, numbers starting imports)
            # Fallback to regex parsing
            pass
        
        # Regex fallback: Extract imports even if AST fails (handles invalid syntax)
        # Pattern: import <module> or from <module> import ...
        # Note: Python doesn't allow identifiers starting with numbers, but we catch them anyway for testing
        import_patterns = [
            r'^\s*import\s+([0-9a-zA-Z_][a-zA-Z0-9_.]*)',  # import module (can start with number for testing)
            r'^\s*from\s+([0-9a-zA-Z_][a-zA-Z0-9_.]*)\s+import',  # from module import
        ]
        
        for line in content.split('\n'):
            # Remove comments
            line = line.split('#')[0].strip()
            
            # Try regex patterns (handles invalid syntax like numbers starting imports)
            for pattern in import_patterns:
                match = re.match(pattern, line)
                if match:
                    module_name = match.group(1)
                    # Extract base module name (first part before dot)
                    base_module = module_name.split('.')[0]
                    if base_module:
                        imports.add(base_module)
        
        # Also handle multi-import statements: import a, b, c or import 1password, 2test
        multi_import_pattern = r'^\s*import\s+([0-9a-zA-Z_][a-zA-Z0-9_.]*(?:\s*,\s*[0-9a-zA-Z_][a-zA-Z0-9_.]*)*)'
        for line in content.split('\n'):
            line = line.split('#')[0].strip()
            match = re.match(multi_import_pattern, line)
            if match:
                modules_str = match.group(1)
                # Split by comma and extract module names
                for module in modules_str.split(','):
                    module = module.strip().split('.')[0]
                    if module:
                        imports.add(module)
        
        return imports
    
    def check_library_installed(self, library_name):
        """Check if library is installed"""
        # Check standard libraries
        if library_name in sys.stdlib_module_names:
            return True, "Standard Library", None
        
        # Check installed libraries
        try:
            spec = importlib.util.find_spec(library_name)
            if spec is not None:
                # Get version info
                version_info = None
                try:
                    version_info = version(library_name)
                except PackageNotFoundError:
                    pass
                return True, "Installed", version_info
            else:
                return False, "Not Installed", None
        except (ImportError, ValueError, ModuleNotFoundError):
            return False, "Not Installed", None
    
    def _check_local_module(self, package_name):
        """Check if package is a local module in the project directory."""
        if not self.selected_path:
            return False
        
        # Check for {package_name}.py file
        module_file = os.path.join(self.selected_path, f"{package_name}.py")
        if os.path.exists(module_file):
            return True
        
        # Check for {package_name}/__init__.py directory
        module_dir = os.path.join(self.selected_path, package_name)
        if os.path.isdir(module_dir):
            init_file = os.path.join(module_dir, "__init__.py")
            if os.path.exists(init_file):
                return True
        
        # Check in subdirectories (common pattern)
        for root, dirs, files in os.walk(self.selected_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'node_modules', 'venv', 'env']]
            
            # Check for {package_name}.py
            if f"{package_name}.py" in files:
                return True
            
            # Check for {package_name}/__init__.py
            if package_name in dirs:
                init_file = os.path.join(root, package_name, "__init__.py")
                if os.path.exists(init_file):
                    return True
        
        return False
    
    def _check_typo(self, package_name):
        """Check if package name might be a typo of a popular package."""
        package_lower = package_name.lower()
        
        # Simple Levenshtein-like check (edit distance)
        def similarity(s1, s2):
            """Calculate simple similarity score (0-1)."""
            if s1 == s2:
                return 1.0
            if abs(len(s1) - len(s2)) > 2:
                return 0.0
            
            # Count matching characters
            matches = sum(1 for a, b in zip(s1, s2) if a == b)
            max_len = max(len(s1), len(s2))
            return matches / max_len if max_len > 0 else 0.0
        
        # Check against popular packages
        best_match = None
        best_score = 0.0
        
        for popular in self.popular_packages:
            score = similarity(package_lower, popular.lower())
            if score > best_score and score >= 0.7:  # 70% similarity threshold
                best_score = score
                best_match = popular
        
        return best_match
    
    def get_pypi_metadata(self, package_name):
        """
        Downloads ONLY JSON metadata from PyPI.
        """
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            with urllib.request.urlopen(url, timeout=10) as response:
                json_text = response.read().decode('utf-8')
                data = json.loads(json_text)
                return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            return None
        except Exception as e:
            return None
    
    def download_package_file(self, package_name, metadata):
        """
        Download package file (wheel or source) from PyPI.
        Returns path to downloaded file or None.
        """
        if not metadata:
            return None
        
        try:
            # Get latest version
            version = metadata['info']['version']
            releases = metadata.get('releases', {})
            version_releases = releases.get(version, [])
            
            if not version_releases:
                return None
            
            # Prefer wheel, fallback to source
            package_file = None
            download_url = None
            file_extension = None
            
            for release in version_releases:
                if release['packagetype'] == 'bdist_wheel' and release['filename'].endswith('.whl'):
                    download_url = release['url']
                    package_file = release['filename']
                    file_extension = '.whl'
                    break
            
            if not download_url:
                for release in version_releases:
                    if release['packagetype'] == 'sdist' and release['filename'].endswith('.tar.gz'):
                        download_url = release['url']
                        package_file = release['filename']
                        file_extension = '.tar.gz'
                        break
            
            if not download_url:
                return None
            
            # Create sandbox directory if not exists
            if not self.sandbox_dir:
                self.sandbox_dir = tempfile.mkdtemp(prefix='chainguard_sandbox_')
                self.log(f"Created sandbox directory: {self.sandbox_dir}")
            
            # Download file
            download_path = os.path.join(self.sandbox_dir, package_file)
            self.log(f"Downloading {package_file} from PyPI...")
            
            with urllib.request.urlopen(download_url, timeout=30) as response:
                with open(download_path, 'wb') as f:
                    shutil.copyfileobj(response, f)
            
            self.log(f"Downloaded: {package_file}")
            return download_path, file_extension
            
        except Exception as e:
            self.log(f"ERROR downloading package: {str(e)}")
            return None
    
    def extract_package(self, package_path, file_extension):
        """
        Extract package file to sandbox directory.
        Returns path to extracted directory (where setup.py or package code is).
        """
        try:
            base_name = os.path.basename(package_path).replace(file_extension, '')
            extract_base = os.path.join(self.sandbox_dir, base_name)
            
            if file_extension == '.whl':
                with zipfile.ZipFile(package_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_base)
                # Wheel files extract to a specific structure, find the actual package dir
                for root, dirs, files in os.walk(extract_base):
                    if 'setup.py' in files:
                        return root
                    # Sometimes package code is in a subdirectory
                    for d in dirs:
                        subdir = os.path.join(root, d)
                        if os.path.isfile(os.path.join(subdir, 'setup.py')):
                            return subdir
                return extract_base
            elif file_extension == '.tar.gz':
                with tarfile.open(package_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_base)
                # Tar.gz usually extracts to a single directory
                extracted_dirs = [d for d in os.listdir(extract_base) 
                                 if os.path.isdir(os.path.join(extract_base, d))]
                if extracted_dirs:
                    # Usually the first directory is the package root
                    package_root = os.path.join(extract_base, extracted_dirs[0])
                    if os.path.exists(os.path.join(package_root, 'setup.py')):
                        return package_root
                    return package_root
                return extract_base
            else:
                return None
            
        except Exception as e:
            self.log(f"ERROR extracting package: {str(e)}")
            return None
    
    def find_python_files_in_package(self, package_dir):
        """Find all .py files in extracted package."""
        python_files = []
        for root, dirs, files in os.walk(package_dir):
            # Skip test directories and __pycache__
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'tests', 'test']]
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        return python_files
    
    def _find_user_input_sources(self, tree):
        """
        Find all user input sources in the AST.
        Returns a set of variable names that are assigned from user input sources.
        Uses a simple approach: track assignments from known user input sources.
        """
        user_input_sources = set()
        
        # Walk the tree and find assignments from user input sources
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check if the value is from a user input source
                value = node.value
                
                # Check for input() calls
                if isinstance(value, ast.Call):
                    if isinstance(value.func, ast.Name) and value.func.id == 'input':
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                user_input_sources.add(target.id)
                    # Check for os.getenv()
                    elif isinstance(value.func, ast.Attribute):
                        if isinstance(value.func.value, ast.Name) and value.func.value.id == 'os':
                            if value.func.attr == 'getenv':
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        user_input_sources.add(target.id)
                
                # Check for sys.argv access
                elif isinstance(value, ast.Subscript):
                    if isinstance(value.value, ast.Attribute):
                        if isinstance(value.value.value, ast.Name) and value.value.value.id == 'sys':
                            if value.value.attr == 'argv':
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        user_input_sources.add(target.id)
                
                # Check for os.environ access
                elif isinstance(value, ast.Subscript):
                    if isinstance(value.value, ast.Attribute):
                        if isinstance(value.value.value, ast.Name) and value.value.value.id == 'os':
                            if value.value.attr == 'environ':
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        user_input_sources.add(target.id)
                
                # Check for request.* access (Flask/Django)
                elif isinstance(value, ast.Attribute):
                    if isinstance(value.value, ast.Name) and value.value.id == 'request':
                        if value.attr in ['args', 'form', 'json', 'GET', 'POST', 'data', 'query_params', 'body']:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    user_input_sources.add(target.id)
        
        return user_input_sources
    
    def _check_user_input_in_args(self, call_node, user_input_sources, tree):
        """
        Check if call node arguments contain user input.
        Returns True if any argument uses user input sources.
        """
        # Check all arguments
        for arg in call_node.args:
            # If argument is a Name (variable), check if it's in user_input_sources
            if isinstance(arg, ast.Name):
                if arg.id in user_input_sources:
                    return True
            
            # If argument is an Attribute (e.g., request.args), check if it's user input
            if isinstance(arg, ast.Attribute):
                if isinstance(arg.value, ast.Name) and arg.value.id == 'request':
                    if arg.attr in ['args', 'form', 'json', 'GET', 'POST', 'data', 'query_params', 'body']:
                        return True
                
                # Check if it's sys.argv
                if isinstance(arg.value, ast.Attribute):
                    if isinstance(arg.value.value, ast.Name) and arg.value.value.id == 'sys':
                        if arg.value.attr == 'argv':
                            return True
                
                # Check if it's os.environ
                if isinstance(arg.value, ast.Name) and arg.value.id == 'os':
                    if arg.attr == 'environ':
                        return True
            
            # If argument is a Subscript (e.g., sys.argv[0])
            if isinstance(arg, ast.Subscript):
                if isinstance(arg.value, ast.Attribute):
                    if isinstance(arg.value.value, ast.Name) and arg.value.value.id == 'sys':
                        if arg.value.attr == 'argv':
                            return True
                    if isinstance(arg.value.value, ast.Name) and arg.value.value.id == 'os':
                        if arg.value.attr == 'environ':
                            return True
            
            # If argument is a Call (e.g., input())
            if isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Name) and arg.func.id == 'input':
                    return True
                if isinstance(arg.func, ast.Attribute):
                    if isinstance(arg.func.value, ast.Name) and arg.func.value.id == 'os':
                        if arg.func.attr == 'getenv':
                            return True
        
        # Check keyword arguments too
        for keyword in call_node.keywords:
            if keyword.value:
                if isinstance(keyword.value, ast.Name):
                    if keyword.value.id in user_input_sources:
                        return True
                if isinstance(keyword.value, ast.Attribute):
                    if isinstance(keyword.value.value, ast.Name) and keyword.value.value.id == 'request':
                        if keyword.value.attr in ['args', 'form', 'json', 'GET', 'POST', 'data', 'query_params', 'body']:
                            return True
        
        return False
    
    def detect_malicious_patterns(self, file_path, content):
        """
        Detect malicious patterns in Python code.
        Returns list of findings.
        """
        findings = []
        
        # Pattern 1: eval/exec/compile - removed from regex matching
        # These will be analyzed in AST analysis with user input detection
        
        # Pattern 2: subprocess/os.system
        subprocess_patterns = [
            (r'subprocess\.(call|run|Popen|check_call|check_output)', 'subprocess call'),
            (r'os\.system\s*\(', 'os.system call'),
            (r'os\.popen\s*\(', 'os.popen call'),
            (r'popen2\s*\(', 'popen2 call'),
            (r'commands\.(getoutput|getstatusoutput)', 'commands module'),
        ]
        for pattern, desc in subprocess_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'System Command Execution',
                    'pattern': pattern,
                    'file': os.path.basename(file_path),
                    'line': line_num,
                    'severity': 'HIGH',
                    'description': f'Found {desc} - can execute system commands'
                })
        
        # Pattern 3: Network calls
        network_patterns = [
            (r'urllib\.(request|urlopen)', 'urllib network call'),
            (r'requests\.(get|post|put|delete|patch)', 'requests HTTP call'),
            (r'socket\.(socket|create_connection)', 'socket connection'),
            (r'httplib\.', 'httplib call'),
            (r'http\.client\.', 'http.client call'),
        ]
        for pattern, desc in network_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'Network Communication',
                    'pattern': pattern,
                    'file': os.path.basename(file_path),
                    'line': line_num,
                    'severity': 'MEDIUM',
                    'description': f'Found {desc} - can communicate over network'
                })
        
        # Pattern 4: Crypto miner keywords
        miner_keywords = [
            'cryptocurrency', 'bitcoin', 'ethereum', 'mining', 'miner', 'hashrate',
            'cryptonight', 'monero', 'xmr', 'stratum', 'mining pool',
            'cryptocurrency mining', 'coin mining', 'crypto mining'
        ]
        for keyword in miner_keywords:
            pattern = rf'\b{re.escape(keyword)}\b'
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'Crypto Miner',
                    'pattern': keyword,
                    'file': os.path.basename(file_path),
                    'line': line_num,
                    'severity': 'CRITICAL',
                    'description': f'Found crypto miner keyword: {keyword}'
                })
        
        # Pattern 5: Credential stealer keywords
        stealer_keywords = [
            'password', 'credential', 'token', 'api_key', 'secret', 'private_key',
            'aws_access_key', 'aws_secret', 'github_token', 'ssh_key', 'private key',
            'stealer', 'keylogger', 'credential theft', 'password theft'
        ]
        for keyword in stealer_keywords:
            # More specific patterns for credential stealing
            patterns = [
                rf'\b{re.escape(keyword)}\s*=\s*["\']',  # keyword = "value"
                rf'{re.escape(keyword)}\s*:\s*["\']',  # keyword: "value"
                rf'get\s*{re.escape(keyword)}',  # get password
                rf'extract\s*{re.escape(keyword)}',  # extract password
                rf'steal\s*{re.escape(keyword)}',  # steal password
            ]
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'Credential Stealer',
                        'pattern': keyword,
                        'file': os.path.basename(file_path),
                        'line': line_num,
                        'severity': 'CRITICAL',
                        'description': f'Found credential stealer pattern: {keyword}'
                    })
                    break  # Only report once per keyword per file
        
        # Pattern 6: Base64/obfuscated code
        base64_pattern = r'base64\.(b64decode|b64encode)'
        matches = re.finditer(base64_pattern, content, re.IGNORECASE)
        base64_count = len(list(matches))
        if base64_count > 5:  # Multiple base64 operations might indicate obfuscation
            findings.append({
                'type': 'Code Obfuscation',
                'pattern': 'base64',
                'file': os.path.basename(file_path),
                'line': 0,
                'severity': 'MEDIUM',
                'description': f'Found {base64_count} base64 operations - possible code obfuscation'
            })
        
        return findings
    
    def analyze_setup_py(self, setup_py_path):
        """Analyze setup.py for post-install scripts and suspicious code."""
        findings = []
        try:
            with open(setup_py_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for post-install scripts
            post_install_patterns = [
                r'cmdclass\s*=\s*\{',
                r'post_install',
                r'setup_requires',
                r'install_requires.*subprocess',
            ]
            for pattern in post_install_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': 'Post-Install Script',
                        'pattern': pattern,
                        'file': 'setup.py',
                        'line': 0,
                        'severity': 'HIGH',
                        'description': 'Found post-install script or setup hook'
                    })
            
            # Check for suspicious imports in setup.py
            if re.search(r'import\s+(subprocess|os|sys|urllib|requests)', content, re.IGNORECASE):
                findings.append({
                    'type': 'Suspicious Setup.py',
                    'pattern': 'suspicious import',
                    'file': 'setup.py',
                    'line': 0,
                    'severity': 'MEDIUM',
                    'description': 'setup.py imports system/network modules'
                })
            
        except Exception as e:
            self.log(f"ERROR analyzing setup.py: {str(e)}")
        
        return findings
    
    def static_analyze_package(self, package_dir, package_name):
        """
        Perform static analysis on extracted package.
        Returns security status, risk level, and detailed findings.
        """
        all_findings = []
        security_status = "SAFE"
        risk_level = "Low"
        
        # Find all Python files
        python_files = self.find_python_files_in_package(package_dir)
        
        if not python_files:
            return security_status, risk_level, all_findings
        
        # Check for setup.py (search in package_dir and subdirectories)
        setup_py_path = None
        for root, dirs, files in os.walk(package_dir):
            if 'setup.py' in files:
                setup_py_path = os.path.join(root, 'setup.py')
                break
        
        if setup_py_path and os.path.exists(setup_py_path):
            setup_findings = self.analyze_setup_py(setup_py_path)
            all_findings.extend(setup_findings)
        
        # Analyze each Python file
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Detect malicious patterns
                findings = self.detect_malicious_patterns(py_file, content)
                all_findings.extend(findings)
                
                # AST-based analysis
                try:
                    tree = ast.parse(content, filename=py_file)
                    
                    # Track user input sources in the file
                    user_input_sources = self._find_user_input_sources(tree)
                    
                    # Check for dangerous AST nodes
                    for node in ast.walk(tree):
                        # Check for eval/exec/compile/__import__ calls
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name):
                                if node.func.id in ['eval', 'exec', 'compile', '__import__']:
                                    line_num = node.lineno
                                    # Check if arguments contain user input
                                    has_user_input = self._check_user_input_in_args(node, user_input_sources, tree)
                                    
                                    if has_user_input:
                                        severity = 'HIGH'
                                        description = f'AST detected {node.func.id}() call with user input - HIGH RISK'
                                    else:
                                        severity = 'LOW'
                                        description = f'AST detected {node.func.id}() call (no user input detected) - Normal usage'
                                    
                                    all_findings.append({
                                        'type': 'Dangerous Code Execution',
                                        'pattern': node.func.id,
                                        'file': os.path.basename(py_file),
                                        'line': line_num,
                                        'severity': severity,
                                        'description': description
                                    })
                        
                        # Check for subprocess imports
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name == 'subprocess':
                                    all_findings.append({
                                        'type': 'System Command Execution',
                                        'pattern': 'subprocess import',
                                        'file': os.path.basename(py_file),
                                        'line': node.lineno,
                                        'severity': 'HIGH',
                                        'description': 'Imports subprocess module'
                                    })
                        
                        # Check for os.system calls
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Attribute):
                                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                                    if node.func.attr in ['system', 'popen', 'spawn']:
                                        all_findings.append({
                                            'type': 'System Command Execution',
                                            'pattern': f'os.{node.func.attr}',
                                            'file': os.path.basename(py_file),
                                            'line': node.lineno,
                                            'severity': 'HIGH',
                                            'description': f'AST detected os.{node.func.attr}() call'
                                        })
                
                except SyntaxError:
                    # Skip files with syntax errors
                    pass
                except Exception as e:
                    self.log(f"ERROR analyzing {py_file}: {str(e)}")
            
            except Exception as e:
                self.log(f"ERROR reading {py_file}: {str(e)}")
        
        # Determine security status based on findings (LOW severity findings are ignored)
        critical_count = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in all_findings if f['severity'] == 'HIGH')
        medium_count = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')
        low_count = sum(1 for f in all_findings if f['severity'] == 'LOW')
        
        if critical_count > 0 or high_count > 3:
            security_status = "MALICIOUS - Suspicious Code Detected"
            risk_level = "Critical"
        elif high_count > 0 or medium_count > 5:
            security_status = "SUSPICIOUS - Multiple Warnings"
            risk_level = "High"
        elif medium_count > 0:
            security_status = "SUSPICIOUS - Some Warnings"
            risk_level = "Medium"
        else:
            security_status = "SAFE"
            risk_level = "Low"
        
        return security_status, risk_level, all_findings
    
    def cleanup_sandbox(self):
        """Clean up sandbox directory and downloaded files."""
        if self.sandbox_dir and os.path.exists(self.sandbox_dir):
            try:
                shutil.rmtree(self.sandbox_dir)
                self.log(f"Cleaned up sandbox directory: {self.sandbox_dir}")
                self.sandbox_dir = None
            except Exception as e:
                self.log(f"WARNING: Could not clean up sandbox: {str(e)}")
    
    def fetch_all_malicious_lists(self):
        """
        Fetch malicious package lists from multiple community sources.
        Returns a combined dictionary of malicious packages with their metadata.
        """
        # Check if we should refresh cache (refresh every 24 hours)
        if self.malicious_packages_cache is not None and self.malicious_packages_last_fetch:
            time_diff = (datetime.now() - self.malicious_packages_last_fetch).total_seconds()
            if time_diff < 86400:  # 24 hours
                return self.malicious_packages_cache
        
        combined_list = {}
        
        for source_url in self.MALICIOUS_PACKAGE_SOURCES:
            try:
                self.log(f"    Fetching malicious packages from {source_url.split('/')[-1]}...")
                with urllib.request.urlopen(source_url, timeout=10) as response:
                    content = response.read().decode('utf-8')
                    
                    # Parse based on format
                    if source_url.endswith('.json'):
                        # JSON format (Guardrails AI, DataDog)
                        try:
                            data = json.loads(content)
                            
                            # Guardrails AI format: {"packages": [{"name": "...", "reason": "..."}, ...]}
                            if isinstance(data, dict) and 'packages' in data:
                                for pkg in data['packages']:
                                    pkg_name = pkg.get('name', '').lower().strip()
                                    if pkg_name:
                                        combined_list[pkg_name] = {
                                            'source': 'Guardrails AI',
                                            'reason': pkg.get('reason', 'Malicious package'),
                                            'severity': 'HIGH'
                                        }
                            
                            # DataDog format: {"package_vulnerabilities": [{"package": "...", ...}, ...]}
                            elif isinstance(data, dict) and 'package_vulnerabilities' in data:
                                for vuln in data['package_vulnerabilities']:
                                    pkg_name = vuln.get('package', '').lower().strip()
                                    if pkg_name:
                                        combined_list[pkg_name] = {
                                            'source': 'DataDog Security Research',
                                            'reason': vuln.get('description', 'Malicious package'),
                                            'severity': 'HIGH'
                                        }
                            
                            # Generic JSON array: [{"name": "...", ...}, ...]
                            elif isinstance(data, list):
                                for item in data:
                                    pkg_name = item.get('name', item.get('package', '')).lower().strip()
                                    if pkg_name:
                                        combined_list[pkg_name] = {
                                            'source': source_url.split('/')[-2],
                                            'reason': item.get('reason', item.get('description', 'Malicious package')),
                                            'severity': 'HIGH'
                                        }
                        except json.JSONDecodeError:
                            self.log(f"    Failed to parse JSON from {source_url}")
                    
                    elif source_url.endswith('.txt'):
                        # TXT format (S3cur3Th1sSh1t) - one package per line
                        for line in content.split('\n'):
                            pkg_name = line.strip().lower()
                            if pkg_name and not pkg_name.startswith('#'):
                                combined_list[pkg_name] = {
                                    'source': 'S3cur3Th1sSh1t',
                                    'reason': 'Listed in malicious packages database',
                                    'severity': 'HIGH'
                                }
                    
                    elif source_url.endswith('.md'):
                        # Markdown format (Awesome Supply Chain Attacks)
                        # Look for package names in code blocks or list items
                        import re
                        # Pattern: - `package_name` or ```package_name``` or | package_name |
                        patterns = [
                            r'`([a-zA-Z0-9_-]+)`',  # `package_name`
                            r'\|\s*([a-zA-Z0-9_-]+)\s*\|',  # | package_name |
                            r'-\s*([a-zA-Z0-9_-]+)',  # - package_name
                        ]
                        for pattern in patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                pkg_name = match.lower().strip()
                                if pkg_name and len(pkg_name) > 2:  # Filter out short matches
                                    combined_list[pkg_name] = {
                                        'source': 'Awesome Supply Chain Attacks',
                                        'reason': 'Listed in supply chain attacks database',
                                        'severity': 'HIGH'
                                    }
            
            except urllib.error.HTTPError as e:
                self.log(f"    Failed to fetch from {source_url}: HTTP {e.code}")
            except urllib.error.URLError as e:
                self.log(f"    Failed to fetch from {source_url}: {str(e)}")
            except Exception as e:
                self.log(f"    Failed to fetch from {source_url}: {str(e)}")
        
        # Cache the results
        self.malicious_packages_cache = combined_list
        self.malicious_packages_last_fetch = datetime.now()
        
        self.log(f"    Loaded {len(combined_list)} malicious packages from community sources")
        return combined_list
    
    def check_threat_intelligence(self, package_name):
        """
        Check package against real threat intelligence APIs.
        Returns threat intelligence data from multiple sources.
        REAL IMPLEMENTATION - No hardcoded lists!
        """
        # Check cache first
        if package_name in self.threat_intel_cache:
            return self.threat_intel_cache[package_name]
        
        threat_data = {
            'is_malicious': False,
            'sources': [],
            'severity': 'UNKNOWN',
            'reports': [],
            'last_updated': datetime.now().isoformat()
        }
        
        # 0. Check community malicious package lists (FIRST - fastest check)
        try:
            malicious_lists = self.fetch_all_malicious_lists()
            package_lower = package_name.lower().strip()
            
            if package_lower in malicious_lists:
                pkg_info = malicious_lists[package_lower]
                threat_data['is_malicious'] = True
                threat_data['severity'] = 'CRITICAL'
                threat_data['sources'].append(pkg_info['source'])
                threat_data['reports'].append({
                    'source': pkg_info['source'],
                    'type': 'Malicious Package List',
                    'summary': pkg_info['reason'],
                    'severity': pkg_info.get('severity', 'HIGH')
                })
                # Cache and return early if found in malicious lists
                self.threat_intel_cache[package_name] = threat_data
                return threat_data
        except Exception as e:
            self.log(f"    Community malicious lists check failed: {str(e)}")
        
        # 1. Check OSV (Open Source Vulnerabilities) - Real API call
        try:
            url = "https://api.osv.dev/v1/query"
            query = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                }
            }
            
            req = urllib.request.Request(url, data=json.dumps(query).encode(), 
                                       headers={'Content-Type': 'application/json'})
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if 'vulns' in data and data['vulns']:
                    for vuln in data['vulns']:
                        # Check for malicious/typosquatting indicators
                        aliases = vuln.get('aliases', [])
                        database_specific = vuln.get('database_specific', {})
                        summary = str(vuln.get('summary', '')).lower()
                        details = str(vuln.get('details', '')).lower()
                        
                        # Check for malicious indicators
                        malicious_indicators = [
                            'typosquat', 'typo-squat', 'malicious', 'malware',
                            'supply chain', 'backdoor', 'stealer', 'credential theft'
                        ]
                        
                        is_malicious_vuln = False
                        for indicator in malicious_indicators:
                            if (indicator in summary or indicator in details or 
                                any(indicator in str(alias).lower() for alias in aliases)):
                                is_malicious_vuln = True
                                break
                        
                        if is_malicious_vuln:
                            threat_data['is_malicious'] = True
                            threat_data['severity'] = 'CRITICAL'
                            threat_data['sources'].append('OSV')
                            threat_data['reports'].append({
                                'source': 'OSV',
                                'id': vuln.get('id', 'Unknown'),
                                'summary': vuln.get('summary', ''),
                                'type': 'Malicious Package',
                                'severity': vuln.get('database_specific', {}).get('severity', 'HIGH')
                            })
        except Exception as e:
            self.log(f"    OSV threat intelligence check failed: {str(e)}")
        
        # 2. Check PyPI JSON API for package status
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Check if package was yanked (removed for security reasons)
                releases = data.get('releases', {})
                yanked_releases = []
                for version, files in releases.items():
                    for file_info in files:
                        if file_info.get('yanked', False):
                            yanked_releases.append({
                                'version': version,
                                'reason': file_info.get('yanked_reason', 'Security issue')
                            })
                
                if yanked_releases:
                    # Yanked releases are suspicious but not necessarily malicious
                    # (could be bug fixes, not just security issues)
                    # Only mark as malicious if there are many yanked releases or explicit security reason
                    has_security_reason = any(
                        'security' in str(r.get('reason', '')).lower() or 
                        'malware' in str(r.get('reason', '')).lower() or
                        'backdoor' in str(r.get('reason', '')).lower()
                        for r in yanked_releases
                    )
                    
                    if has_security_reason or len(yanked_releases) >= 3:
                        threat_data['is_malicious'] = True
                        threat_data['severity'] = 'HIGH'
                    else:
                        threat_data['severity'] = 'MEDIUM'  # Suspicious but not confirmed malicious
                    
                    threat_data['sources'].append('PyPI')
                    threat_data['reports'].append({
                        'source': 'PyPI',
                        'type': 'Yanked Package',
                        'summary': f"Package has {len(yanked_releases)} yanked release(s) - possible security issue",
                        'severity': 'HIGH' if has_security_reason or len(yanked_releases) >= 3 else 'MEDIUM',
                        'yanked_releases': yanked_releases
                    })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Package not found - could be suspicious
                threat_data['reports'].append({
                    'source': 'PyPI',
                    'type': 'Package Not Found',
                    'summary': 'Package does not exist on PyPI - may be fake or removed',
                    'severity': 'MEDIUM'
                })
        except Exception as e:
            self.log(f"    PyPI threat intelligence check failed: {str(e)}")
        
        # 3. Check for known typosquatting patterns (algorithmic, not hardcoded)
        for popular in self.popular_packages:
            if self.is_typosquatting(package_name, popular):
                threat_data['is_malicious'] = True
                threat_data['severity'] = 'HIGH'
                threat_data['sources'].append('Typosquatting Detection')
                threat_data['reports'].append({
                    'source': 'Algorithmic Detection',
                    'type': 'Typosquatting',
                    'summary': f"Package name suspiciously similar to '{popular}' - possible typosquatting",
                    'severity': 'HIGH'
                })
                break
        
        # 4. Check GitHub Security Advisories (via OSV - already checked above)
        # OSV aggregates GitHub advisories, so we're covered
        
        # Cache the result
        self.threat_intel_cache[package_name] = threat_data
        
        return threat_data
    
    def analyze_package_security(self, package_name, is_installed, metadata=None):
        """Analyze package security status"""
        security_status = "SAFE"
        risk_level = "Low"
        warnings = []
        
        # 1. Real threat intelligence check (replaces hardcoded list)
        threat_intel = self.check_threat_intelligence(package_name)
        if threat_intel.get('is_malicious'):
            security_status = "MALICIOUS - Threat Intelligence Alert"
            risk_level = "Critical"
            for report in threat_intel.get('reports', []):
                warnings.append(f"{report.get('source', 'Unknown')}: {report.get('summary', 'Malicious package detected')}")
            return security_status, risk_level, warnings
        
        # 2. PyPI not found check (for non-installed packages)
        if not is_installed:
            # Don't check for standard libraries
            if package_name not in sys.stdlib_module_names:
                if metadata is None:
                    security_status = "SUSPICIOUS - Not Found on PyPI"
                    risk_level = "High"
                    warnings.append("Package not found on PyPI! (May be fake library)")
                    return security_status, risk_level, warnings
        
        # 4. Metadata analizi (yüklü olmayanlar için)
        if not is_installed and metadata:
            info = metadata.get('info', {}) or {}
            
            # Şüpheli kelime kontrolü
            summary = str(info.get('summary') or '')
            description_text = str(info.get('description') or '')
            description = (summary + ' ' + description_text).lower()
            suspicious_keywords = [
                'crypto-miner', 'miner', 'stealer', 'backdoor', 'malware',
                'trojan', 'virus', 'hack', 'exploit', 'keylogger', 'ransomware'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in description:
                    if security_status == "SAFE":
                        security_status = "SUSPICIOUS - Suspicious Content"
                        risk_level = "High"
                    warnings.append(f"Suspicious keyword detected: '{keyword}'")
            
            # Author information check
            author = str(info.get('author') or '').strip()
            author_email = str(info.get('author_email') or '').strip()
            if not author and not author_email:
                warnings.append("Author information missing")
            
            # Very new package check (newer than 1 month)
            # This could check release dates but keeping it simple for now
        
        # 5. Known security vulnerabilities check for installed packages
        # (This could use a security vulnerability database API)
        
        return security_status, risk_level, warnings
    
    def is_typosquatting(self, package_name, popular_package):
        """Check for typosquatting"""
        # Simple Levenshtein-like check
        if len(package_name) < 3 or len(popular_package) < 3:
            return False
        
        # Very similar names
        if abs(len(package_name) - len(popular_package)) <= 2:
            # Character similarity
            common_chars = sum(1 for a, b in zip(package_name.lower(), popular_package.lower()) if a == b)
            similarity = common_chars / max(len(package_name), len(popular_package))
            
            if similarity > 0.7 and package_name.lower() != popular_package.lower():
                return True
        
        return False
    
    def show_python_files(self, event=None):
        """Show found Python files in a window"""
        if not self.python_files:
            return
        
        # Create new window
        files_window = tk.Toplevel(self.root)
        files_window.title(f"Found Python Files ({len(self.python_files)} files)")
        files_window.geometry("700x500")
        
        # Frame
        frame = ttk.Frame(files_window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Label
        ttk.Label(frame, text=f"Total {len(self.python_files)} Python files found:", 
                 font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        # Listbox to show files
        listbox_frame = ttk.Frame(frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set, font=("Courier", 9))
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)
        
        # Add files (with relative paths)
        base_path = self.selected_path
        for file_path in sorted(self.python_files):
            try:
                relative_path = os.path.relpath(file_path, base_path)
                listbox.insert(tk.END, relative_path)
            except:
                listbox.insert(tk.END, file_path)
        
        # Close button
        ttk.Button(frame, text="Close", command=files_window.destroy).pack(pady=5)
    
    def analyze_project(self):
        """Analyze project and show results"""
        if not self.selected_path:
            self.status_label.config(text="Please select a project folder first!")
            self.log("ERROR: No project selected")
            return
        
        self.log("Starting project analysis...")
        self.status_label.config(text="Starting analysis...")
        self.update_progress(0, "Initializing scan...")
        self.root.update()
        
        # Clear existing results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            # Find Python files
            self.update_progress(10, "Scanning for Python files...")
            self.python_files = self.find_python_files(self.selected_path)
            file_count = len(self.python_files)
            
            if file_count == 0:
                self.log("WARNING: No Python files found in project")
                self.status_label.config(text="No Python files found!")
                self.update_progress(100, "No files found")
                return
            
            # Show file count (clickable)
            self.file_count_label.config(
                text=f"{file_count} Python files found (click to view)",
                foreground="#3498db"
            )
            
            self.update_progress(30, f"Found {file_count} Python files. Analyzing imports...")
            self.log(f"Analyzing imports from {file_count} files...")
            
            # Collect all imports
            all_imports = set()
            total_files = len(self.python_files)
            for idx, py_file in enumerate(self.python_files):
                imports = self.extract_imports(py_file)
                all_imports.update(imports)
                progress = 30 + int((idx + 1) / total_files * 30)
                self.update_progress(progress, f"Processing file {idx + 1}/{total_files}...")
            
            self.log(f"Found {len(all_imports)} unique packages")
            self.update_progress(60, f"Found {len(all_imports)} packages. Checking status...")
            
            # Check libraries and show results
            results = []
            self.library_data = {}
            total_libs = len(all_imports)
            for idx, lib in enumerate(sorted(all_imports)):
                is_installed, status, version_info = self.check_library_installed(lib)
                results.append((lib, status, is_installed, version_info))
                self.library_data[lib] = {
                    'is_installed': is_installed,
                    'status': status,
                    'version': version_info,
                    'metadata': None
                }
                progress = 60 + int((idx + 1) / total_libs * 30)
                self.update_progress(progress, f"Checking {lib}...")
            
            # Add results to treeview
            self.update_progress(90, "Building results table...")
            for lib, status, is_installed, version_info in results:
                version_str = version_info if version_info else "-"
                item = self.tree.insert("", tk.END, values=(lib, status, version_str, "Not Analyzed", "-", "-"))
                
                # Don't color by Status column - will be colored by Security Status after analysis
            
            self.update_progress(100, "Scan completed")
            self.log(f"Scan completed: {len(results)} packages found")
            self.status_label.config(text=f"Scan completed! {len(results)} packages found. Click 'Security Analysis' to analyze security.")
            
        except Exception as e:
            self.log(f"ERROR: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            self.update_progress(0, "Error occurred")
    
    def security_analysis(self):
        """
        Perform deep static analysis on all packages.
        Downloads, extracts, and analyzes package code.
        """
        if not self.library_data:
            self.status_label.config(text="Please run 'Scan' first to analyze the project!")
            self.log("ERROR: No library data available. Run scan first.")
            return
        
        self.log("=" * 60)
        self.log("Starting DEEP STATIC ANALYSIS...")
        self.log("=" * 60)
        self.status_label.config(text="Starting deep static analysis...")
        self.update_progress(0, "Initializing security scan...")
        self.root.update()
        
        # Initialize sandbox
        if not self.sandbox_dir:
            self.sandbox_dir = tempfile.mkdtemp(prefix='chainguard_sandbox_')
            self.log(f"Created sandbox directory: {self.sandbox_dir}")
        
        total = len(self.library_data)
        current = 0
        malicious_count = 0
        suspicious_count = 0
        analyzed_count = 0
        
        for lib_name, lib_info in self.library_data.items():
            current += 1
            progress = int((current / total) * 100)
            self.update_progress(progress, f"Analyzing {lib_name} ({current}/{total})...")
            
            # Initialize log collection for this package
            if lib_name not in self.package_logs:
                self.package_logs[lib_name] = []
            
            self.log(f"\n[{current}/{total}] Analyzing: {lib_name}", package_name=lib_name)
            self.status_label.config(
                text=f"Security analysis: {current}/{total} - Analyzing {lib_name}..."
            )
            self.root.update()
            
            is_installed = lib_info['is_installed']
            security_status = "SAFE"
            risk_level = "Low"
            findings = []
            ai_score = 0
            ai_explanation = ""
            
            # Skip standard libraries
            if lib_info['status'] == "Standard Library":
                self.log(f"  → Skipping standard library: {lib_name}", package_name=lib_name)
                security_status = "SAFE - Standard Library"
            else:
                # ============================================================
                # 🔴 STEP 1: LOCAL BLACKLIST (Offline, Fastest)
                # ============================================================
                self.log(f"  → [1/4] Checking local malicious package lists...")
                try:
                    malicious_lists = self.fetch_all_malicious_lists()
                    package_lower = lib_name.lower().strip()
                    
                    if package_lower in malicious_lists:
                        pkg_info = malicious_lists[package_lower]
                        security_status = f"MALICIOUS - {pkg_info['source']}"
                        risk_level = "Critical"
                        findings = [{
                            'type': 'Threat Intelligence',
                            'severity': 'CRITICAL',
                            'description': f"[{pkg_info['source']}] {pkg_info['reason']}"
                        }]
                        self.log(f"    🔴 MALICIOUS PACKAGE DETECTED in local blacklist!", package_name=lib_name)
                        self.log(f"    Source: {pkg_info['source']}", package_name=lib_name)
                        self.log(f"    Reason: {pkg_info['reason']}", package_name=lib_name)
                        # DURDUR - İndirme yapma!
                        # Store report and continue to next package
                        self.analysis_reports[lib_name] = {
                            'security_status': security_status,
                            'risk_level': risk_level,
                            'risk_score': 100,
                            'findings': findings,
                            'analysis_results': {
                                'threat_intelligence': {
                                    'is_malicious': True,
                                    'sources': [pkg_info['source']],
                                    'reports': [{
                                        'source': pkg_info['source'],
                                        'type': 'Malicious Package List',
                                        'summary': pkg_info['reason'],
                                        'severity': 'CRITICAL'
                                    }]
                                }
                            }
                        }
                    else:
                        # ============================================================
                        # 🟠 STEP 2: PYPI EXISTENCE (1 API call, Fast)
                        # ============================================================
                        self.log(f"  → [2/4] Checking PyPI existence...", package_name=lib_name)
                        metadata = self.get_pypi_metadata(lib_name)
                        
                        if not metadata:
                            # PyPI'da yok - local modül veya typo olabilir
                            self.log(f"  → Package '{lib_name}' not found on PyPI", package_name=lib_name)
                            
                            # Check if it's a local module
                            is_local_module = self._check_local_module(lib_name)
                            
                            if is_local_module:
                                # Local modül - SAFE
                                self.log(f"    ✅ Found as local module in project", package_name=lib_name)
                                security_status = "SAFE - Local Module"
                                risk_level = "Low"
                                risk_score = 0
                                findings = [{
                                    'type': 'Local Module',
                                    'severity': 'INFO',
                                    'description': f"Package '{lib_name}' is a local module in the project directory"
                                }]
                                self.analysis_reports[lib_name] = {
                                    'security_status': security_status,
                                    'risk_level': risk_level,
                                    'risk_score': risk_score,
                                    'findings': findings,
                                    'analysis_results': {
                                        'package_name': lib_name,
                                        'is_local_module': True
                                    }
                                }
                            else:
                                # PyPI'da yok ve local değil - UNKNOWN (typo olabilir)
                                self.log(f"    ⚠️  UNKNOWN: Not found on PyPI and not a local module", package_name=lib_name)
                                
                                # Check for possible typo
                                possible_typo = self._check_typo(lib_name)
                                typo_warning = ""
                                if possible_typo:
                                    typo_warning = f" Did you mean '{possible_typo}'?"
                                    self.log(f"    💡 Possible typo: Did you mean '{possible_typo}'?", package_name=lib_name)
                                
                                security_status = "UNKNOWN - Not Found on PyPI"
                                risk_level = "Unknown"
                                risk_score = 0  # UNKNOWN - Belki typo, belki local, belirsiz!
                                findings = [{
                                    'type': 'Package Not Found',
                                    'severity': 'MEDIUM',
                                    'description': f"Package '{lib_name}' does not exist on PyPI and is not a local module.{typo_warning}"
                                }]
                                
                                # UNKNOWN - malicious değil, sadece bilinmiyor
                                self.analysis_reports[lib_name] = {
                                    'security_status': security_status,
                                    'risk_level': risk_level,
                                    'risk_score': risk_score,
                                    'findings': findings,
                                    'analysis_results': {
                                        'package_name': lib_name,
                                        'is_local_module': False,
                                        'possible_typo': possible_typo
                                    }
                                }
                        else:
                            # ============================================================
                            # 🟡 STEP 3: THREAT INTELLIGENCE (2-3 API calls, Medium)
                            # ============================================================
                            self.log(f"  → [3/4] Checking threat intelligence APIs...", package_name=lib_name)
                            threat_intel = self.check_threat_intelligence(lib_name)
                            
                            if threat_intel.get('is_malicious'):
                                security_status = f"MALICIOUS - Threat Intelligence Alert"
                                risk_level = "Critical"
                                findings = []
                                for report in threat_intel.get('reports', []):
                                    findings.append({
                                        'type': 'Threat Intelligence',
                                        'severity': report.get('severity', 'CRITICAL'),
                                        'description': f"[{report.get('source', 'Unknown')}] {report.get('summary', 'Malicious package detected')}"
                                    })
                                self.log(f"    🔴 MALICIOUS PACKAGE DETECTED via Threat Intelligence!", package_name=lib_name)
                                for report in threat_intel.get('reports', []):
                                    self.log(f"    Source: {report.get('source', 'Unknown')}", package_name=lib_name)
                                    self.log(f"    Summary: {report.get('summary', '')}", package_name=lib_name)
                                # DURDUR - Malicious, indirme yapma!
                                self.analysis_reports[lib_name] = {
                                    'security_status': security_status,
                                    'risk_level': risk_level,
                                    'risk_score': 95,
                                    'findings': findings,
                                    'analysis_results': {
                                        'threat_intelligence': threat_intel
                                    }
                                }
                            else:
                                # ============================================================
                                # 🟢 STEP 4: FULL ANALYSIS (Download + Analyze, Slow)
                                # ============================================================
                                self.log(f"  → [4/4] Package is clean, proceeding with full analysis...", package_name=lib_name)
                                
                                # Download package file
                                self.log(f"  → Downloading package file...", package_name=lib_name)
                                download_result = self.download_package_file(lib_name, metadata)
                                
                                if not download_result:
                                    self.log(f"  → ERROR: Could not download {lib_name}", package_name=lib_name)
                                    security_status = "SUSPICIOUS - Download Failed"
                                    risk_level = "Medium"
                                else:
                                    package_path, file_extension = download_result
                                    
                                    # Extract package
                                    self.log(f"  → Extracting package...", package_name=lib_name)
                                    extract_dir = self.extract_package(package_path, file_extension)
                                    
                                    if not extract_dir:
                                        self.log(f"  → ERROR: Could not extract {lib_name}", package_name=lib_name)
                                        security_status = "SUSPICIOUS - Extraction Failed"
                                        risk_level = "Medium"
                                    else:
                                        # Perform ADVANCED static analysis
                                        self.log(f"  → Running ADVANCED security analysis...", package_name=lib_name)
                                        
                                        # Get package version from metadata
                                        package_version = metadata.get('info', {}).get('version') if metadata else None
                                        
                                        # Use AdvancedSecurityAnalyzer with package-specific logging
                                        def package_log(msg):
                                            self.log(msg, package_name=lib_name)
                                        advanced_analyzer = AdvancedSecurityAnalyzer(log_callback=package_log)
                                        analysis_results = advanced_analyzer.analyze_package(
                                            extract_dir, lib_name, package_version,
                                            threat_intel_checker=None  # Already checked above!
                                        )
                                        
                                        analyzed_count += 1
                                        
                                        # Extract results
                                        risk_score = analysis_results['risk_score']
                                        risk_level = analysis_results['risk_level']
                                        findings = analysis_results['findings']
                                        
                                        # Determine security status from risk score
                                        if risk_score >= 70:
                                            security_status = f"MALICIOUS - Risk Score: {risk_score}/100"
                                        elif risk_score >= 50:
                                            security_status = f"SUSPICIOUS - Risk Score: {risk_score}/100"
                                        elif risk_score >= 30:
                                            security_status = f"WARNING - Risk Score: {risk_score}/100"
                                        else:
                                            security_status = f"SAFE - Risk Score: {risk_score}/100"
                                        
                                        # Log findings
                                        if findings:
                                            self.log(f"  → Found {len(findings)} security issues (Risk Score: {risk_score}/100):", package_name=lib_name)
                                            for finding in findings[:5]:  # Show first 5 findings
                                                self.log(f"     - [{finding.get('severity', 'UNKNOWN')}] {finding.get('type', 'Unknown')}: {finding.get('description', '')}", package_name=lib_name)
                                            if len(findings) > 5:
                                                self.log(f"     ... and {len(findings) - 5} more issues", package_name=lib_name)
                                        else:
                                            self.log(f"  → No security issues found (Risk Score: {risk_score}/100)", package_name=lib_name)
                                        
                                        # Store detailed report
                                        self.analysis_reports[lib_name] = {
                                            'security_status': security_status,
                                            'risk_level': risk_level,
                                            'risk_score': risk_score,
                                            'findings': findings,
                                            'analysis_results': analysis_results,
                                            'package_path': extract_dir,
                                            'ai_score': 0,
                                            'ai_explanation': ''
                                        }
                                        
                                        # Run Gemini AI analysis on logs
                                        if self.gemini_analyzer.model:
                                            self.log(f"  → Running Gemini AI analysis...", package_name=lib_name)
                                            try:
                                                package_logs_text = '\n'.join(self.package_logs.get(lib_name, []))
                                                if not package_logs_text or len(package_logs_text.strip()) == 0:
                                                    self.log(f"  → Warning: No logs available for AI analysis", package_name=lib_name)
                                                    package_logs_text = f"Package: {lib_name}\nRisk Score: {risk_score}/100\nFindings: {len(findings)}"
                                                
                                                ai_result = self.gemini_analyzer.analyze_logs(
                                                    lib_name, 
                                                    package_logs_text, 
                                                    analysis_results
                                                )
                                                ai_score = ai_result.get('ai_score', 0)
                                                ai_explanation = ai_result.get('ai_explanation', '')
                                                
                                                # Update report with AI analysis
                                                self.analysis_reports[lib_name]['ai_score'] = ai_score
                                                self.analysis_reports[lib_name]['ai_explanation'] = ai_explanation
                                                self.analysis_reports[lib_name]['ai_concerns'] = ai_result.get('security_concerns', [])
                                                self.analysis_reports[lib_name]['ai_recommendations'] = ai_result.get('recommendations', [])
                                                
                                                self.log(f"  → ✅ AI Score: {ai_score}/100", package_name=lib_name)
                                            except Exception as e:
                                                self.log(f"  → ⚠️  Warning: Gemini AI analysis failed: {str(e)}", package_name=lib_name)
                                                self.analysis_reports[lib_name]['ai_score'] = 0
                                                self.analysis_reports[lib_name]['ai_explanation'] = f'AI analysis error: {str(e)}'
                                        else:
                                            self.log(f"  → ⚠️  Gemini AI not available (API key not set)", package_name=lib_name)
                                            self.analysis_reports[lib_name]['ai_score'] = 0
                                            self.analysis_reports[lib_name]['ai_explanation'] = 'Gemini AI not available. Please set GOOGLE_API_KEY or GEMINI_API_KEY environment variable, or add to config.json'
                except Exception as e:
                    self.log(f"  → ERROR in security analysis: {str(e)}", package_name=lib_name)
                    security_status = "ERROR - Analysis Failed"
                    risk_level = "Unknown"
            
            # Count threats (avoid double counting - malicious_count already incremented for PyPI not found)
            if "MALICIOUS" in security_status:
                # Only increment if not already counted (PyPI not found case already counted)
                if lib_name not in self.analysis_reports or self.analysis_reports[lib_name].get('risk_score', 0) != 100:
                    malicious_count += 1
                self.log(f"  → ⚠️  THREAT DETECTED: {lib_name}", package_name=lib_name)
            elif "SUSPICIOUS" in security_status:
                suspicious_count += 1
                self.log(f"  → ⚠️  SUSPICIOUS: {lib_name}", package_name=lib_name)
            
            # Run Gemini AI analysis if we have logs and analysis results
            if lib_name in self.analysis_reports and lib_name in self.package_logs:
                if not self.analysis_reports[lib_name].get('ai_score') and self.gemini_analyzer.model:
                    # Only run if not already analyzed and model is available
                    try:
                        self.log(f"  → Running Gemini AI analysis for {lib_name}...", package_name=lib_name)
                        package_logs_text = '\n'.join(self.package_logs.get(lib_name, []))
                        if not package_logs_text or len(package_logs_text.strip()) == 0:
                            self.log(f"  → Warning: No logs available for AI analysis", package_name=lib_name)
                            report = self.analysis_reports[lib_name]
                            package_logs_text = f"Package: {lib_name}\nRisk Score: {report.get('risk_score', 0)}/100\nFindings: {len(report.get('findings', []))}"
                        
                        analysis_results = self.analysis_reports[lib_name].get('analysis_results', {})
                        ai_result = self.gemini_analyzer.analyze_logs(
                            lib_name, 
                            package_logs_text, 
                            analysis_results
                        )
                        ai_score = ai_result.get('ai_score', 0)
                        ai_explanation = ai_result.get('ai_explanation', '')
                        
                        # Update report with AI analysis
                        self.analysis_reports[lib_name]['ai_score'] = ai_score
                        self.analysis_reports[lib_name]['ai_explanation'] = ai_explanation
                        self.analysis_reports[lib_name]['ai_concerns'] = ai_result.get('security_concerns', [])
                        self.analysis_reports[lib_name]['ai_recommendations'] = ai_result.get('recommendations', [])
                        
                        self.log(f"  → ✅ AI Score: {ai_score}/100", package_name=lib_name)
                    except Exception as e:
                        self.log(f"  → ⚠️  Warning: Gemini AI analysis failed: {str(e)}", package_name=lib_name)
                        self.analysis_reports[lib_name]['ai_score'] = 0
                        self.analysis_reports[lib_name]['ai_explanation'] = f'AI analysis error: {str(e)}'
            
            # Update treeview - color rows by Security Status and Risk Score
            for item in self.tree.get_children():
                if self.tree.item(item, 'values')[0] == lib_name:
                    current_values = list(self.tree.item(item, 'values'))
                    # Ensure we have 6 columns (Package, Status, Version, Security, Risk Score, AI Score)
                    while len(current_values) < 6:
                        current_values.append("-")
                    
                    current_values[3] = security_status
                    
                    # Add risk score
                    if lib_name in self.analysis_reports:
                        risk_score = self.analysis_reports[lib_name].get('risk_score', 0)
                        current_values[4] = f"{risk_score}/100"
                        
                        # Add AI score
                        ai_score = self.analysis_reports[lib_name].get('ai_score', 0)
                        current_values[5] = f"{ai_score}/100" if ai_score > 0 else "-"
                    else:
                        current_values[4] = "-"
                        current_values[5] = "-"
                    
                    self.tree.item(item, values=tuple(current_values))
                    
                    # Color code entire row by risk score
                    if lib_name in self.analysis_reports:
                        risk_score = self.analysis_reports[lib_name].get('risk_score', 0)
                        if risk_score >= 70:
                            self.tree.item(item, tags=("malicious",))
                        elif risk_score >= 50:
                            self.tree.item(item, tags=("suspicious",))
                        elif risk_score >= 30:
                            self.tree.item(item, tags=("warning",))
                        else:
                            self.tree.item(item, tags=("safe",))
                    else:
                        # Fallback to old logic
                        if "MALICIOUS" in security_status:
                            self.tree.item(item, tags=("malicious",))
                        elif "SUSPICIOUS" in security_status:
                            self.tree.item(item, tags=("suspicious",))
                        else:
                            self.tree.item(item, tags=("safe",))
                    
                    # Update UI to show color change immediately
                    self.root.update()
                    break
        
        # Cleanup sandbox
        self.log("\n" + "=" * 60)
        self.log("Cleaning up sandbox...")
        self.cleanup_sandbox()
        
        # Final summary
        self.update_progress(100, "Security analysis completed")
        self.log("=" * 60)
        self.log(f"ANALYSIS COMPLETE!")
        self.log(f"  Total packages: {total}")
        self.log(f"  Analyzed: {analyzed_count}")
        self.log(f"  Malicious: {malicious_count}")
        self.log(f"  Suspicious: {suspicious_count}")
        self.log("=" * 60)
        
        self.status_label.config(
            text=f"Security analysis completed! {total} packages analyzed. "
                 f"Found: {malicious_count} malicious, {suspicious_count} suspicious. "
                 f"Double-click package for detailed report."
        )
        
        # Make treeview items clickable for detailed reports
        self.tree.bind("<Double-1>", self.show_detailed_report)
        # Make treeview items expandable on single click
        self.tree.bind("<Button-1>", self.on_tree_click)
    
    def on_tree_click(self, event):
        """Handle single click on treeview items to expand/collapse details."""
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            item = self.tree.identify_row(event.y)
            if item:
                # Toggle expand/collapse
                if self.tree.get_children(item):
                    # Has children, toggle
                    if self.tree.item(item, 'open'):
                        self.tree.item(item, open=False)
                    else:
                        self.tree.item(item, open=True)
                else:
                    # No children, add detail items if report exists
                    package_name = self.tree.item(item, 'values')[0]
                    if package_name in self.analysis_reports:
                        report = self.analysis_reports[package_name]
                        
                        # Add detail items
                        details = [
                            f"Risk Score: {report.get('risk_score', 0)}/100",
                            f"AI Score: {report.get('ai_score', 0)}/100" if report.get('ai_score', 0) > 0 else "AI Score: Not analyzed",
                            f"Findings: {len(report.get('findings', []))}",
                        ]
                        
                        if report.get('ai_explanation'):
                            details.append("AI Explanation available (double-click for details)")
                        
                        for detail in details:
                            self.tree.insert(item, tk.END, text="  " + detail, values=("", "", "", "", "", ""))
                        
                        self.tree.item(item, open=True)
    
    def show_detailed_report(self, event=None):
        """Show detailed security analysis report for selected package."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        package_name = item['values'][0]
        
        # Get report if available
        if package_name not in self.analysis_reports:
            # Show basic info
            report_window = tk.Toplevel(self.root)
            report_window.title(f"Security Report: {package_name}")
            report_window.geometry("800x600")
            
            frame = ttk.Frame(report_window, padding="10")
            frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(frame, text=f"Package: {package_name}", 
                     font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=5)
            
            ttk.Label(frame, text="No detailed analysis available. Run Security Analysis first.", 
                     foreground="gray").pack(anchor=tk.W, pady=10)
            
            ttk.Button(frame, text="Close", command=report_window.destroy).pack(pady=10)
            return
        
        report = self.analysis_reports[package_name]
        
        # Create report window
        report_window = tk.Toplevel(self.root)
        report_window.title(f"Security Report: {package_name}")
        report_window.geometry("900x700")
        
        # Main frame
        main_frame = ttk.Frame(report_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text=f"Package: {package_name}", 
                 font=("Arial", 16, "bold")).pack(anchor=tk.W)
        
        # Risk Score (prominent display)
        risk_score = report.get('risk_score', 0)
        risk_level = report.get('risk_level', 'Unknown')
        
        score_frame = ttk.Frame(main_frame)
        score_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(score_frame, text="RISK SCORE:", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        # Color code risk score
        if risk_score >= 70:
            score_color = "#dc3545"
        elif risk_score >= 50:
            score_color = "#ff9800"
        elif risk_score >= 30:
            score_color = "#ffc107"
        else:
            score_color = "#28a745"
        
        score_label = ttk.Label(score_frame, text=f"{risk_score}/100", 
                               foreground=score_color, font=("Arial", 16, "bold"))
        score_label.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(score_frame, text=f"({risk_level} Risk)", 
                 font=("Arial", 10)).pack(side=tk.LEFT)
        
        # Stage Scores Breakdown (4 aşama)
        stage_scores = report.get('analysis_results', {}).get('stage_scores', {})
        if stage_scores:
            stages_frame = ttk.LabelFrame(main_frame, text="Risk Score Detayı (4 Aşama)", padding="10")
            stages_frame.pack(fill=tk.X, pady=10)
            
            # Stage 1: Threat Intelligence
            stage1_frame = ttk.Frame(stages_frame)
            stage1_frame.pack(fill=tk.X, pady=2)
            ttk.Label(stage1_frame, text="1. Threat Intelligence (Tehdit İstihbaratı):", 
                     font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
            stage1_score = stage_scores.get('threat_intelligence', 0)
            stage1_color = "#dc3545" if stage1_score >= 20 else "#ff9800" if stage1_score >= 10 else "#28a745"
            ttk.Label(stage1_frame, text=f"{stage1_score}/25", 
                     foreground=stage1_color, font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            
            # Stage 2: Static Analysis
            stage2_frame = ttk.Frame(stages_frame)
            stage2_frame.pack(fill=tk.X, pady=2)
            ttk.Label(stage2_frame, text="2. Static Analysis (Statik Analiz - CVE/OSV):", 
                     font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
            stage2_score = stage_scores.get('static_analysis', 0)
            stage2_color = "#dc3545" if stage2_score >= 35 else "#ff9800" if stage2_score >= 20 else "#ffc107" if stage2_score >= 10 else "#28a745"
            ttk.Label(stage2_frame, text=f"{stage2_score}/50", 
                     foreground=stage2_color, font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            
            # Stage 3: Setup Behavior
            stage3_frame = ttk.Frame(stages_frame)
            stage3_frame.pack(fill=tk.X, pady=2)
            ttk.Label(stage3_frame, text="3. Setup Behavior (Kurulum Davranışı):", 
                     font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
            stage3_score = stage_scores.get('setup_behavior', 0)
            stage3_color = "#dc3545" if stage3_score >= 7 else "#ff9800" if stage3_score >= 4 else "#28a745"
            ttk.Label(stage3_frame, text=f"{stage3_score}/10", 
                     foreground=stage3_color, font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            
            # Stage 4: Dynamic Analysis
            stage4_frame = ttk.Frame(stages_frame)
            stage4_frame.pack(fill=tk.X, pady=2)
            ttk.Label(stage4_frame, text="4. Dynamic Analysis (Dinamik Analiz):", 
                     font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
            stage4_score = stage_scores.get('dynamic_analysis', 0)
            stage4_color = "#dc3545" if stage4_score >= 15 else "#ff9800" if stage4_score >= 8 else "#ffc107" if stage4_score >= 4 else "#28a745"
            ttk.Label(stage4_frame, text=f"{stage4_score}/20", 
                     foreground=stage4_color, font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            
            # Total Score
            total_frame = ttk.Frame(stages_frame)
            total_frame.pack(fill=tk.X, pady=(5, 0))
            ttk.Label(total_frame, text="TOPLAM:", 
                     font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
            ttk.Label(total_frame, text=f"{risk_score}/100", 
                     foreground=score_color, font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        
        # AI Score (prominent display)
        ai_score = report.get('ai_score', 0)
        if ai_score > 0:
            ai_score_frame = ttk.Frame(main_frame)
            ai_score_frame.pack(fill=tk.X, pady=10)
            
            ttk.Label(ai_score_frame, text="AI SCORE (Gemini):", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=(0, 10))
            
            # Color code AI score
            if ai_score >= 70:
                ai_score_color = "#dc3545"
            elif ai_score >= 50:
                ai_score_color = "#ff9800"
            elif ai_score >= 30:
                ai_score_color = "#ffc107"
            else:
                ai_score_color = "#28a745"
            
            ai_score_label = ttk.Label(ai_score_frame, text=f"{ai_score}/100", 
                                     foreground=ai_score_color, font=("Arial", 16, "bold"))
            ai_score_label.pack(side=tk.LEFT, padx=(0, 10))
            
            # AI Explanation
            ai_explanation = report.get('ai_explanation', '')
            if ai_explanation:
                explanation_frame = ttk.LabelFrame(main_frame, text="AI Explanation (Why This Score Was Given)", padding="10")
                explanation_frame.pack(fill=tk.BOTH, expand=True, pady=10)
                
                explanation_text = scrolledtext.ScrolledText(explanation_frame, height=12, 
                                                           font=("Arial", 10), wrap=tk.WORD)
                explanation_text.insert(tk.END, ai_explanation)
                explanation_text.config(state=tk.DISABLED)
                explanation_text.pack(fill=tk.BOTH, expand=True)
        
        # Security status
        status_color = "#dc3545" if "MALICIOUS" in report['security_status'] else \
                      "#ff9800" if "SUSPICIOUS" in report['security_status'] else "#28a745"
        
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(status_frame, text="Security Status:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        status_label = ttk.Label(status_frame, text=report['security_status'], 
                                foreground=status_color, font=("Arial", 10, "bold"))
        status_label.pack(side=tk.LEFT)
        
        # Findings count
        findings_count = len(report.get('findings', []))
        ttk.Label(main_frame, text=f"Total Findings: {findings_count}", 
                 font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        # Findings list
        if findings_count > 0:
            # Create scrollable text widget
            text_frame = ttk.Frame(main_frame)
            text_frame.pack(fill=tk.BOTH, expand=True, pady=10)
            
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            report_text = scrolledtext.ScrolledText(text_frame, 
                                                   font=("Consolas", 9),
                                                   bg='#1e1e1e', fg='#d4d4d4',
                                                   yscrollcommand=scrollbar.set)
            report_text.pack(fill=tk.BOTH, expand=True)
            scrollbar.config(command=report_text.yview)
            
            # Group findings by type
            findings_by_type = defaultdict(list)
            for finding in report['findings']:
                findings_by_type[finding['type']].append(finding)
            
            # Write comprehensive report
            report_text.insert(tk.END, "=" * 80 + "\n")
            report_text.insert(tk.END, f"ADVANCED SECURITY ANALYSIS REPORT\n")
            report_text.insert(tk.END, f"Package: {package_name}\n")
            report_text.insert(tk.END, f"Risk Score: {risk_score}/100 ({risk_level})\n")
            report_text.insert(tk.END, "=" * 80 + "\n\n")
            
            # Show analysis results summary
            if 'analysis_results' in report:
                results = report['analysis_results']
                
                report_text.insert(tk.END, "ANALYSIS SUMMARY\n")
                report_text.insert(tk.END, "-" * 80 + "\n")
                
                # Threat Intelligence
                threat_intel = results.get('threat_intelligence', {})
                if threat_intel.get('is_malicious'):
                    report_text.insert(tk.END, f"⚠️  THREAT INTELLIGENCE: MALICIOUS PACKAGE DETECTED\n")
                    report_text.insert(tk.END, f"  Sources: {', '.join(threat_intel.get('sources', []))}\n")
                    for report in threat_intel.get('reports', [])[:3]:
                        report_text.insert(tk.END, f"  - {report.get('source')}: {report.get('summary', '')}\n")
                elif threat_intel.get('reports'):
                    report_text.insert(tk.END, f"Threat Intelligence: {len(threat_intel['reports'])} report(s)\n")
                
                # Data-flow analysis
                if results.get('data_flow', {}).get('dangerous_sinks'):
                    high_risk = sum(1 for s in results['data_flow']['dangerous_sinks'] if s.get('has_tainted_input'))
                    report_text.insert(tk.END, f"Data-Flow Analysis: {high_risk} high-risk sinks detected\n")
                
                # Vulnerabilities
                if results.get('vulnerabilities'):
                    report_text.insert(tk.END, f"Known Vulnerabilities: {len(results['vulnerabilities'])} CVE/OSV entries\n")
                
                # Domains/IPs
                if results.get('suspicious_domains') or results.get('suspicious_ips'):
                    report_text.insert(tk.END, f"Suspicious Domains: {len(results.get('suspicious_domains', []))}\n")
                    report_text.insert(tk.END, f"Suspicious IPs: {len(results.get('suspicious_ips', []))}\n")
                
                # Credentials
                if results.get('credentials_found'):
                    report_text.insert(tk.END, f"Credentials/Tokens Found: {len(results['credentials_found'])}\n")
                
                # Obfuscation
                if results.get('obfuscation_detected'):
                    report_text.insert(tk.END, f"Obfuscation Techniques: {len(results['obfuscation_detected'])}\n")
                
                # Setup behavior
                setup_behavior = results.get('setup_behavior', {})
                if setup_behavior.get('has_post_install') or setup_behavior.get('network_during_setup'):
                    report_text.insert(tk.END, f"Setup Behavior: Suspicious patterns detected\n")
                
                # Dynamic analysis
                dynamic = results.get('dynamic_analysis', {})
                if dynamic:
                    report_text.insert(tk.END, f"\nDynamic Analysis (Sandbox Execution):\n")
                    if dynamic.get('timeout'):
                        report_text.insert(tk.END, f"  ⚠️  TIMEOUT: Execution timed out\n")
                    if dynamic.get('network_connections'):
                        report_text.insert(tk.END, f"  Network Connections: {len(dynamic['network_connections'])} detected\n")
                    if dynamic.get('file_operations'):
                        report_text.insert(tk.END, f"  File Operations: {len(dynamic['file_operations'])} detected\n")
                    if dynamic.get('process_spawns'):
                        report_text.insert(tk.END, f"  Process Spawns: {len(dynamic['process_spawns'])} detected\n")
                    if dynamic.get('cpu_usage', 0) > 0:
                        report_text.insert(tk.END, f"  CPU Usage: {dynamic['cpu_usage']:.1f}%\n")
                    if dynamic.get('memory_usage', 0) > 0:
                        report_text.insert(tk.END, f"  Memory Usage: {dynamic['memory_usage']:.1f}MB\n")
                    if dynamic.get('execution_time', 0) > 0:
                        report_text.insert(tk.END, f"  Execution Time: {dynamic['execution_time']:.2f}s\n")
                
                report_text.insert(tk.END, "\n")
            
            # Detailed findings
            report_text.insert(tk.END, "DETAILED FINDINGS\n")
            report_text.insert(tk.END, "-" * 80 + "\n\n")
            
            for finding_type, type_findings in findings_by_type.items():
                report_text.insert(tk.END, f"\n[{finding_type}] - {len(type_findings)} finding(s)\n")
                report_text.insert(tk.END, "-" * 80 + "\n")
                
                for finding in type_findings:
                    severity = finding.get('severity', 'UNKNOWN')
                    
                    report_text.insert(tk.END, f"  Severity: {severity}\n", "severity")
                    if 'file' in finding:
                        report_text.insert(tk.END, f"  File: {finding['file']}\n")
                    if 'line' in finding and finding['line'] > 0:
                        report_text.insert(tk.END, f"  Line: {finding['line']}\n")
                    report_text.insert(tk.END, f"  Description: {finding.get('description', 'N/A')}\n")
                    if 'pattern' in finding:
                        report_text.insert(tk.END, f"  Pattern: {finding['pattern']}\n")
                    report_text.insert(tk.END, "\n")
                
                report_text.insert(tk.END, "\n")
            
            # Configure text tags for colors
            report_text.tag_config("severity", foreground="#ff9800")
            report_text.config(state=tk.DISABLED)  # Make read-only
        else:
            ttk.Label(main_frame, text="✓ No security issues found", 
                     foreground="#28a745", font=("Arial", 12)).pack(pady=20)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="Close", command=report_window.destroy).pack()


def main():
    root = tk.Tk()
    app = ChainGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

