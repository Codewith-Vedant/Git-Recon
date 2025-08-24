#!/usr/bin/env python3
import argparse
import concurrent.futures
import logging
import os
import re
import requests
import time
import json
import threading
from pathlib import Path
from urllib.parse import quote_plus
from typing import List, Dict, Set
from datetime import datetime

# Add colorama for cross-platform colored output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    print("⚠️  Install colorama for colored output: pip install colorama")
    COLORS_ENABLED = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BLACK = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

# =========== CONFIGURATION ===========
MAX_THREADS = 8
PER_PAGE = 30
MAX_PAGES = 5

# Enhanced patterns with better specificity
SECRETS_PATTERNS = [
    # AWS Keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key"),
    (re.compile(r'(?i)aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]'), "AWS Secret Access Key"),
    # Google API Keys
    (re.compile(r'AIza[0-9A-Za-z-_]{35}'), "Google API Key"),
    # GitHub Tokens
    (re.compile(r'ghp_[0-9A-Za-z]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'ghs_[0-9A-Za-z]{36}'), "GitHub App Token"),
    (re.compile(r'ghr_[0-9A-Za-z]{36}'), "GitHub Refresh Token"),
    # Stripe Keys
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "Stripe Secret Key"),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "Stripe Publishable Key"),
    (re.compile(r'rk_live_[0-9a-zA-Z]{24,}'), "Stripe Restricted Key"),
    # Slack Tokens
    (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}'), "Slack Token"),
    # Twilio
    (re.compile(r'SK[0-9a-fA-F]{32}'), "Twilio API Key"),
    (re.compile(r'AC[0-9a-fA-F]{32}'), "Twilio Account SID"),
    # Generic API patterns
    (re.compile(r'(?i)(?:api[_-]?key|apikey)[\s]*[=:\'\"]\s*[\'\"]*([A-Za-z0-9_\-]{20,})[\'\"]*'), "Generic API Key"),
    (re.compile(r'(?i)(?:secret[_-]?key|secret)[\s]*[=:\'\"]\s*[\'\"]*([A-Za-z0-9_\-/+]{20,})[\'\"]*'), "Generic Secret"),
    (re.compile(r'(?i)(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)[\s]*[=:\'\"]\s*[\'\"]*([A-Za-z0-9_\-/+]{20,})[\'\"]*'), "Generic Token"),
    (re.compile(r'(?i)password[\s]*[=:\'\"]\s*[\'\"]*([A-Za-z0-9!@#$%^&*()_\-+={}[\]|\\:;\"\'<>?,.]{8,})[\'\"]*'), "Password"),
    # Database URLs
    (re.compile(r'(?i)mongodb://[^\s]+'), "MongoDB Connection String"),
    (re.compile(r'(?i)mysql://[^\s]+'), "MySQL Connection String"),
    (re.compile(r'(?i)postgres://[^\s]+'), "PostgreSQL Connection String"),
    # JWT Tokens
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), "JWT Token"),
    # Private Keys
    (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----'), "Private Key"),
    (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "OpenSSH Private Key"),
]

# File extensions to ignore
IGNORE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.pdf', '.doc', '.docx', 
    '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.tar', '.gz', '.rar', '.7z', '.mp3', 
    '.mp4', '.avi', '.mov', '.wmv', '.exe', '.dll', '.so', '.dylib', '.woff', 
    '.woff2', '.ttf', '.eot', '.min.js', '.min.css'
}

# File paths to ignore
IGNORE_PATHS = {
    'node_modules', 'vendor', 'build', 'dist', 'target', '.git', 'documentation', 
    'docs', 'examples', 'test', 'tests', 'spec', '.vscode', '.idea', '__pycache__', 
    '.pytest_cache'
}

# Common false positive patterns
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'^[a-f0-9]{32}$'),
    re.compile(r'^[a-f0-9]{40}$'),
    re.compile(r'^[a-f0-9]{64}$'),
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    re.compile(r'interface_.*_html'),
    re.compile(r'class_.*_members'),
    re.compile(r'[A-Z][a-z]+[A-Z][a-z]+'),
    re.compile(r'^[A-Za-z]+[0-9]+$'),
    re.compile(r'UIInterface'),
    re.compile(r'NSString'),
    re.compile(r'kSec[A-Za-z]+'),
]

# Words that indicate legitimate content
LEGITIMATE_KEYWORDS = {
    'interface', 'function', 'class', 'method', 'property', 'constant', 'string', 
    'array', 'object', 'boolean', 'number', 'undefined', 'prototype', 'constructor', 
    'instanceof', 'typeof', 'orientation', 'portrait', 'landscape', 'upside', 'down', 
    'accessible', 'when', 'unlocked', 'device', 'only', 'this', 'after', 'first', 
    'unlock', 'always'
}

# Global stats
stats = {
    'total_files_scanned': 0,
    'total_findings': 0,
    'high_confidence': 0,
    'medium_confidence': 0,
    'low_confidence': 0,
    'start_time': None
}

def sanitize_filename(filename: str) -> str:
    """Sanitize organization name for use in filename"""
    # Remove or replace characters that are not allowed in filenames
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove extra spaces and replace with underscores
    sanitized = re.sub(r'\s+', '_', sanitized.strip())
    # Remove leading/trailing dots and dashes
    sanitized = sanitized.strip('.-')
    return sanitized

def print_banner():
    """Print a nice banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════╗
║                          GitRecon v1.0                      ║
║               GitHub Repository Secret Scanner               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}🔍 Scanning for exposed secrets and sensitive information...{Style.RESET_ALL}
"""
    print(banner)

def print_colored(text: str, color: str = Fore.WHITE, style: str = Style.NORMAL, prefix: str = ""):
    """Print colored text with optional prefix"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{Style.DIM}[{timestamp}]{Style.RESET_ALL} {prefix}{color}{style}{text}{Style.RESET_ALL}")

def print_success(text: str):
    """Print success message"""
    print_colored(text, Fore.GREEN, Style.BRIGHT, "✅ ")

def print_info(text: str):
    """Print info message"""
    print_colored(text, Fore.BLUE, Style.NORMAL, "ℹ️  ")

def print_warning(text: str):
    """Print warning message"""
    print_colored(text, Fore.YELLOW, Style.BRIGHT, "⚠️  ")

def print_error(text: str):
    """Print error message"""
    print_colored(text, Fore.RED, Style.BRIGHT, "❌ ")

def print_finding(finding_type: str, confidence: str, source: str, line_num: int):
    """Print a finding with appropriate colors"""
    if confidence == "HIGH":
        color = Fore.RED
        icon = "🚨"
    elif confidence == "MEDIUM":
        color = Fore.YELLOW
        icon = "⚠️ "
    else:
        color = Fore.CYAN
        icon = "🔍"
    
    filename = source.split('/')[-1]
    print_colored(f"{icon} {finding_type} in {filename}#{line_num} ({confidence} confidence)", color, Style.BRIGHT)

def print_stats():
    """Print current statistics"""
    elapsed = time.time() - stats['start_time']
    print(f"""
{Fore.CYAN}{Style.BRIGHT}╔═══════════════ SCAN STATISTICS ═══════════════╗{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL} Files Scanned:     {stats['total_files_scanned']:>6} files       {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL} Total Findings:    {stats['total_findings']:>6} secrets     {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL} High Confidence:   {Fore.RED}{stats['high_confidence']:>6}{Style.RESET_ALL} findings    {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL} Medium Confidence: {Fore.YELLOW}{stats['medium_confidence']:>6}{Style.RESET_ALL} findings    {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL} Low Confidence:    {Fore.CYAN}{stats['low_confidence']:>6}{Style.RESET_ALL} findings    {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL} Scan Duration:     {elapsed:>6.1f} seconds     {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def setup_logging():
    """Setup logging - console output only"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[logging.StreamHandler()]
    )

def get_github_tokens() -> List[str]:
    """Get GitHub tokens from environment or file"""
    tokens = []
    if env := os.environ.get("GITHUB_TOKEN"):
        tokens += env.split(",")
    if Path("github_tokens.txt").is_file():
        tokens += [t.strip() for t in open("github_tokens.txt") if t.strip()]
    
    if not tokens:
        print_error("Missing GitHub tokens. Set GITHUB_TOKEN env var or create github_tokens.txt")
        print_info("Example: export GITHUB_TOKEN=ghp_your_token_here")
        exit(1)
    
    print_success(f"Loaded {len(tokens)} GitHub token(s)")
    return list(dict.fromkeys(tokens))

def load_dorks(dork_file: str) -> List[str]:
    """Load dorks from file"""
    dork_path = Path(dork_file)
    
    if not dork_path.exists():
        print_error(f"Dork file not found: {dork_file}")
        exit(1)
    
    try:
        dorks = []
        with open(dork_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    dorks.append(line)
        
        if not dorks:
            print_error(f"No dorks found in file: {dork_file}")
            exit(1)
        
        print_success(f"Loaded {len(dorks)} dork(s) from {dork_file}")
        return dorks
    
    except Exception as e:
        print_error(f"Error reading dork file {dork_file}: {str(e)}")
        exit(1)

def github_search(query: str, token: str) -> List[dict]:
    """Search GitHub API with improved error handling and rate limiting"""
    headers = {"Authorization": f"token {token}"}
    results = []
    
    for page in range(1, MAX_PAGES + 1):
        url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page={PER_PAGE}&page={page}"
        
        try:
            r = requests.get(url, headers=headers, timeout=15)
            
            # Check if response is HTML (rate limit error page)
            content_type = r.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                if r.status_code == 429:
                    print_error("Rate limit exceeded - GitHub returned HTML error page")
                    print_warning("Consider using multiple tokens or reducing thread count")
                else:
                    print_error(f"GitHub returned HTML error page (Status: {r.status_code})")
                    print_warning("This usually indicates rate limiting or access issues")
                break
            
            if r.status_code == 200:
                try:
                    response_data = r.json()
                    items = response_data.get("items", [])
                    if not items:
                        break
                    results.extend(items)
                    print_info(f"Page {page}: Found {len(items)} files")
                    if len(items) < PER_PAGE:
                        break
                    time.sleep(1)  # Basic rate limiting
                except json.JSONDecodeError:
                    print_error("Invalid JSON response from GitHub API")
                    break
                    
            elif r.status_code == 403:
                if "X-RateLimit-Reset" in r.headers:
                    reset = int(r.headers["X-RateLimit-Reset"]) - int(time.time()) + 5
                    print_warning(f"Rate limited. Waiting {reset} seconds...")
                    time.sleep(max(reset, 5))
                else:
                    print_error("Access forbidden - check your token permissions")
                    break
                    
            elif r.status_code == 422:
                print_warning(f"Query too complex or invalid: {query}")
                break
                
            else:
                print_error(f"GitHub API error {r.status_code}")
                break
                
        except requests.RequestException as e:
            print_error(f"Request failed: {str(e)}")
            break
        except Exception as e:
            print_error(f"Unexpected error: {str(e)}")
            break
    
    return results

def entropy(s: str) -> float:
    """Calculate Shannon entropy of a string"""
    import math
    if not s:
        return 0.0
    p = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(pi*math.log(pi, 2) for pi in p)

def should_ignore_file(source: str) -> bool:
    """Check if file should be ignored"""
    source_lower = source.lower()
    
    for ext in IGNORE_EXTENSIONS:
        if source_lower.endswith(ext):
            return True
    
    path_parts = source_lower.split('/')
    for part in path_parts:
        if part in IGNORE_PATHS:
            return True
    
    return False

def is_false_positive(match: str, context: str = "", source: str = "") -> bool:
    """Enhanced false positive detection"""
    match_lower = match.lower()
    
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.match(match):
            return True
    
    for keyword in LEGITIMATE_KEYWORDS:
        if keyword in match_lower:
            return True
    
    context_lower = context.lower()
    if any(indicator in context_lower for indicator in [
        'function', 'class', 'interface', 'const', 'var', 'let', 'property', 
        'method', 'prototype', 'constructor', 'html', 'css', 'javascript', 
        'documentation', 'example'
    ]):
        return True
    
    if any(path_part in source.lower() for path_part in [
        'documentation', 'docs', 'test', 'spec', 'example', 'demo', '.html', 
        'readme', 'changelog'
    ]):
        return True
    
    if entropy(match) < 3.0:
        return True
    
    return False

def extract_variable_context(line: str, match_start: int, match_end: int) -> dict:
    """Extract variable name and context around a match"""
    before_match = line[:match_start].strip()
    after_match = line[match_end:].strip()
    
    context = {
        'variable_name': None,
        'assignment_type': None,
        'is_assignment': False,
        'context_before': before_match[-50:] if len(before_match) > 50 else before_match,
        'context_after': after_match[:50] if len(after_match) > 50 else after_match
    }
    
    assignment_patterns = [
        r'(\w+)\s*[=:]\s*[\'"]?$',
        r'[\'"](\w+)[\'"]:\s*[\'"]?$',
        r'(\w+)\s*:\s*[\'"]?$',
        r'const\s+(\w+)\s*=\s*[\'"]?$',
        r'let\s+(\w+)\s*=\s*[\'"]?$',
        r'var\s+(\w+)\s*=\s*[\'"]?$',
    ]
    
    for pattern in assignment_patterns:
        match_obj = re.search(pattern, before_match, re.IGNORECASE)
        if match_obj:
            context['variable_name'] = match_obj.group(1)
            context['is_assignment'] = True
            if 'const' in pattern:
                context['assignment_type'] = 'const'
            elif 'let' in pattern:
                context['assignment_type'] = 'let'
            elif 'var' in pattern:
                context['assignment_type'] = 'var'
            else:
                context['assignment_type'] = 'property'
            break
    
    return context

def improved_classification(match: str, pattern_type: str, context: dict) -> str:
    """Improve classification based on variable names and context"""
    if not context['variable_name']:
        return pattern_type
    
    var_name = context['variable_name'].lower()
    
    api_type_mapping = {
        'aws': 'AWS', 'amazon': 'AWS', 's3': 'AWS S3',
        'google': 'Google', 'gcp': 'Google Cloud',
        'github': 'GitHub', 'stripe': 'Stripe', 'twilio': 'Twilio',
        'slack': 'Slack', 'discord': 'Discord', 'telegram': 'Telegram',
        'firebase': 'Firebase', 'mongodb': 'MongoDB', 'mysql': 'MySQL',
        'postgres': 'PostgreSQL', 'redis': 'Redis', 'jwt': 'JWT',
        'oauth': 'OAuth', 'bearer': 'Bearer Token', 'auth': 'Authentication Token',
        'api': 'API Key', 'secret': 'Secret Key', 'password': 'Password',
        'token': 'Token', 'key': 'Key'
    }
    
    for keyword, api_type in api_type_mapping.items():
        if keyword in var_name:
            return f"{api_type} ({pattern_type})"
    
    return pattern_type

def calculate_confidence(match: str, pattern_type: str, context: dict, source: str) -> str:
    """Calculate confidence level based on impact/sensitivity score"""
    score = 50
    
    # High impact patterns - immediate security risk
    if any(prefix in match for prefix in ['AKIA', 'AIza', 'sk_live_', 'ghp_', 'ghs_']):
        score += 40
    
    # Variable name context scoring
    if context.get('variable_name'):
        var_name = context['variable_name'].lower()
        if any(keyword in var_name for keyword in ['api', 'key', 'secret', 'token', 'password']):
            score += 20
        elif any(keyword in var_name for keyword in ['id', 'name', 'title', 'description']):
            score -= 20
    
    # File path context scoring
    if any(path in source.lower() for path in ['config', 'env', 'secret', 'key']):
        score += 15
    elif any(path in source.lower() for path in ['test', 'example', 'demo', 'doc']):
        score -= 25
    
    # Entropy-based scoring
    ent = entropy(match)
    if ent > 4.5:
        score += 10
    elif ent < 3.0:
        score -= 15
    
    # Length-based scoring
    if len(match) > 50:
        score += 5
    elif len(match) < 16:
        score -= 10
    
    # Confidence levels based on impact/sensitivity
    if score >= 85:
        return "HIGH"      # Critical impact - immediate risk
    elif score >= 65:
        return "MEDIUM"    # Moderate impact - potential risk
    elif score >= 45:
        return "LOW"       # Low impact - minimal risk
    else:
        return "VERY_LOW"  # Negligible impact

def extract_and_filter(content: str, source: str) -> List[Dict]:
    """Enhanced extraction with better filtering"""
    if should_ignore_file(source):
        return []
    
    stats['total_files_scanned'] += 1
    findings = []
    lines = content.splitlines()
    
    for lineno, line in enumerate(lines, 1):
        for regex, label in SECRETS_PATTERNS:
            for match_obj in regex.finditer(line):
                match = match_obj.group()
                if len(match_obj.groups()) > 0:
                    match = match_obj.group(1)
                
                match = match.strip().strip('\'\"')
                
                if len(match) < 8:
                    continue
                
                match_start = match_obj.start()
                match_end = match_obj.end()
                context = extract_variable_context(line, match_start, match_end)
                
                if is_false_positive(match, line, source):
                    continue
                
                if entropy(match) < 3.5 and not any(pattern in match for pattern in ['AKIA', 'AIza', 'sk_live_', 'ghp_']):
                    continue
                
                if re.match(r'^[a-f0-9]{6}$', match):
                    continue
                
                improved_type = improved_classification(match, label, context)
                confidence = calculate_confidence(match, label, context, source)
                
                finding = {
                    "type": improved_type,
                    "match": match,
                    "line_number": lineno,
                    "source": source,
                    "variable_name": context.get('variable_name'),
                    "context_before": context.get('context_before'),
                    "context_after": context.get('context_after'),
                    "confidence": confidence
                }
                
                findings.append(finding)
                stats['total_findings'] += 1
                
                if confidence == "HIGH":
                    stats['high_confidence'] += 1
                elif confidence == "MEDIUM":
                    stats['medium_confidence'] += 1
                else:
                    stats['low_confidence'] += 1
                
                print_finding(improved_type, confidence, source, lineno)
    
    return findings

def fetch_raw(raw_url: str) -> str:
    """Fetch raw file content with better error handling"""
    try:
        r = requests.get(raw_url, timeout=10)
        if r.status_code == 200:
            # Check if response is actually text content, not HTML error page
            content_type = r.headers.get('content-type', '').lower()
            if 'text/html' in content_type and '<html>' in r.text:
                return ""  # Skip HTML error pages
            return r.text
        return ""
    except:
        return ""

write_lock = threading.Lock()

def process_dork(org: str, dork: str, token: str, jsonl_path: Path):
    """Process a single dork query"""
    print_info(f"Processing dork: {dork}")
    
    for item in github_search(f"org:{org} {dork}", token):
        html_url = item["html_url"]
        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        
        content = fetch_raw(raw_url)
        if not content:
            continue
        
        findings = extract_and_filter(content, html_url)
        
        # Save ALL findings (including LOW confidence)
        if findings:
            with write_lock, open(jsonl_path, "a", encoding="utf-8") as out:
                for finding in findings:
                    finding.update({"dork": dork, "org": org})
                    out.write(json.dumps(finding, ensure_ascii=False) + "\n")

def generate_html_report(jsonl_path: Path, html_path: Path, org: str):
    """Generate an improved HTML report with modern styling"""
    try:
        import pandas as pd
    except ImportError:
        print_error("pandas not installed. Install with: pip install pandas")
        return
    
    if not jsonl_path.exists():
        print_warning("No findings file found")
        return
    
    df = pd.read_json(jsonl_path, lines=True)
    if df.empty:
        print_warning("No findings to report")
        return
    
    high_conf = df[df['confidence'] == 'HIGH']
    medium_conf = df[df['confidence'] == 'MEDIUM']
    low_conf = df[df['confidence'] == 'LOW']
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitRecon Security Report - {org}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 30px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 1.1em;
        }}
        
        .high {{ color: #dc3545; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .total {{ color: #28a745; }}
        
        .section {{
            padding: 40px;
        }}
        
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 30px;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }}
        
        .findings-table th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        .findings-table td {{
            padding: 15px;
            border-bottom: 1px solid #eee;
        }}
        
        .findings-table tr:hover {{
            background-color: #f8f9fa;
        }}
        
        .confidence-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .confidence-high {{
            background-color: #dc3545;
            color: white;
        }}
        
        .confidence-medium {{
            background-color: #ffc107;
            color: #333;
        }}
        
        .confidence-low {{
            background-color: #17a2b8;
            color: white;
        }}
        
        .secret-type {{
            background-color: #e9ecef;
            padding: 5px 10px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        
        .source-link {{
            color: #007bff;
            text-decoration: none;
        }}
        
        .source-link:hover {{
            text-decoration: underline;
        }}
        
        .match-preview {{
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 5px 8px;
            border-radius: 3px;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        .footer {{
            background-color: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        
        .empty-state h3 {{
            font-size: 1.5em;
            margin-bottom: 10px;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .findings-table {{
                font-size: 0.9em;
            }}
            
            .findings-table th,
            .findings-table td {{
                padding: 10px 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 GitRecon Security Report</h1>
            <p class="subtitle">Organization: {org} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number total">{len(df)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">{len(high_conf)}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">{len(medium_conf)}</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">{len(low_conf)}</div>
                <div class="stat-label">Low Risk</div>
            </div>
        </div>
'''
    
    if len(high_conf) > 0:
        html_content += f'''
        <div class="section">
            <h2>🚨 High Risk Findings ({len(high_conf)})</h2>
            {generate_table_html(high_conf, 'high')}
        </div>
        '''
    
    if len(medium_conf) > 0:
        html_content += f'''
        <div class="section">
            <h2>⚠️ Medium Risk Findings ({len(medium_conf)})</h2>
            {generate_table_html(medium_conf, 'medium')}
        </div>
        '''
    
    if len(low_conf) > 0:
        html_content += f'''
        <div class="section">
            <h2>🔍 Low Risk Findings ({len(low_conf)})</h2>
            {generate_table_html(low_conf, 'low')}
        </div>
        '''
    
    if len(df) == 0:
        html_content += '''
        <div class="section">
            <div class="empty-state">
                <h3>✅ No Secrets Found</h3>
                <p>Great! No sensitive information was detected in the scanned repositories.</p>
            </div>
        </div>
        '''
    
    html_content += f'''
        <div class="footer">
            <p>Generated by GitRecon v1.0 | Scan completed at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>'''
    
    html_path.write_text(html_content, encoding="utf-8")
    print_success(f"Enhanced HTML report generated: {html_path}")

def generate_table_html(df, confidence_level: str) -> str:
    """Generate HTML table for findings with improved styling"""
    if df.empty:
        return '<div class="empty-state"><p>No findings to display.</p></div>'
    
    html = '<table class="findings-table">'
    html += '''
        <thead>
            <tr>
                <th>Type</th>
                <th>Match Preview</th>
                <th>Variable</th>
                <th>Source File</th>
                <th>Line</th>
                <th>Confidence</th>
            </tr>
        </thead>
        <tbody>
    '''
    
    for _, row in df.iterrows():
        match_preview = row['match'][:50] + ('...' if len(row['match']) > 50 else '')
        filename = row['source'].split('/')[-1]
        variable_name = row.get('variable_name', 'N/A')
        
        html += f'''
            <tr>
                <td><span class="secret-type">{row['type']}</span></td>
                <td><code class="match-preview">{match_preview}</code></td>
                <td>{variable_name}</td>
                <td><a href="{row['source']}" target="_blank" class="source-link">{filename}</a></td>
                <td>#{row['line_number']}</td>
                <td><span class="confidence-badge confidence-{confidence_level.lower()}">{row['confidence']}</span></td>
            </tr>
        '''
    
    html += '</tbody></table>'
    return html

def main():
    """Main function with custom dork file support"""
    parser = argparse.ArgumentParser(
        description="GitRecon v1.0 - GitHub Repository Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -o example-org -c ALL
  %(prog)s -o example-org -c HIGH -f custom_dorks.txt
  %(prog)s -o example-org -c MEDIUM --output results.jsonl --html custom_report.html
  %(prog)s -o example-org -c LOW --threads 2 --max-pages 2

Confidence/Impact Levels (-c parameter):
  ALL     - Show all findings (HIGH, MEDIUM, LOW impact)
  HIGH    - Show only high impact/critical secrets (score >= 85)
  MEDIUM  - Show medium+ impact secrets (score >= 65)  
  LOW     - Show low+ impact secrets (score >= 45)
        '''
    )
    
    parser.add_argument("-o", "--org", required=True, help="GitHub organization to scan")
    parser.add_argument("-c", "--category", default="ALL", help="Secret impact/sensitivity level filter (ALL, HIGH, MEDIUM, LOW)")
    parser.add_argument("-f", "--file", default="dorks/small.txt", help="Dork file to use (default: dorks/small.txt)")
    parser.add_argument("--output", help="Output JSONL file (default: ORG_NAME_findings.jsonl)")
    parser.add_argument("--html", help="HTML report file (default: ORG_NAME_report.html)")
    parser.add_argument("--threads", "-t", type=int, default=4, help="Number of threads (default: 4)")
    parser.add_argument("--max-pages", "-p", type=int, default=3, help="Maximum pages per query (default: 3)")
    
    args = parser.parse_args()
    
    # Update global configuration
    global MAX_THREADS, MAX_PAGES
    MAX_THREADS = args.threads
    MAX_PAGES = args.max_pages
    
    # Generate unique filenames based on organization name
    org_name_clean = sanitize_filename(args.org)
    
    # Set default filenames if not provided
    if not args.output:
        args.output = f"{org_name_clean}_findings.jsonl"
    if not args.html:
        args.html = f"{org_name_clean}_report.html"
    
    print_banner()
    stats['start_time'] = time.time()
    
    setup_logging()
    tokens = get_github_tokens()
    dorks = load_dorks(args.file)
    
    print_info(f"Target organization: {args.org}")
    print_info(f"Impact/Sensitivity filter: {args.category}")
    print_info(f"Dork file: {args.file}")
    print_info(f"Using {MAX_THREADS} threads, {MAX_PAGES} pages per query")
    print_info(f"Results will be saved to: {args.output}")
    print_info(f"HTML report will be saved to: {args.html}")
    
    if MAX_THREADS > 4:
        print_warning("High thread count may cause rate limiting. Consider using --threads 2-4")
    
    jsonl_path = Path(args.output)
    html_path = Path(args.html)
    
    if jsonl_path.exists():
        jsonl_path.unlink()
    
    print_info(f"Starting scan with {len(dorks)} dork patterns...")
    print()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for i, dork in enumerate(dorks):
            token = tokens[i % len(tokens)]
            future = executor.submit(process_dork, args.org, dork, token, jsonl_path)
            futures.append(future)
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            print_info(f"Completed {completed}/{len(dorks)} dork patterns")
    
    print()
    print_stats()
    
    print_info("Generating HTML report...")
    generate_html_report(jsonl_path, html_path, args.org)
    
    if stats['total_findings'] > 0:
        if stats['high_confidence'] > 0:
            print_error(f"⚠️  CRITICAL: Found {stats['high_confidence']} high-impact secrets!")
        elif stats['medium_confidence'] > 0:
            print_warning(f"Found {stats['medium_confidence']} medium-impact potential secrets")
        else:
            print_info(f"Found {stats['total_findings']} low-impact potential secrets")
        
        print_success(f"Detailed report available at: {args.html}")
    else:
        print_success("✅ No secrets detected! Your repositories look secure.")
    
    print_info("Scan completed successfully!")

if __name__ == "__main__":
    main()