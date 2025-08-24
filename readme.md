# 🔍 GitRecon v1.0

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Security Scanner](https://img.shields.io/badge/tool-security--scanner-red.svg)](https://github.com/Codewith-Vedant/Git-Recon)

**Advanced GitHub Repository Secret Scanner with Impact-Based Analysis**

GitRecon v1.0 is a powerful security reconnaissance tool designed to detect exposed secrets, API keys, tokens, passwords, and sensitive information in GitHub organization repositories. Features intelligent impact scoring, custom dork support, and professional HTML reporting.

---

## ✨ Features

### 🔍 **Comprehensive Secret Detection**
- **22+ Secret Patterns**: AWS keys, GitHub tokens, Stripe keys, Google API keys, JWT tokens, private keys, database URLs
- **Smart Pattern Matching**: Context-aware detection with variable name analysis
- **Impact-Based Scoring**: HIGH/MEDIUM/LOW confidence levels
- **Advanced Filtering**: Entropy analysis, false positive reduction, and legitimate keyword filtering

### 🎨 **Professional Interface**
- **Colorful CLI Output**: Timestamped messages with emojis and color-coded findings
- **Real-time Progress**: Live updates showing scan progress and statistics
- **Modern HTML Reports**: Responsive design with interactive tables and statistics
- **Unique Filenames**: Auto-generates `ORG_findings.jsonl` and `ORG_report.html`

### ⚡ **Performance & Flexibility**
- **Custom Dork Support**: Load search patterns from external files (`-f` option)
- **Multi-threaded Scanning**: Configurable concurrency for optimal performance
- **Rate Limit Handling**: Intelligent GitHub API management with automatic retries
- **Error Recovery**: Graceful handling of network issues and API limitations

---

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- GitHub Personal Access Token with `public_repo` scope

### Install Dependencies
```bash
pip install requests colorama pandas
```

### Optional: Install via requirements.txt
```bash
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### 1. Set Up GitHub Token
Create a GitHub Personal Access Token with `public_repo` scope:

**Linux/macOS:**
```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

**Windows (Command Prompt):**
```cmd
set GITHUB_TOKEN=ghp_your_token_here
```

**Windows (PowerShell):**
```powershell
$env:GITHUB_TOKEN="ghp_your_token_here"
```

### 2. Create Dork Directory
```bash
mkdir dorks
# Place your small.txt file in the dorks/ directory
```

### 3. Run Basic Scan
```bash
python git-recon-proper.py -o target-org -c ALL
```

### 4. Check Results
- View real-time results in the terminal
- Open `target-org_report.html` for detailed findings
- Review `target-org_findings.jsonl` for raw data

---

## 📖 Usage Guide

### Basic Usage
```bash
python git-recon-proper.py -o organization-name -c ALL
```

### Advanced Options
```bash
python git-recon-proper.py -o example-org -c HIGH \
  -f custom_dorks.txt \
  --threads 6 \
  --max-pages 4 \
  --output custom_findings.jsonl \
  --html custom_report.html
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--org` | `-o` | **Required**. GitHub organization to scan | - |
| `--category` | `-c` | Impact/sensitivity filter (ALL, HIGH, MEDIUM, LOW) | `ALL` |
| `--file` | `-f` | Custom dork file path | `dorks/small.txt` |
| `--threads` | `-t` | Number of concurrent threads | `4` |
| `--max-pages` | `-p` | Maximum API pages per query | `3` |
| `--output` | - | Custom JSONL output filename | `ORG_findings.jsonl` |
| `--html` | - | Custom HTML report filename | `ORG_report.html` |

---

## 🎯 Impact/Sensitivity Levels

### Understanding the `-c` Parameter

The category parameter filters findings based on their security impact score:

```bash
# Show all findings regardless of impact
python git-recon-proper.py -o target-org -c ALL

# Show only critical/high-impact secrets (score >= 85)
python git-recon-proper.py -o target-org -c HIGH

# Show medium+ impact secrets (score >= 65)  
python git-recon-proper.py -o target-org -c MEDIUM

# Show low+ impact secrets (score >= 45)
python git-recon-proper.py -o target-org -c LOW
```

### Impact Scoring Criteria

<details>
<summary>Click to expand scoring methodology</summary>

**Base Score: 50**

**High Impact Indicators (+40 points):**
- AWS Access Keys (`AKIA*`)
- Google API Keys (`AIza*`)
- Live Stripe Keys (`sk_live_*`)
- GitHub Personal Tokens (`ghp_*`)

**Variable Context (+20/-20 points):**
- Security-related variable names: `+20`
- Generic identifiers (id, name, title): `-20`

**File Path Context (+15/-25 points):**
- Config/secret files: `+15`
- Test/demo files: `-25`

**Entropy Analysis (+10/-15 points):**
- High randomness (>4.5): `+10`
- Low randomness (<3.0): `-15`

**Length Assessment (+5/-10 points):**
- Long secrets (>50 chars): `+5`
- Short secrets (<16 chars): `-10`

</details>

---

## 🔍 Secret Patterns Detected

<details>
<summary>Click to expand supported patterns (22+ types)</summary>

### Cloud Providers
- **AWS**: Access Keys (`AKIA*`), Secret Access Keys
- **Google Cloud**: API Keys (`AIza*`)

### Version Control
- **GitHub**: Personal Access Tokens (`ghp_*`), App Tokens (`ghs_*`), Refresh Tokens (`ghr_*`)

### Payment Processing
- **Stripe**: Live Secret Keys (`sk_live_*`), Publishable Keys (`pk_live_*`), Restricted Keys (`rk_live_*`)

### Communication
- **Slack**: Bot Tokens, User Tokens, Workspace Tokens
- **Twilio**: API Keys (`SK*`), Account SIDs (`AC*`)

### Authentication
- **JWT Tokens**: Complete JSON Web Tokens
- **Generic API Keys**: Context-aware detection
- **OAuth Tokens**: Access tokens and refresh tokens

### Infrastructure
- **Database URLs**: MongoDB, MySQL, PostgreSQL connection strings
- **Private Keys**: RSA, OpenSSH private keys

### Generic Patterns
- **Passwords**: High-entropy password detection
- **Secrets**: Generic secret key patterns
- **Tokens**: Bearer tokens and access tokens

</details>

---

## 📁 Dork File Format

### Default Location: `dorks/small.txt`

You can use other dork files(All-dorks.txt or medium.txt) or create your own custom dork file with search patterns (one per line):

```txt
# Configuration files
"access_key"
"secret_key"
"api_key"
"password"

# AWS patterns
"aws_access_key_id"
"AWS_SECRET_ACCESS_KEY"
AKIA

# GitHub patterns
"github_token"
"gh_token"
ghp_

# Database patterns
"db_password"
"database_password"
mysql://
mongodb://

# Generic patterns
"client_secret"
"private_key"
"oauth_token"

# File-based searches
filename:.env
filename:config.json
filename:secrets.yml
```

### Dork File Rules:
- One search pattern per line
- Lines starting with `#` are comments (ignored)
- Empty lines are ignored
- Supports both keyword and filename searches

---

## 📊 Output Examples

### HTML File Output
![Output](Output.png)

### Terminal Output
```
╔══════════════════════════════════════════════════════════════╗
║                          GitRecon v1.0                      ║
║               GitHub Repository Secret Scanner               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🔍 Scanning for exposed secrets and sensitive information...

[19:15:12] ✅ Loaded 1 GitHub token(s)
[19:15:12] ✅ Loaded 85 dork(s) from dorks/small.txt
[19:15:12] ℹ️  Target organization: example-org
[19:15:12] ℹ️  Impact/Sensitivity filter: ALL
[19:15:15] 🚨 AWS Access Key in config.js#23 (HIGH confidence)
[19:15:18] ⚠️  Generic API Key in settings.py#45 (MEDIUM confidence)
[19:15:21] 🔍 Password in .env#12 (LOW confidence)

╔═══════════════ SCAN STATISTICS ═══════════════╗
║ Files Scanned:       375 files                ║
║ Total Findings:      113 secrets              ║
║ High Confidence:      46 findings             ║
║ Medium Confidence:    27 findings             ║
║ Low Confidence:       40 findings             ║
║ Scan Duration:      192.1 seconds             ║
╚═══════════════════════════════════════════════╝

⚠️  CRITICAL: Found 46 high-impact secrets!
✅ Detailed report available at: example-org_report.html
```

### HTML Report Features
- **Executive Summary**: Statistics dashboard with impact breakdown
- **Categorized Findings**: Separate sections for HIGH/MEDIUM/LOW impact
- **Interactive Tables**: Sortable columns with source file links
- **Modern Design**: Responsive layout with professional styling
- **Mobile Friendly**: Optimized for all device sizes

---

## ⚡ Performance Optimization

### Rate Limiting Best Practices
```bash
# Conservative approach (recommended for single token)
python git-recon-proper.py -o target-org -c ALL --threads 2 --max-pages 2

# Balanced approach (good for most cases)
python git-recon-proper.py -o target-org -c ALL --threads 4 --max-pages 3

# Aggressive approach (requires multiple tokens)
python git-recon-proper.py -o target-org -c ALL --threads 8 --max-pages 5
```

### Multiple Tokens Setup
**Environment Variable (comma-separated):**
```bash
export GITHUB_TOKEN="ghp_token1,ghp_token2,ghp_token3"
```

**Token File (`github_tokens.txt`):**
```txt
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
ghp_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
```

### Custom Dork Files
```bash
# Use different dork sets for different scan types
python git-recon-proper.py -o target-org -c HIGH -f dorks/medium.txt
python git-recon-proper.py -o target-org -c ALL -f dorks/All-dorks.txt
```

---

## 🔧 Configuration Examples

### Quick Security Audit (High Impact Only)
```bash
python git-recon-proper.py -o company-name -c HIGH -f dorks/critical.txt --threads 2
```

### Comprehensive Analysis (All Findings)
```bash
python git-recon-proper.py -o company-name -c ALL -f dorks/medium.txt --threads 4 --max-pages 4
```

### Fast Scan (Limited Scope)
```bash
python git-recon-proper.py -o company-name -c MEDIUM --threads 6 --max-pages 2
```

### Custom Output Location
```bash
python git-recon-proper.py -o company-name -c ALL \
  --output /path/to/results.jsonl \
  --html /path/to/report.html
```

---

## 🛠️ Troubleshooting

### Debug Tips
- Use `--threads 1` for debugging individual requests
- Check GitHub token permissions (needs `public_repo` scope)
- Verify organization name is correct and public
- Monitor rate limits in GitHub account settings

---

## 📋 Requirements

### System Requirements
- Python 3.7+
- 100MB+ free disk space
- Internet connection for GitHub API access

### Python Dependencies
```txt
requests>=2.28.0    # HTTP requests to GitHub API
colorama>=0.4.5     # Colored terminal output
pandas>=1.5.0       # HTML report generation (optional)
urllib3>=1.26.0     # URL encoding and parsing
```

---

## 🔒 Security Considerations

### Responsible Usage
- **Only scan organizations you own or have explicit permission to test**
- **Report findings through proper security disclosure channels**
- **Do not use this tool for malicious reconnaissance or unauthorized access**
- **Respect GitHub's Terms of Service and API rate limits**

### Data Protection
- **Findings may contain actual secrets - handle results securely**
- **Use encrypted storage for sensitive reports**
- **Implement proper access controls on result files**
- **Clean up temporary files after analysis**
- **Consider legal implications of discovered secrets**

### Rate Limiting Ethics
- **Use reasonable request rates to avoid impacting GitHub's infrastructure**
- **Implement proper delays between requests**
- **Monitor your API usage to stay within limits**
- **Use multiple tokens responsibly, not to bypass intentional limits**

---

## 🤝 Contributing

We welcome contributions to improve GitRecon! Here's how to get involved:

### Development Setup
```bash
git clone https://github.com/Codewith-Vedant/Git-Recon
cd Git-Recon
pip install -r requirements.txt
```

### Contribution Areas
- **New Secret Patterns**: Add detection for additional services
- **Performance Improvements**: Optimize scanning algorithms
- **Enhanced Filtering**: Improve false positive detection
- **Output Formats**: Add new report formats (CSV, XML, etc.)
- **Documentation**: Improve guides and examples

### Pull Request Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Test your changes thoroughly
4. Add appropriate documentation
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request with detailed description

---

## 📝 Changelog

### v1.0.0 (Current)
- ✨ **Custom Dork File Support**: Load patterns from external files (`-f` option)
- ✨ **Professional HTML Reports**: Modern responsive design with statistics
- ✨ **Advanced Pattern Detection**: 22+ secret types with context analysis
- ✨ **Smart False Positive Filtering**: Entropy analysis and keyword detection
- ✨ **Multi-threaded Performance**: Configurable concurrency for speed
- ✨ **Rate Limit Management**: Intelligent API handling with retry logic
- ✨ **Unique Output Files**: Organization-based naming convention
- ✨ **Comprehensive CLI**: Colorful output with progress tracking
- ✨ **Error Recovery**: Graceful handling of network and API issues

---

## 👥 Authors & Acknowledgments

- **Lead Developer**: [Vedant Pillai aka Titan-Hack](https://github.com/Codewith-Vedant)

---

<div align="center">

**🛡️ Securing repositories, one secret at a time 🛡️**

**Made with ❤️ for the cybersecurity community by [Titan-Hack](https://www.linkedin.com/in/vedant0701/)**

</div>