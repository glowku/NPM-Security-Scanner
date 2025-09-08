# 🛡️ NPM Security Scanner - Professional Edition

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![Security](https://img.shields.io/badge/security-critical-red.svg)](https://cve.mitre.org)
[![GitHub issues](https://img.shields.io/github/issues/glowku/NPM-Security-Scanner.svg)](https://github.com/glowku/NPM-Security-Scanner/issues)
[![GitHub forks](https://img.shields.io/github/forks/glowku/NPM-Security-Scanner.svg?style=social)](https://github.com/glowku/NPM-Security-Scanner/network)
[![GitHub stars](https://img.shields.io/github/stars/glowku/NPM-Security-Scanner.svg?style=social)](https://github.com/glowku/NPM-Security-Scanner/stargazers)

**A comprehensive professional tool to detect and respond to the Operation CryptoClipper supply chain attack targeting JavaScript packages.**

---

## 🚨 Critical Security Alert

This tool responds to **Operation CryptoClipper** (CVE-2025-31842), a sophisticated supply chain attack that compromised popular NPM packages to steal cryptocurrency through wallet address hijacking. **2+ billion weekly downloads** were affected across the JavaScript ecosystem.

### Attack Overview
- **Date Discovered**: September 8, 2025
- **Attack Vector**: Compromised NPM maintainer account (qix) via phishing
- **Impact**: 18 popular packages with over 2 billion weekly downloads
- **Objective**: Financial gain through cryptocurrency theft
- **Method**: Malicious code injection in package updates

### Malicious Capabilities
- Crypto wallet address swapping using Levenshtein distance
- Transaction hijacking via wallet provider interception
- Network request modification (fetch, XMLHttpRequest)
- Clipboard manipulation for address replacement
- Multi-currency support (BTC, ETH, SOL, TRX, LTC, BCH)
- Ethereum provider hijacking (window.ethereum)
- Sophisticated code obfuscation to avoid detection

--


✨ Features
Core Functionality

🔍 Comprehensive Scanning: Automatically detects compromised packages across your entire system with deep directory traversal
🎯 Precision Targeting: Identifies specific malicious versions with CVE tracking and risk scoring
🛠️ Multiple Response Options: Three remediation paths - Delete, Repair, or Ignore vulnerable projects
📊 Professional Reporting: Generates detailed HTML reports with comprehensive threat analysis and visualizations
🖥️ Interactive Tools: Step-by-step guidance through the vulnerability remediation process

Advanced Features

🔄 Automated Scripts: Batch processing capabilities for enterprise environments
🎨 Professional UI: Dark theme with cyan/blue/black/gray color scheme for reduced eye strain
🔐 Security Best Practices: Built-in recommendations and mitigation strategies based on threat intelligence
📈 Metrics Dashboard: Real-time scanning progress and comprehensive statistics
🕵️ Recent Package Detection: Identifies packages installed in the last 7 days that might be affected
💾 Backup Integration: Automatic backup creation before any remediation actions
🌐 Multi-Platform Support: Works on Windows, macOS, and Linux systems


📦 Installation
Prerequisites

Node.js >= 14.0.0
npm >= 6.0.0
Administrative privileges (for system-wide scanning)

Method 1: Install from GitHub (Recommended)
npm install -g glowku/NPM-Security-Scanner

Method 2: Manual Installation
# 1. Clone the repository
git clone https://github.com/glowku/NPM-Security-Scanner.git

# 2. Enter the directory
cd NPM-Security-Scanner

# 3. Install dependencies
npm install

# 4. Create a global link
npm link

Method 3: Use with NPX
# Run without permanent installation
npx github:glowku/NPM-Security-Scanner

Installation Verification
# Verify the tool is properly installed
npm-security-scanner-pro --version

# You should see: 1.0.0


🚀 Usage
Before Scanning - Preparation

Backup your important data

# Example backup
cp -r /your/project /backup/project-$(date +%Y%m%d)


Close sensitive applications (e.g., Crypto wallets like MetaMask, banking applications, running projects)
Note your important projects (keep a list of critical projects and their paths)

Basic Scan - Getting Started
# Launch the full scan
npm-security-scanner-pro

What the scan does:

🔍 Searches all your JavaScript projects
📊 Analyzes each installed package
⚠️ Identifies malicious versions
📋 Generates a detailed report

Interactive Scan - For Beginners
# Launch interactive mode (recommended)
npm-security-scanner-pro --interactive

Advantages of interactive mode:

🎯 Step-by-step guidance
💬 Clear explanations for each action
✅ Confirmation before each critical action
🛡️ Built-in security options

Advanced Options
# Scan without generating a report (faster)
npm-security-scanner-pro --no-report

# Debug mode for developers
npm-security-scanner-pro --debug

# See all options
npm-security-scanner-pro --help

Action Guide - What To Do?
Step 1: Understand the Results
After scanning, you'll see:
📈 SCAN STATISTICS:
   • Total Projects Scanned:    15
   • Vulnerable Projects:       3
   • Vulnerable Packages:      7
   • Risk Level:          CRITICAL

What this means:

Total Projects Scanned: Number of projects found
Vulnerable Projects: Projects containing dangerous packages
Risk Level: Risk level (CRITICAL = very dangerous)

Step 2: Analyze Vulnerable Projects
The scanner will show:
🚨 AFFECTED PROJECTS (3):
1. 📁 C:\Users\your\name\project1
   🔴 chalk 5.6.1 → 5.6.0 (CVE-2025-31842)
   
2. 📁 C:\Users\your\name\project2
   🔴 debug 4.4.2 → 4.4.1 (CVE-2025-31843)

How to read:

📁 Path to compromised project
🔴 Dangerous package → Safe version
(CVE-XXXXX): Vulnerability identifier

Step 3: Choose Your Action
For each project, you have 3 options:

Option 1: DELETE (Recommended) 🗑️

When: For most projects
Why: Completely eliminates the threat
Risk: None (with backup)


Option 2: REPAIR (Risky) 🔧

When: Only for critical indispensable projects
Why: Keeps the project but fixes vulnerabilities
Risk: High (might not work properly)


Option 3: IGNORE (Very Risky) ⚠️

When: Only if the project is unused and has no crypto
Why: Does nothing
Risk: Very high (vulnerability persists)



Step 4: Execute Your Chosen Action
With the Interactive Tool (Recommended):
npm-security-scanner-pro --interactive

The tool will guide you:

📋 Shows project details
❓ Asks clear questions
✅ Requests confirmation before acting
🔄 Performs the action safely

Manually (Experts only):
# To delete a project
rmdir /s /q "C:\path\to\project"

# To repair a project
cd "C:\path\to\project"
npm install package@safe-version

🛡️ Security Measures - Before, During, After
Before Using the Tool

Complete Backup

# Example Windows
robocopy C:\my-projects D:\backup-projects /E


Document Your Projects
List of important projects
Their functionality
Their critical dependencies


Prepare Your Environment
Close crypto applications
Disconnect wallets
Note your passwords



While Using the Tool

Read Carefully
Every message is important
Don't click too fast
Understand before acting


Use Interactive Mode
Safer for beginners
Step-by-step explanations
Security confirmations


Take Notes
Screenshot results
Note actions performed
Keep a change log



After Using the Tool

Verify Everything

# Run another scan to verify
npm-security-scanner-pro --no-report


Update Your Security
Change crypto passwords
Enable 2FA everywhere
Use hardware wallets


Monitor
Check your crypto transactions
Watch for suspicious activity
Stay vigilant for a few weeks




🔍 How It Works
The NPM Security Scanner uses a multi-layered approach to detect and remediate vulnerabilities:

Deep System Scan: Traverses your file system to identify all JavaScript projects
Package Analysis: Examines package.json and node_modules for vulnerable packages
Version Comparison: Checks installed versions against the vulnerability database
Risk Assessment: Assigns risk scores based on project usage and vulnerability severity
Remediation Guidance: Provides clear options for addressing each vulnerability
Report Generation: Creates comprehensive reports with visualizations and recommendations


📊 Vulnerability Database
The tool maintains an up-to-date database of known vulnerabilities including:

CVE-2025-31842: Operation CryptoClipper wallet hijacking
CVE-2025-31843: Debug package clipboard manipulation
CVE-2025-31844: Request interceptor for crypto transactions
CVE-2025-31845: Ethereum provider hijacking vulnerability
CVE-2025-31846: Obfuscated code injection in popular utilities

The database is automatically updated with the latest threat intelligence.

🛡️ Security Recommendations
Immediate Actions

Scan all systems using this tool
Update or remove all vulnerable packages
Monitor transactions in all crypto wallets
Change passwords for all crypto accounts

Long-term Protections

Implement package pinning in all projects
Use automated security scanning in CI/CD pipelines
Educate developers about supply chain risks
Monitor npm advisories for new vulnerabilities
Consider using alternative registries with enhanced security


⚠️ User Responsibility - Important!
What You Should Know 📜By using this tool, you agree that:

YOU ARE RESPONSIBLE for all actions performed
YOU MUST BACKUP your important data before
ACTIONS ARE IRREVERSIBLE (especially deletion)
YOU ASSUME ALL RISKS related to usage


🤝 Contributing
We welcome contributions! Please see our contributing guidelines:

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

Please make sure to update tests as appropriate and follow the existing code style.

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments

Security researchers who discovered and reported Operation CryptoClipper
Node.js security team for their rapid response
Open source community for maintaining vulnerable packages
NPM security team for their coordination efforts


📞 Contact
Project Lead: glowku
