# 🛡️ NPM Security Scanner - CHECK+FIX Edition

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

---

## 📋 Table of Contents
- [🚨 Critical Security Alert](#-critical-security-alert)
- [✨ Features](#-features)
- [📦 Installation](#-installation)
- [🚀 Usage](#-usage)
- [🔍 How It Works](#-how-it-works)
- [📊 Vulnerability Database](#-vulnerability-database)
- [🛡️ Security Recommendations](#-security-recommendations)
- [⚠️ User Responsibility](#-user-responsibility)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Contact](#-contact)

---

## ✨ Features

### Core Functionality
- 🔍 **Comprehensive Scanning**: Automatically detects compromised packages across your entire system with deep directory traversal
- 🎯 **Precision Targeting**: Identifies specific malicious versions with CVE tracking and risk scoring
- 🛠️ **Multiple Response Options**: Three remediation paths - Delete, Repair, or Ignore vulnerable projects
- 📊 **Professional Reporting**: Generates detailed HTML reports with comprehensive threat analysis and visualizations
- 🖥️ **Interactive Tools**: Step-by-step guidance through the vulnerability remediation process

### Advanced Features
- 🔄 **Automated Scripts**: Batch processing capabilities for enterprise environments
- 🎨 **Professional UI**: Dark theme with cyan/blue/black/gray color scheme for reduced eye strain
- 🔐 **Security Best Practices**: Built-in recommendations and mitigation strategies based on threat intelligence
- 📈 **Metrics Dashboard**: Real-time scanning progress and comprehensive statistics
- 🕵️ **Recent Package Detection**: Identifies packages installed in the last 7 days that might be affected
- 💾 **Backup Integration**: Automatic backup creation before any remediation actions
- 🌐 **Multi-Platform Support**: Works on Windows, macOS, and Linux systems

---

## 📦 Installation

### Prerequisites
- Node.js >= 14.0.0
- npm >= 6.0.0
- Administrative privileges (for system-wide scanning)

### Method 1: Install from GitHub (Recommended)
```bash
npm install -g glowku/NPM-Security-Scanner

