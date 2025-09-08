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

The attack involved malicious code injection into commonly used packages, allowing attackers to:
- Hijack cryptocurrency transactions by replacing wallet addresses
- Intercept network requests and modify responses
- Manipulate clipboard content for address replacement
- Use visual similarity attacks with Levenshtein distance algorithms

---

## 📋 Table of Contents

- [🚨 Critical Security Alert](#-critical-security-alert)
- [✨ Features](#-features)
- [📦 Installation](#-installation)
- [🚀 Usage](#-usage)
- [🔍 How It Works](#-how-it-works)
  - [Scanning Process](#scanning-process)
  - [Detection Methodology](#detection-methodology)
  - [Remediation Options](#remediation-options)
- [📊 Vulnerability Database](#-vulnerability-database)
  - [Complete List of Affected Packages](#complete-list-of-affected-packages)
  - [Attack Technical Details](#attack-technical-details)
- [🛡️ Security Recommendations](#-security-recommendations)
  - [Immediate Actions](#immediate-actions)
  - [Preventive Measures](#preventive-measures)
  - [Response Strategy](#response-strategy)
- [📋 Detailed Reporting](#-detailed-reporting)
  - [HTML Report Features](#html-report-features)
  - [Automated Scripts](#automated-scripts)
  - [Interactive Tool](#interactive-tool)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Contact](#-contact)
- [📊 Project Statistics](#-project-statistics)

---

## ✨ Features

- 🔍 **Comprehensive Scanning**: Automatically detects compromised packages across your entire system with deep directory traversal
- 🎯 **Precision Targeting**: Identifies specific malicious versions with CVE tracking and risk scoring
- 🛠️ **Multiple Response Options**: Three remediation paths - Delete, Repair, or Ignore vulnerable projects
- 📊 **Professional Reporting**: Generates detailed HTML reports with comprehensive threat analysis and visualizations
- 🖥️ **Interactive Tools**: Step-by-step guidance through the vulnerability remediation process
- 🔄 **Automated Scripts**: Batch processing capabilities for enterprise environments
- 🎨 **Professional UI**: Dark theme with cyan/blue/black/gray color scheme for reduced eye strain
- 🔐 **Security Best Practices**: Built-in recommendations and mitigation strategies based on threat intelligence
- 📈 **Metrics Dashboard**: Real-time scanning progress and comprehensive statistics
- 🕵️ **Recent Package Detection**: Identifies packages installed in the last 7 days that might be affected
- 💾 **Backup Integration**: Automatic backup creation before any remediation actions
- 🌐 **Multi-Platform Support**: Works on Windows, macOS, and Linux systems

---

## 📦 Installation

**Requirements:**
- Node.js >= 14.0.0
- npm >= 6.0.0

### Install from GitHub (Recommended)

```bash
npm install -g glowku/NPM-Security-Scanner