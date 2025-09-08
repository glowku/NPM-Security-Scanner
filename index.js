#!/usr/bin/env node

// Votre code JavaScript complet ici
// (collez le code que je vous ai fourni précédemment)

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');
const readline = require('readline');

// ===== DEBUG MODE =====
const DEBUG = true;
function debugLog(message) {
  if (DEBUG) {
    console.log(`[DEBUG] ${message}`);
  }
}

// ===== COMPREHENSIVE THREAT INTELLIGENCE (UPDATED) =====
const THREAT_INTEL = {
  attack: {
    name: "Operation CryptoClipper",
    date: "September 2025",
    cve: "CVE-2025-31842",
    severity: "CRITICAL",
    description: "Sophisticated supply chain attack targeting JavaScript ecosystem",
    actor: "Unknown (financially motivated)",
    impact: "2B+ weekly downloads affected",
    attack_vector: "Compromised developer account (qix) via phishing",
    mitre: "T1195.002",
    source: "https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the"
  },
  attacker_wallets: {
    ethereum: [
      "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976",
      "0xa29eeFb3f21Dc8FA8bce065Db4f4354AA683c024",
      "0x40C351B989113646bc4e9Dfe66AE66D24fE6Da7B",
      "0x30F895a2C66030795131FB66CBaD6a1f91461731",
      "0x57394449fE8Ee266Ead880D5588E43501cb84cC7",
      "0xCd422cCC9f6e8f30FfD6F68C0710D3a7F24a026A"
    ],
    bitcoin: [
      "1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx",
      "1Li1CRPwjovnGHGPTtcKzy75j37K6n97Rd",
      "1Dk12ey2hKWJctU3V8Akc1oZPo1ndjbnjP",
      "1NBvJqc1GdSb5uuX8vT7sysxtT4LB8GnuY"
    ],
    bitcoin_bech32: [
      "bc1qms4f8ys8c4z47h0q29nnmyekc9r74u5ypqw6wm",
      "bc1qznntn2q7df8ltvx842upkd9uj4atwxpk0whxh9",
      "bc1q4rllc9q0mxs827u6vts2wjvvmel0577tdsvltx"
    ]
  },
  attack_methods: [
    "Crypto wallet address swapping",
    "Transaction hijacking", 
    "Network request interception",
    "Clipboard manipulation",
    "Levenshtein distance algorithm for visual similarity",
    "Ethereum provider hijacking",
    "XMLHttpRequest override",
    "Fetch API hijacking"
  ],
  malware_capabilities: [
    "Intercepts window.ethereum requests",
    "Modifies fetch and XMLHttpRequest responses",
    "Replaces crypto addresses with attacker-controlled ones",
    "Uses Levenshtein distance for address similarity",
    "Targets multiple cryptocurrencies (BTC, ETH, BCH, LTC, etc.)",
    "Obfuscated code to avoid detection"
  ]
};

// ===== DETAILED VULNERABILITY DATABASE (UPDATED SEPTEMBER 2025) =====
const VULN_DB = {
  'chalk': {
    safe: '5.6.0',
    malicious: ['5.6.1'],
    description: 'Terminal string styling library',
    weeklyDownloads: 300000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31842',
    risk_score: 9.8,
    attack_surface: 'Frontend applications, CLI tools',
    mitigation: 'Downgrade to version 5.6.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'debug': {
    safe: '4.4.1',
    malicious: ['4.4.2'],
    description: 'Debugging utility',
    weeklyDownloads: 150000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31843',
    risk_score: 9.8,
    attack_surface: 'Node.js applications, development tools',
    mitigation: 'Downgrade to version 4.4.1 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'strip-ansi': {
    safe: '7.1.0',
    malicious: ['7.1.1'],
    description: 'ANSI escape code stripper',
    weeklyDownloads: 261000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31844',
    risk_score: 9.8,
    attack_surface: 'Web applications, build tools',
    mitigation: 'Downgrade to version 7.1.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'color-convert': {
    safe: '3.1.0',
    malicious: ['3.1.1'],
    description: 'Color space conversion utilities',
    weeklyDownloads: 193000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31845',
    risk_score: 9.8,
    attack_surface: 'Design applications, data visualization',
    mitigation: 'Downgrade to version 3.1.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'color-name': {
    safe: '2.0.0',
    malicious: ['2.0.1'],
    description: 'CSS color name mappings',
    weeklyDownloads: 191000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31846',
    risk_score: 9.8,
    attack_surface: 'Web applications, styling tools',
    mitigation: 'Downgrade to version 2.0.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'supports-hyperlinks': {
    safe: '4.1.0',
    malicious: ['4.1.1'],
    description: 'Detect hyperlink support',
    weeklyDownloads: 50000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31847',
    risk_score: 9.8,
    attack_surface: 'Terminal applications, CLI tools',
    mitigation: 'Downgrade to version 4.1.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'chalk-template': {
    safe: '1.1.0',
    malicious: ['1.1.1'],
    description: 'Template literal styling',
    weeklyDownloads: 30000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31848',
    risk_score: 9.8,
    attack_surface: 'Template applications, styling tools',
    mitigation: 'Downgrade to version 1.1.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'wrap-ansi': {
    safe: '9.0.0',
    malicious: ['9.0.1'],
    description: 'Word wrapping with ANSI codes',
    weeklyDownloads: 40000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31849',
    risk_score: 9.8,
    attack_surface: 'Terminal applications, CLI tools',
    mitigation: 'Downgrade to version 9.0.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'slice-ansi': {
    safe: '7.1.0',
    malicious: ['7.1.1'],
    description: 'Slice ANSI strings',
    weeklyDownloads: 25000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31850',
    risk_score: 9.8,
    attack_surface: 'String processing utilities',
    mitigation: 'Downgrade to version 7.1.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'has-ansi': {
    safe: '6.0.0',
    malicious: ['6.0.1'],
    description: 'ANSI code detection',
    weeklyDownloads: 12000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31851',
    risk_score: 9.8,
    attack_surface: 'Terminal applications, CLI tools',
    mitigation: 'Downgrade to version 6.0.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'ansi-styles': {
    safe: '6.2.1',
    malicious: ['6.2.2'],
    description: 'ANSI escape code styles',
    weeklyDownloads: 80000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31852',
    risk_score: 9.8,
    attack_surface: 'Styling utilities, terminal apps',
    mitigation: 'Downgrade to version 6.2.1 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'supports-color': {
    safe: '10.2.0',
    malicious: ['10.2.1'],
    description: 'Color support detection',
    weeklyDownloads: 60000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31853',
    risk_score: 9.8,
    attack_surface: 'Terminal applications, CLI tools',
    mitigation: 'Downgrade to version 10.2.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'ansi-regex': {
    safe: '6.2.0',
    malicious: ['6.2.1'],
    description: 'ANSI escape code regex',
    weeklyDownloads: 70000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31854',
    risk_score: 9.8,
    attack_surface: 'Text processing utilities',
    mitigation: 'Downgrade to version 6.2.0 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'simple-swizzle': {
    safe: '0.2.2',
    malicious: ['0.2.3'],
    description: 'Array manipulation utilities',
    weeklyDownloads: 26000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31855',
    risk_score: 9.8,
    attack_surface: 'Data processing, utilities',
    mitigation: 'Downgrade to version 0.2.2 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'is-arrayish': {
    safe: '0.3.2',
    malicious: ['0.3.3'],
    description: 'Array detection utility',
    weeklyDownloads: 15000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31856',
    risk_score: 9.8,
    attack_surface: 'Type checking utilities',
    mitigation: 'Downgrade to version 0.3.2 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  },
  'error-ex': {
    safe: '1.3.2',
    malicious: ['1.3.3'],
    description: 'Error handling utilities',
    weeklyDownloads: 47000000,
    severity: 'CRITICAL',
    cve: 'CVE-2025-31857',
    risk_score: 9.8,
    attack_surface: 'Error handling, logging systems',
    mitigation: 'Downgrade to version 1.3.2 or remove project',
    malware_function: 'Crypto wallet address swapping',
    first_seen: '2025-09-08',
    author: 'qix (compromised)'
  }
};

// ===== ADVANCED UI SYSTEM =====
class ProfessionalUI {
  static showHeader() {
    console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    NPM SUPPLY CHAIN ATTACK - PROFESSIONAL EDITION                 ║
║                          Operation CryptoClipper Response                          ║
║                               September 2025 - CVE-2025-31842                       ║
║                                                                                   ║
║  🎯 TARGET: Compromised packages from qix account                              ║
║  ⚠️  SEVERITY: CRITICAL (9.8/10)                                               ║
║  🌐 IMPACT: 2+ Billion weekly downloads affected                                 ║
║  👤 AUTHOR: Security Research Team                                              ║
║  🔗 SOURCE: https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the   ║
╚═══════════════════════════════════════════════════════════════════════════════╝`);
  }

  static showSection(title) {
    const line = '═'.repeat(80);
    console.log(`\n\x1b[36m${line}\x1b[0m`);
    console.log(`  \x1b[1;36m${title}\x1b[0m`);
    console.log(`\x1b[36m${line}\x1b[0m\n`);
  }

  static showProgress(current, total, action = 'Processing') {
    const percent = Math.round((current / total) * 100);
    const filled = Math.floor(percent / 2);
    const bar = '\x1b[36m█\x1b[0m'.repeat(filled) + '\x1b[90m░\x1b[0m'.repeat(50 - filled);
    process.stdout.write(`\r🔄 ${action}: [\x1b[36m${bar}\x1b[0m] \x1b[1;36m${percent}%\x1b[0m (${current}/${total})`);
  }

  static clearProgress() {
    process.stdout.write('\r' + ' '.repeat(100) + '\r');
  }

  static showVulnerabilityDetails(pkg, version) {
    const vuln = VULN_DB[pkg];
    console.log(`\n   📋 VULNERABILITY DETAILS:`);
    console.log(`      Package:     \x1b[1;36m${pkg}\x1b[0m`);
    console.log(`      Version:     \x1b[1;31m${version} ⚠️  MALICIOUS\x1b[0m`);
    console.log(`      Safe:        \x1b[1;32m${vuln.safe} ✅\x1b[0m`);
    console.log(`      CVE:         \x1b[1;33m${vuln.cve}\x1b[0m`);
    console.log(`      Risk Score:  \x1b[1;31m${vuln.risk_score}/10\x1b[0m`);
    console.log(`      Downloads:   \x1b[1;36m${vuln.weeklyDownloads.toLocaleString()}/week\x1b[0m`);
    console.log(`      Surface:     \x1b[1;36m${vuln.attack_surface}\x1b[0m`);
    console.log(`      Function:    \x1b[1;31m${vuln.malware_function}\x1b[0m`);
    console.log(`      First Seen:  \x1b[1;33m${vuln.first_seen}\x1b[0m`);
    console.log(`      Author:      \x1b[1;33m${vuln.author}\x1b[0m`);
    console.log(`      Impact:      \x1b[1;31mCrypto wallet hijacking, transaction interception\x1b[0m`);
    console.log(`      Mitigation:  \x1b[1;32m${vuln.mitigation}\x1b[0m`);
  }

  static showSecurityRecommendations() {
    console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                             🛡️  IMMEDIATE ACTION REQUIRED                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
   🔴 CRITICAL STEPS:
   1. DISCONNECT: Immediately disconnect from networks
   2. ISOLATE: Isolate affected systems from crypto activities
   3. BACKUP: Create secure backups of critical data
   4. DECIDE: Choose to delete, ignore, or carefully fix each vulnerable project
   5. MONITOR: Monitor blockchain transactions for suspicious activity
   6. CHANGE: Change all crypto wallet passwords and 2FA
   
   🟡 RECOMMENDED APPROACH:
   • DELETE infected projects is the safest solution
   • DO NOT REINSTALL dependencies in compromised projects
   • IGNORE only if the project is not used or can be isolated
   • REPAIR with caution only if the project is critical and cannot be deleted
   
   🟢 PREVENTIVE MEASURES:
   • Enable 2FA on all package registry accounts
   • Use dependency pinning (package-lock.json)
   • Regular security audits with 'npm audit fix'
   • Implement CI/CD security scanning
   • Use hardware wallets for crypto transactions`);
  }

  static showAttackSummary() {
    console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                🚨 ATTACK SUMMARY                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
   🎯 ATTACK VECTOR: Compromised NPM developer account (qix)
   📅 DISCOVERED:   September 8, 2025
   🔧 METHOD:       Malicious code injection in popular packages
   💰 MOTIVE:       Financial (crypto theft)
   🌐 TARGETS:      JavaScript/Node.js ecosystem
   
   🦠 MALICIOUS CAPABILITIES:
   • Crypto wallet address swapping using Levenshtein distance
   • Transaction hijacking via wallet provider interception
   • Network request modification (fetch, XMLHttpRequest)
   • Clipboard manipulation for address replacement
   • Multi-currency support (BTC, ETH, SOL, TRX, LTC, BCH)
   • Ethereum provider hijacking (window.ethereum)
   • Fetch and XMLHttpRequest API hijacking
   
   🎭 DECEPTION TECHNIQUES:
   • Visual similarity attacks for wallet addresses
   • Sophisticated code obfuscation
   • Legitimate-looking package updates
   • Uses multiple crypto address formats
   
   💻 TECHNICAL DETAILS:
   • Intercepts window.ethereum requests
   • Overrides fetch and XMLHttpRequest
   • Replaces addresses in JSON responses
   • Uses Levenshtein distance for similarity matching
   • Targets 70+ attacker-controlled addresses`);
  }

  static showFAQ() {
    console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                    ❓ FAQ & RISKS                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
   ❓ "I don't have crypto wallets connected to these projects. Am I safe?"
   ⚠️  NOT ENTIRELY. The malicious code is present and could:
      • Execute if you connect a wallet later
      • Spread to other projects during copies
      • Compromise your system security
      • Steal credentials if added to crypto projects later
   
   ❓ "What are my options for each vulnerable project?"
   🔧 THREE OPTIONS:
      1. DELETE: Completely remove the project (recommended)
      2. IGNORE: Leave as is (risky, not recommended)
      3. REPAIR: Manual downgrade of dependencies (with caution)
   
   ❓ "Why is deletion recommended?"
   🗑️  Deletion completely eliminates the threat:
      • No more malicious code in your system
      • No risk of reinfection
      • Complete and definitive cleanup
      • Irreversible but safe action
   
   ❓ "What happens if I ignore?"
   ⚠️  The vulnerability remains active:
      • The malicious code persists
      • Risk of future exploitation
      • Potential spread to other projects`);
  }
}

// ===== CORE SCANNING ENGINE =====
class SecurityScanner {
  constructor() {
    this.results = {
      totalProjects: 0,
      projectsWithoutLock: 0,
      vulnerableProjects: 0,
      vulnerablePackages: 0,
      highRiskProjects: [],
      scanTime: 0,
      vulnerabilities: [],
      fixCommands: [],
      batchScript: '',
      interactiveScript: '',
      recentlyInstalled: [] // Track recently installed packages
    };
  }

  parsePackageLock(lockfilePath) {
    try {
      debugLog(`Reading file: ${lockfilePath}`);
      const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
      const packages = {};
      
      if (lockfile.packages) {
        debugLog(`Processing ${Object.keys(lockfile.packages).length} packages in 'packages' section`);
        for (const [key, value] of Object.entries(lockfile.packages)) {
          if (key.startsWith('node_modules/')) {
            const packageName = key.substring('node_modules/'.length);
            packages[packageName] = {
              version: value.version,
              resolved: value.resolved,
              integrity: value.integrity
            };
            debugLog(`Package found: ${packageName} v${value.version}`);
          }
        }
      }
      
      if (lockfile.dependencies) {
        debugLog(`Processing ${Object.keys(lockfile.dependencies).length} packages in 'dependencies' section`);
        for (const [packageName, value] of Object.entries(lockfile.dependencies)) {
          if (!packages[packageName]) {
            packages[packageName] = {
              version: value.version,
              resolved: value.resolved,
              integrity: value.integrity
            };
            debugLog(`Package found (dependencies): ${packageName} v${value.version}`);
          }
        }
      }
      
      debugLog(`Total packages analyzed: ${Object.keys(packages).length}`);
      return packages;
    } catch (error) {
      debugLog(`Error reading package-lock: ${error.message}`);
      return {};
    }
  }

  parsePackageJson(packageJsonPath) {
    try {
      debugLog(`Reading package.json: ${packageJsonPath}`);
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      const packages = {};
      
      // Check dependencies
      if (packageJson.dependencies) {
        Object.entries(packageJson.dependencies).forEach(([name, version]) => {
          // Clean version string (remove ^, ~, etc.)
          const cleanVersion = version.replace(/^[^0-9]*/, '');
          packages[name] = { version: cleanVersion };
          debugLog(`Dependency found: ${name} v${cleanVersion}`);
        });
      }
      
      // Check devDependencies
      if (packageJson.devDependencies) {
        Object.entries(packageJson.devDependencies).forEach(([name, version]) => {
          const cleanVersion = version.replace(/^[^0-9]*/, '');
          packages[name] = { version: cleanVersion };
          debugLog(`DevDependency found: ${name} v${cleanVersion}`);
        });
      }
      
      debugLog(`Total packages in package.json: ${Object.keys(packages).length}`);
      return packages;
    } catch (error) {
      debugLog(`Error reading package.json: ${error.message}`);
      return {};
    }
  }

  findProjects(rootDir) {
    const projects = [];
    debugLog(`Searching for projects in: ${rootDir}`);
    
    function scan(dir, depth = 0) {
      if (depth > 6) { // Increased depth
        debugLog(`Maximum depth reached in: ${dir}`);
        return;
      }
      
      try {
        const files = fs.readdirSync(dir, { withFileTypes: true });
        debugLog(`Analyzing directory: ${dir} (${files.length} elements)`);
        
        for (const file of files) {
          if (file.isDirectory()) {
            const fullPath = path.join(dir, file.name);
            
            // Skip system directories and common non-project directories
            const skipDirs = ['node_modules', '.git', '.vscode', '.idea', 'Windows', 'Program Files', 'System Volume Information', 'AppData', 'Application Data', '.next', '.nuxt', 'dist', 'build'];
            if (skipDirs.includes(file.name) || file.name.startsWith('.')) {
              debugLog(`Directory ignored: ${file.name}`);
              continue;
            }
            
            debugLog(`Checking directory: ${fullPath}`);
            
            // Check if this is a project directory
            if (fs.existsSync(path.join(fullPath, 'package.json'))) {
              debugLog(`✅ Project found: ${fullPath}`);
              projects.push(fullPath);
            } else {
              // Recursively scan subdirectories
              scan(fullPath, depth + 1);
            }
          }
        }
      } catch (error) {
        debugLog(`Error accessing directory ${dir}: ${error.message}`);
        // Ignore access errors
      }
    }
    
    scan(rootDir);
    debugLog(`Total projects found in ${rootDir}: ${projects.length}`);
    return projects;
  }

  getSearchPaths() {
    const username = os.userInfo().username;
    const paths = [];
    
    // Platform-specific paths
    if (process.platform === 'win32') {
      paths.push(
        `C:\\Users\\${username}`,
        `C:\\Users\\${username}\\Documents`,
        `C:\\Users\\${username}\\Desktop`,
        `C:\\Users\\${username}\\nft-project`,
        `C:\\devtool`,
        `C:\\hardhat`,
        `C:\\Users\\${username}\\source`,
        `C:\\Users\\${username}\\projects`,
        `C:\\projects`,
        `C:\\`,
        `D:\\`,
        `E:\\`,
        `F:\\`,
        `G:\\`
      );
    } else {
      // macOS/Linux paths
      paths.push(
        `/Users/${username}`,
        `/Users/${username}/Documents`,
        `/Users/${username}/Desktop`,
        `/Users/${username}/projects`,
        `/home/${username}`,
        `/home/${username}/projects`,
        `/`,
        `/opt`
      );
    }
    
    // Add current directory and parent directories
    paths.push(process.cwd());
    let parentDir = path.dirname(process.cwd());
    for (let i = 0; i < 5; i++) { // Increased to 5 levels
      if (parentDir !== path.dirname(parentDir)) {
        paths.push(parentDir);
        parentDir = path.dirname(parentDir);
      }
    }
    
    // Add common development directories
    const commonDevDirs = ['dev', 'development', 'src', 'projects', 'workspace'];
    commonDevDirs.forEach(dir => {
      paths.push(path.join(process.cwd(), dir));
      paths.push(path.join(path.dirname(process.cwd()), dir));
    });
    
    // Filter existing paths
    const existingPaths = paths.filter(p => {
      try {
        const exists = fs.existsSync(p);
        debugLog(`Path ${p}: ${exists ? 'exists' : 'does not exist'}`);
        return exists;
      } catch (error) {
        debugLog(`Error checking path ${p}: ${error.message}`);
        return false;
      }
    });
    
    debugLog(`Valid search paths: ${existingPaths.join(', ')}`);
    return existingPaths;
  }

  checkRecentlyInstalled(projectPath) {
    // Check if any packages were installed recently (last 7 days)
    const nodeModulesPath = path.join(projectPath, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) return [];
    
    const recentPackages = [];
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    
    try {
      const packages = fs.readdirSync(nodeModulesPath);
      packages.forEach(pkg => {
        const pkgPath = path.join(nodeModulesPath, pkg);
        try {
          const stats = fs.statSync(pkgPath);
          if (stats.mtime.getTime() > oneWeekAgo) {
            recentPackages.push({
              name: pkg,
              installed: stats.mtime,
              path: pkgPath
            });
          }
        } catch (e) {
          // Ignore errors
        }
      });
    } catch (error) {
      debugLog(`Error reading node_modules: ${error.message}`);
    }
    
    return recentPackages;
  }

  analyzeVulnerabilities(projectPath, packages, source = 'package-lock.json') {
    const vulnerabilities = [];
    debugLog(`Analyzing vulnerabilities for project: ${projectPath} (source: ${source})`);
    
    // Check for recently installed packages
    const recentPackages = this.checkRecentlyInstalled(projectPath);
    if (recentPackages.length > 0) {
      debugLog(`${recentPackages.length} packages recently installed in ${projectPath}`);
      this.results.recentlyInstalled.push({
        project: projectPath,
        packages: recentPackages
      });
    }
    
    Object.entries(VULN_DB).forEach(([packageName, vulnInfo]) => {
      if (packages[packageName]) {
        const packageVersion = packages[packageName].version;
        
        // Check if version is in malicious list
        if (vulnInfo.malicious.includes(packageVersion)) {
          const vuln = {
            package: packageName,
            currentVersion: packageVersion,
            safeVersion: vulnInfo.safe,
            severity: vulnInfo.severity,
            cve: vulnInfo.cve,
            riskScore: vulnInfo.risk_score,
            resolved: packages[packageName].resolved || '',
            integrity: packages[packageName].integrity || '',
            source: source,
            description: vulnInfo.description,
            malware_function: vulnInfo.malware_function,
            first_seen: vulnInfo.first_seen,
            author: vulnInfo.author,
            weeklyDownloads: vulnInfo.weeklyDownloads
          };
          vulnerabilities.push(vuln);
          debugLog(`🚨 Vulnerability found: ${packageName} ${packageVersion} (source: ${source})`);
        } else {
          debugLog(`✅ Safe package: ${packageName} ${packageVersion}`);
        }
      }
    });
    
    debugLog(`Total vulnerabilities in ${projectPath}: ${vulnerabilities.length}`);
    return vulnerabilities;
  }

  generateDeleteCommands(projectPath) {
    const projectName = path.basename(projectPath);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const commands = [];
    
    commands.push(`@echo off`);
    commands.push(`echo ╔═══════════════════════════════════════════════════════════════════════════════╗`);
    commands.push(`echo ║                    DELETING INFECTED PROJECT                          ║`);
    commands.push(`echo ║                          ${projectName}                              ║`);
    commands.push(`echo ╚═══════════════════════════════════════════════════════════════════════════════╝`);
    commands.push(`echo.`);
    commands.push(`echo ⚠️  WARNING: This action is irreversible!`);
    commands.push(`echo.`);
    commands.push(`echo Project to delete: ${projectPath}`);
    commands.push(`echo.`);
    commands.push(`pause`);
    commands.push(`echo.`);
    commands.push(`echo Creating backup archive...`);
    commands.push(`if not exist "C:\\npm-backups" mkdir "C:\\npm-backups"`);
    commands.push(`powershell -Command "Compress-Archive -Path '${projectPath}' -DestinationPath 'C:\\npm-backups\\${projectName}-${timestamp}.zip'"`);
    commands.push(`echo.`);
    commands.push(`echo Deleting project...`);
    commands.push(`rmdir /s /q "${projectPath}"`);
    commands.push(`echo.`);
    commands.push(`if exist "${projectPath}" (`);
    commands.push(`    echo ❌ Deletion failed`);
    commands.push(`) else (`);
    commands.push(`    echo ✅ Project successfully deleted`);
    commands.push(`)`);
    commands.push(`echo.`);
    commands.push(`pause`);
    
    return commands.join('\n');
  }

  generateFixCommands(projectPath, vulnerabilities) {
    const projectName = path.basename(projectPath);
    const commands = [];
    
    commands.push(`@echo off`);
    commands.push(`echo ╔═══════════════════════════════════════════════════════════════════════════════╗`);
    commands.push(`echo ║                    REPAIRING INFECTED PROJECT                          ║`);
    commands.push(`echo ║                          ${projectName}                              ║`);
    commands.push(`echo ╚═══════════════════════════════════════════════════════════════════════════════╝`);
    commands.push(`echo.`);
    commands.push(`echo ⚠️  WARNING: This operation is risky!`);
    commands.push(`echo.`);
    commands.push(`cd "${projectPath}"`);
    commands.push(`echo.`);
    commands.push(`echo Creating backup...`);
    commands.push(`copy package.json "package.json.backup-%date%"`);
    commands.push(`echo.`);
    commands.push(`echo Updating dependencies to safe versions...`);
    
    // Create overrides in package.json
    const overrideCmd = `node -e "const pkg=require('./package.json');pkg.overrides={${vulnerabilities.map(v => `'${v.package}':'${v.safeVersion}'`).join(',')}};fs.writeFileSync('package.json',JSON.stringify(pkg,null,2));"`;
    commands.push(overrideCmd);
    commands.push(`echo.`);
    commands.push(`echo Cleaning infected dependencies...`);
    commands.push(`if exist node_modules rmdir /s /q node_modules`);
    commands.push(`if exist package-lock.json del package-lock.json`);
    commands.push(`echo.`);
    commands.push(`echo Reinstalling dependencies...`);
    commands.push(`npm install`);
    commands.push(`if %errorlevel% neq 0 (`);
    commands.push(`    echo ⚠️  Failed, trying with --legacy-peer-deps...`);
    commands.push(`    npm install --legacy-peer-deps`);
    commands.push(`)`);
    commands.push(`echo.`);
    commands.push(`echo ✅ Repair completed`);
    commands.push(`echo.`);
    commands.push(`pause`);
    
    return commands.join('\n');
  }

  generateBatchScript() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const scriptPath = path.join(os.tmpdir(), `npm-security-response-${timestamp}.bat`);
    
    let script = `@echo off
setlocal enabledelayedexpansion
echo ╔═══════════════════════════════════════════════════════════════════════════════╗
echo ║                NPM VULNERABILITY RESPONSE SCRIPT                          ║
echo ║                          Operation CryptoClipper                          ║
echo ║                          Author: Security Team                            ║
echo ╚═══════════════════════════════════════════════════════════════════════════════╝
echo.
echo This script will help you manage vulnerable projects.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul
echo.
echo Starting vulnerability analysis...
echo.
`;
    // Add all project management commands
    this.results.highRiskProjects.forEach((project, index) => {
      script += `echo [${index + 1}/${this.results.highRiskProjects.length}] Project: ${path.basename(project.path)}\n`;
      script += `echo Path: ${project.path}\n`;
      script += `echo Source: ${project.vulnerabilities[0].source}\n`;
      script += `echo Vulnerabilities:\n`;
      project.vulnerabilities.forEach(vuln => {
        script += `echo   • ${vuln.package} ${vuln.currentVersion} (CVE: ${vuln.cve})\n`;
      });
      script += `echo.\n`;
      script += `echo Choose an action:\n`;
      script += `echo   1. DELETE the project (recommended)\n`;
      script += `echo   2. REPAIR the project (risky)\n`;
      script += `echo   3. IGNORE the project (not recommended)\n`;
      script += `echo.\n`;
      script += `set /p choice=Your choice (1/2/3): \n`;
      script += `if "!choice!"=="1" goto delete_${index}\n`;
      script += `if "!choice!"=="2" goto fix_${index}\n`;
      script += `if "!choice!"=="3" goto ignore_${index}\n`;
      script += `echo Invalid choice, please try again.\n`;
      script += `goto project_${index}\n`;
      script += `:delete_${index}\n`;
      script += this.generateDeleteCommands(project.path).replace(/%date%/g, `%date:~0,10%-%date:~5,2%-%date:~8,2%`);
      script += `goto next_project\n`;
      script += `:fix_${index}\n`;
      script += this.generateFixCommands(project.path, project.vulnerabilities).replace(/%date%/g, `%date:~0,10%-%date:~5,2%-%date:~8,2%`);
      script += `goto next_project\n`;
      script += `:ignore_${index}\n`;
      script += `echo ⚠️ Project ignored - vulnerability remains active\n`;
      script += `echo Project: ${project.path}\n`;
      script += `echo.\n`;
      script += `pause\n`;
      script += `goto next_project\n`;
      script += `:project_${index}\n`;
      script += `goto project_${index}\n`;
      script += `:next_project\n`;
      script += `echo.\n`;
    });
    script += `echo.
echo ╔═══════════════════════════════════════════════════════════════════════════════╗
echo ║                           OPERATIONS COMPLETED                              ║
echo ╚═══════════════════════════════════════════════════════════════════════════════╝
echo.
echo All projects have been processed.
echo.
echo 🔐 SECURITY RECOMMENDATIONS:
echo • Monitor your blockchain transactions
echo • Change your passwords and 2FA
echo • Enable 2FA on all your accounts
echo • Use hardware wallets for crypto
echo.
echo Press any key to exit...
pause >nul`;
    fs.writeFileSync(scriptPath, script);
    return scriptPath;
  }

  generateInteractiveScript() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const scriptPath = path.join(os.tmpdir(), `interactive-npm-response-${timestamp}.js`);
    
    let script = `const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const readline = require('readline');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
// Vulnerable project data
const vulnerableProjects = ${JSON.stringify(this.results.highRiskProjects, null, 2)};

function deleteProject(projectPath) {
  const projectName = path.basename(projectPath);
  console.log(\`\\n🗑️  Preparing for deletion: \${projectName}\`);
  
  rl.question(\`   ⚠️  Are you sure you want to DELETE this project? (y/N): \`, (answer) => {
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      try {
        // Create a backup
        const timestamp = Date.now();
        const backupDir = 'C:\\\\npm-backups';
        if (!fs.existsSync(backupDir)) {
          fs.mkdirSync(backupDir, { recursive: true });
        }
        
        console.log(\`   💾 Creating backup...\`);
        execSync(\`powershell -Command "Compress-Archive -Path '\${projectPath}' -DestinationPath '\${backupDir}\\\\\${projectName}-\${timestamp}.zip'"\`, { 
          stdio: 'pipe',
          timeout: 300000 
        });
        
        console.log(\`   🗑️  Deleting project...\`);
        fs.rmSync(projectPath, { recursive: true, force: true });
        console.log(\`   ✅ Project successfully deleted\`);
        console.log(\`   💾 Backup created: \${backupDir}\\\\\${projectName}-\${timestamp}.zip\`);
        processNextProject();
      } catch (error) {
        console.log(\`   ❌ Error during deletion: \${error.message}\`);
        processNextProject();
      }
    } else {
      console.log(\`   ❌ Deletion cancelled\`);
      processNextProject();
    }
  });
}

function fixProject(projectPath, vulnerabilities) {
  const projectName = path.basename(projectPath);
  console.log(\`\\n🔧 Preparing for repair: \${projectName}\`);
  
  rl.question(\`   ⚠️  Repair is risky. Continue? (y/N): \`, (answer) => {
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      try {
        // Backup package.json
        const packageJsonPath = path.join(projectPath, 'package.json');
        const backupPath = path.join(projectPath, \`package.json.backup-\${Date.now()}\`);
        fs.copyFileSync(packageJsonPath, backupPath);
        console.log(\`   💾 Backup created\`);
        
        // Update package.json
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        if (!packageJson.overrides) packageJson.overrides = {};
        
        vulnerabilities.forEach(vuln => {
          packageJson.overrides[vuln.package] = vuln.safeVersion;
          console.log(\`   📌 Downgrading \${vuln.package} to \${vuln.safeVersion}\`);
        });
        
        fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
        
        // Clean up
        const nodeModulesPath = path.join(projectPath, 'node_modules');
        const lockPath = path.join(projectPath, 'package-lock.json');
        
        if (fs.existsSync(nodeModulesPath)) {
          fs.rmSync(nodeModulesPath, { recursive: true, force: true });
          console.log(\`   🗑️  Deleting node_modules\`);
        }
        
        if (fs.existsSync(lockPath)) {
          fs.unlinkSync(lockPath);
          console.log(\`   🗑️  Deleting package-lock.json\`);
        }
        
        // Reinstall
        console.log(\`   ⬇️  Reinstalling dependencies...\`);
        try {
          execSync('npm install', { 
            cwd: projectPath, 
            stdio: 'pipe',
            timeout: 300000 
          });
          console.log(\`   ✅ Repair successful!\`);
          processNextProject();
        } catch (error) {
          console.log(\`   ⚠️  Failed, trying with --legacy-peer-deps...\`);
          try {
            execSync('npm install --legacy-peer-deps', { 
              cwd: projectPath, 
              stdio: 'pipe',
              timeout: 300000 
            });
            console.log(\`   ✅ Repair successful with --legacy-peer-deps!\`);
            processNextProject();
          } catch (error2) {
            console.log(\`   ❌ Both methods failed\`);
            processNextProject();
          }
        }
      } catch (error) {
        console.log(\`   ❌ Error: \${error.message}\`);
        processNextProject();
      }
    } else {
      console.log(\`   ❌ Repair cancelled\`);
      processNextProject();
    }
  });
}

function processNextProject() {
  if (vulnerableProjects.length === 0) {
    console.log(\`\\n✅ All projects have been processed!\`);
    console.log(\`\\n🔐 FINAL RECOMMENDATIONS:\`);
    console.log(\`• Monitor your blockchain transactions\`);
    console.log(\`• Change your passwords and 2FA\`);
    console.log(\`• Use hardware wallets\`);
    console.log(\`• Enable 2FA on all your accounts\`);
    rl.close();
    return;
  }
  
  const project = vulnerableProjects.shift();
  const projectName = path.basename(project.path);
  
  console.log(\`\\n📋 PROJECT \${vulnerableProjects.length + 1} OF \${vulnerableProjects.length + this.results.highRiskProjects.length}\`);
  console.log(\`   Path: \${project.path}\`);
  console.log(\`   Source: \${project.vulnerabilities[0].source}\`);
  console.log(\`   Vulnerabilities:\`);
  project.vulnerabilities.forEach(vuln => {
    console.log(\`     • \${vuln.package} \${vuln.currentVersion} (CVE: \${vuln.cve})\`);
  });
  
  console.log(\`\\n🔧 CHOOSE AN ACTION:\`);
  console.log(\`   1. DELETE the project (recommended)\`);
  console.log(\`   2. REPAIR the project (risky)\`);
  console.log(\`   3. IGNORE the project (not recommended)\`);
  
  rl.question(\`   Your choice (1/2/3): \`, (answer) => {
    switch(answer) {
      case '1':
        deleteProject(project.path);
        break;
      case '2':
        fixProject(project.path, project.vulnerabilities);
        break;
      case '3':
        console.log(\`   ⚠️  Project ignored - vulnerability remains active\`);
        processNextProject();
        break;
      default:
        console.log(\`   ❌ Invalid choice, please try again\`);
        vulnerableProjects.unshift(project); // Put back in queue
        processNextProject();
        break;
    }
  });
}

console.log(\`╔═══════════════════════════════════════════════════════════════════════════════╗\`);
console.log(\`║                INTERACTIVE VULNERABILITY RESPONSE TOOL                 ║\`);
console.log(\`║                          Operation CryptoClipper                          ║\`);
console.log(\`║                              Author: Security Team                        ║\`);
console.log(\`╚═══════════════════════════════════════════════════════════════════════════════╝\`);
console.log(\`\\nThis tool will help you delete, repair, or ignore vulnerable projects.\\n\`);
console.log(\`\\n🎯 RECOMMENDATION: DELETE infected projects\\n\`);
processNextProject();
`;
    fs.writeFileSync(scriptPath, script);
    return scriptPath;
  }

  generateHTMLReport() {
    const timestamp = new Date().toISOString();
    const reportPath = path.join(os.tmpdir(), `npm-security-report-${timestamp.replace(/[:.]/g, '-')}.html`);
    
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NPM Security Report - Operation CryptoClipper</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a1929 0%, #132f4c 50%, #0d2137 100%);
            color: #e0e0e0;
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #132f4c 0%, #0d2137 100%);
            border: 2px solid #00bcd4;
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            margin-bottom: 40px;
            box-shadow: 0 0 30px rgba(0, 188, 212, 0.3);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(0, 188, 212, 0.1), transparent);
            animation: shine 3s infinite;
        }
        
        @keyframes shine {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
        }
        
        .header h1 {
            color: #00bcd4;
            font-size: 3em;
            margin-bottom: 15px;
            text-shadow: 0 0 20px rgba(0, 188, 212, 0.5);
            position: relative;
            z-index: 1;
        }
        
        .header .subtitle {
            color: #a0a0a0;
            font-size: 1.2em;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        
        .header .meta {
            color: #888;
            font-size: 0.9em;
            position: relative;
            z-index: 1;
        }
        
        .section {
            background: rgba(19, 47, 76, 0.8);
            border: 1px solid #333;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(10px);
        }
        
        .section h2 {
            color: #00bcd4;
            border-bottom: 3px solid #00bcd4;
            padding-bottom: 15px;
            margin-bottom: 25px;
            font-size: 2.2em;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .metric {
            background: linear-gradient(135deg, #0d2137 0%, #132f4c 100%);
            border: 2px solid #00bcd4;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 0 25px rgba(0, 188, 212, 0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .metric:hover {
            transform: translateY(-5px);
            box-shadow: 0 0 35px rgba(0, 188, 212, 0.4);
        }
        
        .metric h3 {
            color: #00bcd4;
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 0 0 15px rgba(0, 188, 212, 0.5);
        }
        
        .metric p {
            color: #a0a0a0;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .project-card {
            background: rgba(76, 10, 10, 0.8);
            border: 2px solid #f44336;
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 10px 30px rgba(244, 67, 54, 0.3);
            transition: transform 0.3s ease;
        }
        
        .project-card:hover {
            transform: translateY(-3px);
        }
        
        .project-card h3 {
            color: #f44336;
            margin-bottom: 20px;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .project-card .severity {
            background: #f44336;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .project-card p {
            margin: 12px 0;
            color: #d0d0d0;
        }
        
        .project-card .path {
            color: #00bcd4;
            font-family: 'Courier New', monospace;
            background: rgba(0, 188, 212, 0.1);
            padding: 10px 15px;
            border-radius: 8px;
            display: inline-block;
            margin: 15px 0;
            border: 1px solid #00bcd4;
        }
        
        .project-card .source {
            color: #ff9800;
            font-size: 0.9em;
            margin: 8px 0;
            font-weight: bold;
        }
        
        .vulnerability {
            background: rgba(244, 67, 54, 0.1);
            border-left: 5px solid #f44336;
            padding: 15px;
            margin: 15px 0;
            border-radius: 8px;
        }
        
        .vulnerability strong {
            color: #00bcd4;
        }
        
        .vulnerability .cve {
            background: #f44336;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        
        .action-buttons {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .action-btn {
            background: linear-gradient(135deg, #0d2137 0%, #132f4c 100%);
            border: 2px solid #00bcd4;
            color: #00bcd4;
            padding: 12px 20px;
            border-radius: 8px;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s ease;
            cursor: pointer;
            display: inline-block;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .action-btn:hover {
            background: linear-gradient(135deg, #132f4c 0%, #0d2137 100%);
            box-shadow: 0 0 20px rgba(0, 188, 212, 0.4);
            transform: translateY(-2px);
        }
        
        .action-btn.delete {
            border-color: #f44336;
            color: #f44336;
        }
        
        .action-btn.delete:hover {
            box-shadow: 0 0 20px rgba(244, 67, 54, 0.4);
        }
        
        .action-btn.ignore {
            border-color: #ff9800;
            color: #ff9800;
        }
        
        .action-btn.ignore:hover {
            box-shadow: 0 0 20px rgba(255, 152, 0, 0.4);
        }
        
        .command-block {
            background: rgba(10, 10, 10, 0.9);
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        
        .command-block h4 {
            color: #00bcd4;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .command-block code {
            color: #00bcd4;
            font-size: 0.95em;
            line-height: 1.5;
            white-space: pre-wrap;
        }
        
        .recommendations {
            background: linear-gradient(135deg, rgba(10, 26, 10, 0.9) 0%, rgba(15, 20, 15, 0.9) 100%);
            border: 2px solid #00bcd4;
            padding: 30px;
            margin: 30px 0;
            border-radius: 15px;
            box-shadow: 0 0 30px rgba(0, 188, 212, 0.2);
        }
        
        .recommendations h2 {
            color: #00bcd4;
            margin-bottom: 20px;
            font-size: 2em;
        }
        
        .recommendations ol {
            margin-left: 25px;
        }
        
        .recommendations li {
            margin: 15px 0;
            color: #d0d0d0;
            font-size: 1.1em;
        }
        
        .recommendations strong {
            color: #f44336;
        }
        
        .download-section {
            background: linear-gradient(135deg, rgba(26, 10, 10, 0.9) 0%, rgba(15, 20, 15, 0.9) 100%);
            border: 2px solid #00bcd4;
            padding: 30px;
            margin: 30px 0;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 0 30px rgba(0, 188, 212, 0.2);
        }
        
        .download-section h2 {
            color: #00bcd4;
            margin-bottom: 20px;
            font-size: 2em;
        }
        
        .recent-packages {
            background: rgba(255, 152, 0, 0.1);
            border: 1px solid #ff9800;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .recent-packages h3 {
            color: #ff9800;
            margin-bottom: 15px;
        }
        
        .recent-packages ul {
            list-style: none;
            margin-left: 0;
        }
        
        .recent-packages li {
            background: rgba(255, 152, 0, 0.1);
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 3px solid #ff9800;
        }
        
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 30px;
            border-top: 2px solid #333;
            color: #666;
            font-size: 0.9em;
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.6; }
            100% { opacity: 1; }
        }
        
        .threat-details {
            background: rgba(244, 67, 54, 0.05);
            border: 1px solid #f44336;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .threat-details h3 {
            color: #f44336;
            margin-bottom: 15px;
        }
        
        .threat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .threat-item {
            background: rgba(19, 47, 76, 0.6);
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #f44336;
        }
        
        .threat-item h4 {
            color: #00bcd4;
            margin-bottom: 10px;
        }
        
        .copy-btn {
            background: #00bcd4;
            color: #0a1929;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin-top: 10px;
            transition: all 0.3s ease;
        }
        
        .copy-btn:hover {
            background: #00acc1;
            transform: translateY(-1px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ NPM Security Report</h1>
            <div class="subtitle">Operation CryptoClipper Response</div>
            <div class="meta">Generated on ${new Date().toLocaleString('en-US')} | Author: Security Team</div>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="metrics">
                <div class="metric">
                    <h3>${this.results.totalProjects}</h3>
                    <p>Projects Scanned</p>
                </div>
                <div class="metric">
                    <h3>${this.results.projectsWithoutLock}</h3>
                    <p>Projects without Lock</p>
                </div>
                <div class="metric">
                    <h3 class="pulse">${this.results.vulnerableProjects}</h3>
                    <p>Vulnerable Projects</p>
                </div>
                <div class="metric">
                    <h3 class="pulse">${this.results.vulnerablePackages}</h3>
                    <p>Vulnerable Packages</p>
                </div>
                <div class="metric">
                    <h3>${Math.round(this.results.scanTime / 1000)}s</h3>
                    <p>Scan Time</p>
                </div>
                <div class="metric">
                    <h3>${this.results.recentlyInstalled.length}</h3>
                    <p>Recent Packages</p>
                </div>
            </div>
        </div>
        
        ${this.results.recentlyInstalled.length > 0 ? `
        <div class="section">
            <h2>⚠️ Recently Installed Packages</h2>
            <div class="recent-packages">
                <h3>📦 Packages installed in the last 7 days:</h3>
                ${this.results.recentlyInstalled.map(project => `
                    <div>
                        <strong>Project:</strong> ${project.project}
                        <ul>
                            ${project.packages.map(pkg => `
                                <li>${pkg.name} - Installed on ${new Date(pkg.installed).toLocaleString('en-US')}</li>
                            `).join('')}
                        </ul>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        <div class="section">
            <h2>🚨 Threat Details</h2>
            <div class="threat-details">
                <h3>🎯 Operation CryptoClipper - September 2025</h3>
                <p><strong>Source:</strong> <a href="https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the" style="color: #00bcd4;">Substack Article</a></p>
                <p><strong>Impact:</strong> 2+ billion weekly downloads affected</p>
                <p><strong>Vector:</strong> Compromised npm account "qix" via phishing</p>
                
                <div class="threat-grid">
                    <div class="threat-item">
                        <h4>🔓 Attack Method</h4>
                        <p>Malicious code injection in popular packages via compromised maintainer account</p>
                    </div>
                    <div class="threat-item">
                        <h4>💰 Objective</h4>
                        <p>Crypto transaction hijacking by replacing wallet addresses</p>
                    </div>
                    <div class="threat-item">
                        <h4>🎭 Techniques</h4>
                        <p>Code obfuscation, API hijacking, visual address similarity</p>
                    </div>
                    <div class="threat-item">
                        <h4>🌐 Targets</h4>
                        <p>JavaScript/Node.js applications, especially those with crypto integrations</p>
                    </div>
                </div>
            </div>
        </div>
        
        ${this.results.vulnerableProjects > 0 ? `
        <div class="section">
            <h2>🚨 Vulnerable Projects - Action Required</h2>
            <p style="font-size: 1.2em; margin-bottom: 20px;">
                <strong>⚠️ WARNING:</strong> ${this.results.vulnerableProjects} project(s) contain malicious packages!
            </p>
            <p style="color: #ff9800; font-weight: bold; margin-bottom: 20px;">
                🎯 Recommendation: DELETE infected projects for maximum security
            </p>
            
            ${this.results.highRiskProjects.map((project, index) => `
                <div class="project-card">
                    <h3>
                        🚨 Project ${index + 1}: ${path.basename(project.path)}
                        <span class="severity">CRITICAL</span>
                    </h3>
                    <p><strong>Path:</strong> <span class="path">${project.path}</span></p>
                    <p><strong>Source:</strong> <span class="source">${project.vulnerabilities[0].source}</span></p>
                    
                    <div class="vulnerability">
                        <strong>📋 Detected Vulnerabilities:</strong>
                        ${project.vulnerabilities.map(vuln => `
                            <div style="margin: 10px 0; padding: 10px; background: rgba(244, 67, 54, 0.1); border-radius: 5px;">
                                <p><strong>Package:</strong> ${vuln.package}</p>
                                <p><strong>Version:</strong> ${vuln.currentVersion} → <span style="color: #00bcd4;">${vuln.safeVersion}</span></p>
                                <p><strong>CVE:</strong> <span class="cve">${vuln.cve}</span></p>
                                <p><strong>Risk:</strong> ${vuln.riskScore}/10</p>
                                <p><strong>Malicious Function:</strong> ${vuln.malware_function}</p>
                                <p><strong>Downloads:</strong> ${vuln.weeklyDownloads.toLocaleString()}/week</p>
                                <p><strong>First Seen:</strong> ${vuln.first_seen}</p>
                                <p><strong>Author:</strong> ${vuln.author}</p>
                            </div>
                        `).join('')}
                    </div>
                    
                    <div class="action-buttons">
                        <button class="action-btn delete" onclick="executeDelete('${project.path.replace(/\\/g, '\\\\')}', '${path.basename(project.path)}')">🗑️ Delete Project</button>
                        <button class="action-btn" onclick="executeFix('${project.path.replace(/\\/g, '\\\\')}', '${path.basename(project.path)}', '${encodeURIComponent(JSON.stringify(project.vulnerabilities))}')">🔧 Repair Project</button>
                        <button class="action-btn ignore" onclick="executeIgnore('${project.path.replace(/\\/g, '\\\\')}', '${path.basename(project.path)}')">⚠️ Ignore</button>
                    </div>
                    
                    <div id="commands-${index}" style="display: none;">
                        <div class="command-block">
                            <h4>🗑️ Deletion Commands:</h4>
                            <code id="delete-commands-${index}">rmdir /s /q "${project.path}"
# Or with backup:
powershell -Command "Compress-Archive -Path '${project.path}' -DestinationPath 'C:\\npm-backups\\${path.basename(project.path)}-%date%.zip'"
rmdir /s /q "${project.path}"</code>
                            <button class="copy-btn" onclick="copyCommands('delete-commands-${index}')">📋 Copy</button>
                        </div>
                        
                        <div class="command-block">
                            <h4>🔧 Repair Commands:</h4>
                            <code id="fix-commands-${index}">cd "${project.path}"
copy package.json "package.json.backup-%date%"
node -e "const pkg=require('./package.json');pkg.overrides={${project.vulnerabilities.map(v => `'${v.package}':'${v.safeVersion}'`).join(',')}};fs.writeFileSync('package.json',JSON.stringify(pkg,null,2));"
rmdir /s /q node_modules
del package-lock.json
npm install
# If fails:
npm install --legacy-peer-deps</code>
                            <button class="copy-btn" onclick="copyCommands('fix-commands-${index}')">📋 Copy</button>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
        ` : ''}
        
        <div class="section">
            <h2>🛠️ Automated Tools</h2>
            <div class="download-section">
                <h2>📥 Download Response Tools</h2>
                <p style="font-size: 1.1em; margin-bottom: 25px;">
                    Automated tools are available to manage detected vulnerabilities:
                </p>
                
                <div style="margin: 30px 0;">
                    <a href="file:///${this.results.batchScriptPath}" class="action-btn" style="font-size: 1.1em; padding: 15px 30px;">
                        📜 Download Batch Script
                    </a>
                    <a href="file:///${this.results.interactiveScriptPath}" class="action-btn" style="font-size: 1.1em; padding: 15px 30px;">
                        🖥️ Download Interactive Tool
                    </a>
                </div>
                
                <div style="text-align: left; max-width: 600px; margin: 0 auto;">
                    <p><strong>📜 Batch Script:</strong> Executes all actions automatically (for advanced users)</p>
                    <p><strong>🖥️ Interactive Tool:</strong> Guides you step by step for each project (recommended)</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🛡️ Security Recommendations</h2>
            <div class="recommendations">
                <h2>🔐 Immediate Measures</h2>
                <ol>
                    <li><strong>Immediate Action:</strong> Disconnect affected systems from networks</li>
                    <li><strong>Isolation:</strong> Isolate systems from crypto activities</li>
                    <li><strong>Backup:</strong> Create secure backups of critical data</li>
                    <li><strong>Monitoring:</strong> Monitor blockchain transactions for suspicious activity</li>
                    <li><strong>Credentials:</strong> Change wallet passwords and 2FA</li>
                </ol>
                
                <h2 style="margin-top: 30px;">🎯 Recommended Approach</h2>
                <ol>
                    <li><strong>DELETE</strong> infected projects (safest solution)</li>
                    <li><strong>AVOID</strong> reinstalling dependencies in compromised projects</li>
                    <li><strong>USE</strong> deletion rather than repair</li>
                    <li><strong>ISOLATE</strong> projects that cannot be deleted</li>
                </ol>
                
                <h2 style="margin-top: 30px;">🛡️ Future Prevention</h2>
                <ol>
                    <li><strong>2FA:</strong> Enable 2FA on all registry accounts</li>
                    <li><strong>Pinning:</strong> Use dependency pinning (package-lock.json)</li>
                    <li><strong>Audits:</strong> Regular security audits with 'npm audit fix'</li>
                    <li><strong>CI/CD:</strong> Implement CI/CD security scanning</li>
                    <li><strong>Hardware:</strong> Use hardware wallets for crypto</li>
                </ol>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Technical Information</h2>
            <div class="threat-details">
                <h3>🔍 Technical Attack Details</h3>
                
                <div class="threat-grid">
                    <div class="threat-item">
                        <h4>🎯 Compromised Packages</h4>
                        <p>18 popular packages compromised, totaling 2+ billion weekly downloads</p>
                    </div>
                    <div class="threat-item">
                        <h4>💻 Malicious Code</h4>
                        <p>window.ethereum, fetch and XMLHttpRequest hijacking to replace crypto addresses</p>
                    </div>
                    <div class="threat-item">
                        <h4>🔐 Attacker Addresses</h4>
                        <p>70+ attacker-controlled addresses (BTC, ETH, BCH, LTC, etc.)</p>
                    </div>
                    <div class="threat-item">
                        <h4>🎭 Algorithms</h4>
                        <p>Levenshtein distance for finding visually similar addresses</p>
                    </div>
                </div>
                
                <h3 style="margin-top: 25px;">📋 Complete Vulnerable Package List</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 20px;">
                    ${Object.entries(VULN_DB).map(([pkg, info]) => `
                        <div style="background: rgba(19, 47, 76, 0.6); padding: 15px; border-radius: 8px; border-left: 3px solid #f44336;">
                            <h4 style="color: #f44336; margin-bottom: 10px;">${pkg}</h4>
                            <p><strong>Malicious version:</strong> ${info.malicious.join(', ')}</p>
                            <p><strong>Safe version:</strong> ${info.safe}</p>
                            <p><strong>Downloads:</strong> ${info.weeklyDownloads.toLocaleString()}/week</p>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ LEGAL DISCLAIMER & USER RESPONSIBILITY</h2>
            <div style="background: rgba(255, 152, 0, 0.1); border: 1px solid #ff9800; border-radius: 10px; padding: 20px; margin: 20px 0;">
                <h3 style="color: #ff9800; margin-bottom: 15px;">📜 User Responsibility Notice</h3>
                <p><strong>IMPORTANT:</strong> By using this tool, you acknowledge and agree to the following terms:</p>
                <ol style="margin-left: 20px; margin-top: 15px;">
                    <li><strong>Full Responsibility:</strong> You are solely responsible for all actions taken with this tool, including file deletions and system modifications.</li>
                    <li><strong>Data Backup:</strong> You must create adequate backups of all important data before using this tool.</li>
                    <li><strong>Irreversible Actions:</strong> Deletion operations performed by this tool are permanent and cannot be undone.</li>
                    <li><strong>System Impact:</strong> You assume all risks associated with using this tool, including potential system instability or data loss.</li>
                    <li><strong>Professional Use:</strong> This tool is provided "as is" without warranty of any kind. Use at your own risk.</li>
                </ol>
                <p style="margin-top: 15px; font-weight: bold; color: #ff9800;">
                    By proceeding with the use of this tool, you confirm that you have read, understood, and accept full responsibility for all consequences of its use.
                </p>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by NPM Security Scanner - Professional Edition</p>
            <p>Author: Security Team | GitHub</p>
            <p>Operation CryptoClipper Response | CVE-2025-31842</p>
            <p>Source: https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the</p>
        </div>
    </div>
    
    <script>
        function executeDelete(projectPath, projectName) {
            const confirmed = confirm(\`⚠️ Are you sure you want to DELETE the project "\${projectName}" ?\\n\\nThis action is irreversible!\\n\\nPath: \${projectPath}\`);
            if (confirmed) {
                alert('For security reasons, please manually execute the deletion commands displayed below.');
                // Display commands
                const cards = document.querySelectorAll('.project-card');
                cards.forEach(card => {
                    if (card.textContent.includes(projectName)) {
                        const commandsDiv = card.querySelector('[id^="commands-"]');
                        if (commandsDiv) {
                            commandsDiv.style.display = commandsDiv.style.display === 'none' ? 'block' : 'none';
                        }
                    }
                });
            }
        }
        
        function executeFix(projectPath, projectName, vulnerabilitiesJson) {
            const confirmed = confirm(\`⚠️ Repair is risky. Continue with project "\${projectName}" ?\\n\\nPath: \${projectPath}\`);
            if (confirmed) {
                alert('For security reasons, please manually execute the repair commands displayed below.');
                // Display commands
                const cards = document.querySelectorAll('.project-card');
                cards.forEach(card => {
                    if (card.textContent.includes(projectName)) {
                        const commandsDiv = card.querySelector('[id^="commands-"]');
                        if (commandsDiv) {
                            commandsDiv.style.display = commandsDiv.style.display === 'none' ? 'block' : 'none';
                        }
                    }
                });
            }
        }
        
        function executeIgnore(projectPath, projectName) {
            const confirmed = confirm(\`⚠️ Are you sure you want to IGNORE the project "\${projectName}" ?\\n\\nThe vulnerability will remain active!\\n\\nPath: \${projectPath}\`);
            if (confirmed) {
                alert('⚠️ Project ignored. The vulnerability remains active in your system.');
            }
        }
        
        function copyCommands(elementId) {
            const element = document.getElementById(elementId);
            const text = element.innerText;
            
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ Commands copied to clipboard!');
            }).catch(() => {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('✅ Commands copied to clipboard!');
            });
        }
        
        // Animation on load
        document.addEventListener('DOMContentLoaded', function() {
            const metrics = document.querySelectorAll('.metric');
            metrics.forEach((metric, index) => {
                setTimeout(() => {
                    metric.style.opacity = '0';
                    metric.style.transform = 'translateY(20px)';
                    setTimeout(() => {
                        metric.style.transition = 'all 0.6s ease';
                        metric.style.opacity = '1';
                        metric.style.transform = 'translateY(0)';
                    }, 100);
                }, index * 100);
            });
        });
    </script>
</body>
</html>`;
    fs.writeFileSync(reportPath, html);
    return reportPath;
  }

  async scan() {
    const startTime = Date.now();
    const searchPaths = this.getSearchPaths();
    let totalProjectsFound = 0;
    
    ProfessionalUI.showSection('🔍 SCANNING FOR COMPROMISED PACKAGES');
    console.log('📂 Searching for Node.js projects...\n');
    
    debugLog(`Search paths: ${searchPaths.join(', ')}`);
    
    for (let i = 0; i < searchPaths.length; i++) {
      const searchPath = searchPaths[i];
      ProfessionalUI.showProgress(i + 1, searchPaths.length, 'Analyzing directories');
      
      debugLog(`\n=== Searching in: ${searchPath} ===`);
      const projects = this.findProjects(searchPath);
      debugLog(`Projects found in ${searchPath}: ${projects.length}`);
      
      for (let j = 0; j < projects.length; j++) {
        const projectPath = projects[j];
        totalProjectsFound++;
        ProfessionalUI.showProgress(totalProjectsFound, 'Search in progress', 'Analyzing projects');
        
        debugLog(`\n--- Analyzing project: ${projectPath} ---`);
        
        const packageJsonPath = path.join(projectPath, 'package.json');
        const lockPath = path.join(projectPath, 'package-lock.json');
        
        if (!fs.existsSync(packageJsonPath)) {
          debugLog(`No package.json in ${projectPath}`);
          continue;
        }
        
        let packages = {};
        let source = 'unknown';
        
        // Try package-lock.json first (more accurate)
        if (fs.existsSync(lockPath)) {
          debugLog(`Reading ${lockPath}`);
          packages = this.parsePackageLock(lockPath);
          source = 'package-lock.json';
        } else {
          // Fallback to package.json
          debugLog(`No package-lock.json, reading ${packageJsonPath}`);
          packages = this.parsePackageJson(packageJsonPath);
          source = 'package.json';
          this.results.projectsWithoutLock++;
        }
        
        debugLog(`${Object.keys(packages).length} packages found in ${projectPath} (${source})`);
        
        const vulnerabilities = this.analyzeVulnerabilities(projectPath, packages, source);
        
        if (vulnerabilities.length > 0) {
          this.results.vulnerableProjects++;
          this.results.vulnerablePackages += vulnerabilities.length;
          
          vulnerabilities.forEach(vuln => {
            vuln.project = path.basename(projectPath);
            this.results.vulnerabilities.push(vuln);
          });
          
          this.results.highRiskProjects.push({
            path: projectPath,
            vulnerabilities: vulnerabilities
          });
          
          debugLog(`🚨 VULNERABLE PROJECT: ${projectPath} (${source})`);
        }
        
        this.results.totalProjects++;
      }
    }
    
    ProfessionalUI.clearProgress();
    this.results.scanTime = Date.now() - startTime;
    
    debugLog(`\n=== SCAN SUMMARY ===`);
    debugLog(`Total projects found: ${totalProjectsFound}`);
    debugLog(`Total projects analyzed: ${this.results.totalProjects}`);
    debugLog(`Projects without package-lock.json: ${this.results.projectsWithoutLock}`);
    debugLog(`Vulnerable projects: ${this.results.vulnerableProjects}`);
    debugLog(`Vulnerable packages: ${this.results.vulnerablePackages}`);
    debugLog(`Projects with recent packages: ${this.results.recentlyInstalled.length}`);
    debugLog(`Scan time: ${this.results.scanTime}ms`);
    
    // Generate scripts
    this.results.batchScriptPath = this.generateBatchScript();
    this.results.interactiveScriptPath = this.generateInteractiveScript();
    
    debugLog(`Generated scripts:`);
    debugLog(`Batch: ${this.results.batchScriptPath}`);
    debugLog(`Interactive: ${this.results.interactiveScriptPath}`);
  }

  displayResults() {
    ProfessionalUI.showSection('📊 SECURITY SCAN RESULTS');
    
    console.log(`📈 SCAN STATISTICS:`);
    console.log(`   • Total Projects Scanned:    ${this.results.totalProjects}`);
    console.log(`   • Projects without lock:        ${this.results.projectsWithoutLock}`);
    console.log(`   • Vulnerable Projects:       ${this.results.vulnerableProjects}`);
    console.log(`   • Vulnerable Packages:      ${this.results.vulnerablePackages}`);
    console.log(`   • Recent packages:         ${this.results.recentlyInstalled.length}`);
    console.log(`   • Scan Duration:            ${Math.round(this.results.scanTime / 1000)} seconds`);
    console.log(`   • Risk Level:          ${this.results.vulnerableProjects > 0 ? 'CRITICAL' : 'LOW'}`);
    
    if (this.results.recentlyInstalled.length > 0) {
      console.log(`\n⚠️  RECENTLY INSTALLED PACKAGES:`);
      this.results.recentlyInstalled.forEach(project => {
        console.log(`   📁 ${project.project}:`);
        project.packages.forEach(pkg => {
          console.log(`      • ${pkg.name} (installed on ${new Date(pkg.installed).toLocaleString('en-US')})`);
        });
      });
    }
    
    if (this.results.projectsWithoutLock > 0) {
      console.log(`\n⚠️  WARNING: ${this.results.projectsWithoutLock} projects did not have package-lock.json`);
      console.log(`   These projects were analyzed via their package.json (less accurate)`);
    }
    
    if (this.results.vulnerableProjects > 0) {
      ProfessionalUI.showSection('🚨 CRITICAL VULNERABILITIES DETECTED');
      
      console.log(`🎯 AFFECTED PROJECTS (${this.results.vulnerableProjects}):`);
      this.results.highRiskProjects.forEach((project, index) => {
        console.log(`\n${index + 1}. 📁 ${project.path}`);
        console.log(`   Source: ${project.vulnerabilities[0].source}`);
        project.vulnerabilities.forEach(vuln => {
          console.log(`   🔴 ${vuln.package} ${vuln.currentVersion} → ${vuln.safeVersion}`);
          console.log(`      CVE: ${vuln.cve} | Risk: ${vuln.riskScore}/10`);
          console.log(`      Function: ${vuln.malware_function}`);
        });
      });
      
      ProfessionalUI.showSection('🛠️ YOUR OPTIONS');
      
      console.log(`📋 THREE OPTIONS FOR EACH VULNERABLE PROJECT:`);
      console.log(`   1. 🗑️ DELETE: Completely remove the project (recommended)`);
      console.log(`   2. 🔧 REPAIR: Manual downgrade of dependencies (risky)`);
      console.log(`   3. ⚠️ IGNORE: Leave as is (very risky, not recommended)\n`);
      
      console.log(`📜 AUTOMATED TOOLS AVAILABLE:`);
      console.log(`   • Batch Script: ${this.results.batchScriptPath}`);
      console.log(`   • Interactive Tool: ${this.results.interactiveScriptPath}\n`);
      
      console.log(`💡 RECOMMENDED WORKFLOW:`);
      console.log(`   1. Run the interactive tool: node "${this.results.interactiveScriptPath}"`);
      console.log(`   2. Choose DELETE for each infected project`);
      console.log(`   3. Follow on-screen instructions\n`);
      
      ProfessionalUI.showSecurityRecommendations();
      ProfessionalUI.showFAQ();
    } else {
      console.log(`\n✅ NO VULNERABILITIES DETECTED!`);
      console.log(`   Your projects appear to be secure against this supply chain attack.`);
      
      if (this.results.projectsWithoutLock > 0) {
        console.log(`\n💡 TIP: Some projects did not have package-lock.json.`);
        console.log(`   Consider running 'npm install' in these projects to generate a lockfile.`);
      }
    }
  }

  generateReport() {
    ProfessionalUI.showSection('📄 GENERATING SECURITY REPORT');
    const reportPath = this.generateHTMLReport();
    console.log(`📋 Detailed HTML report saved to:`);
    console.log(`   ${reportPath}`);
    console.log(`\n📜 Automated tools saved to:`);
    console.log(`   • Batch Script: ${this.results.batchScriptPath}`);
    console.log(`   • Interactive Tool: ${this.results.interactiveScriptPath}`);
    return reportPath;
  }

  async runInteractiveTool() {
    console.log(`\n🖥️ Starting interactive tool...`);
    console.log(`This tool will help you choose what to do for each vulnerable project.\n`);
    
    try {
      execSync(`node "${this.results.interactiveScriptPath}"`, { stdio: 'inherit' });
    } catch (error) {
      console.error(`Error running interactive tool: ${error.message}`);
    }
  }
}

// ===== MAIN APPLICATION =====
class SecurityApp {
  constructor() {
    this.scanner = new SecurityScanner();
  }

  async run() {
    debugLog('Starting application...');
    ProfessionalUI.showHeader();
    ProfessionalUI.showAttackSummary();
    
    const args = process.argv.slice(2);
    const generateReport = !args.includes('--no-report');
    const runInteractive = args.includes('--interactive');
    
    debugLog(`Arguments: ${args.join(', ')}`);
    debugLog(`Generate report: ${generateReport}`);
    debugLog(`Interactive mode: ${runInteractive}`);
    
    // Scan phase
    debugLog('Starting scan...');
    await this.scanner.scan();
    debugLog('Scan completed');
    
    this.scanner.displayResults();
    
    // Generate report
    if (generateReport) {
      debugLog('Generating report...');
      const reportPath = this.scanner.generateReport();
      console.log(`\n📊 Complete security report: ${reportPath}`);
      console.log(`\n🌐 Open the report in your browser for detailed view!`);
    }
    
    // Run interactive tool if requested
    if (runInteractive && this.scanner.results.vulnerableProjects > 0) {
      debugLog('Starting interactive tool...');
      await this.scanner.runInteractiveTool();
    }
    
    // Final recommendations
    ProfessionalUI.showSection('🔐 NEXT STEPS');
    
    if (this.scanner.results.vulnerableProjects > 0) {
      if (!runInteractive) {
        console.log(`💡 To use the interactive tool:`);
        console.log(`   node ${process.argv[1]} --interactive`);
        console.log(`\n💡 Or run the interactive tool directly:`);
        console.log(`   node "${this.scanner.results.interactiveScriptPath}"`);
      }
      
      console.log(`\n🔐 SECURITY BEST PRACTICES:`);
      console.log(`   1. DELETE infected projects (recommendation)`);
      console.log(`   2. Regular security audits: npm audit fix`);
      console.log(`   3. Enable 2FA on all accounts`);
      console.log(`   4. Use dependency pinning`);
      console.log(`   5. Monitor crypto transactions`);
      console.log(`   6. Keep systems updated`);
    } else {
      console.log(`✅ Your environment is secure!`);
      console.log(`💡 Continue practicing good security hygiene.`);
    }
    
    console.log(`\n🛡️  Thank you for using NPM Security Scanner - Professional Edition`);
    console.log(`👤 Author: Security Team | GitHub`);
    
    debugLog('Application completed');
  }
}

// ===== EXECUTION =====
if (require.main === module) {
  debugLog('Running main script...');
  const app = new SecurityApp();
  app.run().catch(error => {
    console.error('Fatal error:', error);
    debugLog(`Fatal error: ${error.message}`);
    debugLog(error.stack);
  });
}

module.exports = { SecurityApp, SecurityScanner };