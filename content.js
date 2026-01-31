// Dependency Confusion Hunter v1.4.0 - Content Script
// Author: OFJAAAH

(function() {
  'use strict';

  console.log('[Dependency Hunter v1.4.0] Content script loaded');

  // Track reported packages to avoid duplicates
  const reportedPackages = new Set();

  // Report package to background script
  function reportPackage(pkgName, pkgType, source, confidence = 70, context = {}) {
    if (!pkgName || pkgName.length < 2) return;

    // Normalize package name
    pkgName = pkgName.trim();

    const key = `${pkgType}:${pkgName}`;
    if (reportedPackages.has(key)) return;
    reportedPackages.add(key);

    console.log(`[Dependency Hunter] Reporting: ${pkgName} (${pkgType}) - ${confidence}% confidence`);

    try {
      chrome.runtime.sendMessage({
        action: 'checkPackage',
        package: pkgName,
        type: pkgType,
        source: source || window.location.href,
        confidence: confidence,
        context: context
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.debug('[Dependency Hunter] Message error:', chrome.runtime.lastError.message);
        }
      });
    } catch (e) {
      console.debug('[Dependency Hunter] Exception:', e.message);
    }
  }

  // =====================================================
  // NPM / Node.js Detection
  // =====================================================

  // Monitor all script tags in the page
  function scanPageScripts() {
    const scripts = document.querySelectorAll('script[src]');

    scripts.forEach(script => {
      const src = script.src;
      if (src && (src.endsWith('.js') || src.endsWith('.map'))) {
        try {
          chrome.runtime.sendMessage({
            action: 'analyzeUrl',
            url: src
          }, (response) => {
            if (chrome.runtime.lastError) {
              console.debug('[Dependency Hunter] Error:', chrome.runtime.lastError.message);
            }
          });
        } catch (e) {
          console.debug('[Dependency Hunter] Exception:', e.message);
        }
      }
    });
  }

  // Scan inline scripts for package references
  function scanInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');

    scripts.forEach(script => {
      const content = script.textContent || '';

      // Find require() calls - npm
      const requireMatches = content.matchAll(/require\s*\(\s*['"]([a-z0-9@][a-z0-9-_./]*)['"]\s*\)/gi);
      for (const match of requireMatches) {
        const pkgName = extractPackageName(match[1]);
        if (pkgName) reportPackage(pkgName, 'npm', window.location.href, 75);
      }

      // Find import statements - npm
      const importMatches = content.matchAll(/import\s+(?:[\w{},\s*]+\s+from\s+)?['"]([a-z0-9@][a-z0-9-_./]*)['"]/gi);
      for (const match of importMatches) {
        const pkgName = extractPackageName(match[1]);
        if (pkgName) reportPackage(pkgName, 'npm', window.location.href, 75);
      }

      // Find node_modules references - npm
      const nodeModulesMatches = content.matchAll(/node_modules\/(@?[a-z0-9][a-z0-9-_]*(?:\/[a-z0-9-_]+)?)/gi);
      for (const match of nodeModulesMatches) {
        const pkgName = extractPackageName(match[1]);
        if (pkgName) reportPackage(pkgName, 'npm', window.location.href, 90);
      }

      // Scan for Python imports - pip
      scanPythonImports(content);

      // Scan for Go imports - go
      scanGoImports(content);

      // Scan for PHP namespaces - composer
      scanPHPNamespaces(content);

      // Scan for Ruby requires - gem
      scanRubyRequires(content);

      // Scan for Rust crate imports - cargo
      scanRustImports(content);
    });
  }

  // Extract clean package name from path
  function extractPackageName(path) {
    if (!path) return null;

    // Handle scoped packages (@org/pkg)
    if (path.startsWith('@')) {
      const parts = path.split('/');
      if (parts.length >= 2) {
        return `${parts[0]}/${parts[1]}`;
      }
      return path;
    }

    // Handle regular packages
    return path.split('/')[0];
  }

  // =====================================================
  // Python/pip Detection
  // =====================================================

  function scanPythonImports(content) {
    // Skip if this looks like JavaScript code (has common JS patterns)
    if (isLikelyJavaScript(content)) {
      return;
    }

    // Only process if content looks like actual Python code
    if (!isLikelyPythonCode(content)) {
      return;
    }

    // Python import statements - more specific patterns
    // Only match if followed by Python-specific syntax
    const importPatterns = [
      // "from package import something" - must have actual Python syntax after
      /from\s+([a-z_][a-z0-9_]*)\s+import\s+[A-Za-z_*]/g,
      // Standalone "import package" at line start or after semicolon
      /(?:^|;|\n)\s*import\s+([a-z_][a-z0-9_]*)(?:\s*,|\s*$|\s*#|\s*;)/gm,
    ];

    importPatterns.forEach(pattern => {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const pkgName = match[1].toLowerCase();
        // Validate package name
        if (isValidPythonPackageName(pkgName) && !isPythonBuiltin(pkgName)) {
          reportPackage(pkgName, 'pip', window.location.href, 60);
        }
      }
    });

    // Look for requirements.txt patterns (more reliable)
    const requirementsPattern = /^([a-z][a-z0-9_-]*)(?:==|>=|<=|~=|!=|>|<|\[)/gm;
    const reqMatches = content.matchAll(requirementsPattern);
    for (const match of reqMatches) {
      const pkgName = match[1].toLowerCase();
      if (isValidPythonPackageName(pkgName) && !isPythonBuiltin(pkgName)) {
        reportPackage(pkgName, 'pip', window.location.href, 85);
      }
    }
  }

  function isLikelyJavaScript(content) {
    // Common JavaScript patterns that Python doesn't have
    const jsPatterns = [
      /\bfunction\s*\(/,           // function declarations
      /\bconst\s+\w+\s*=/,         // const declarations
      /\blet\s+\w+\s*=/,           // let declarations
      /\bvar\s+\w+\s*=/,           // var declarations
      /=>\s*{/,                     // arrow functions
      /\bclass\s+\w+\s*{/,         // JS class syntax
      /\bimport\s+.*\s+from\s+['"]/,  // ES6 imports (with 'from')
      /\bexport\s+(default\s+)?/,   // ES6 exports
      /React\./,                    // React
      /useState|useEffect/,         // React hooks
      /document\.|window\./,        // DOM/BOM
      /console\.(log|error|warn)/,  // console
      /\.querySelector/,            // DOM queries
      /\.addEventListener/,         // event listeners
      /\$\(/,                        // jQuery
      /require\s*\(\s*['"]/,        // CommonJS require
      /module\.exports/,            // CommonJS exports
    ];

    return jsPatterns.some(pattern => pattern.test(content));
  }

  function isLikelyPythonCode(content) {
    // Python-specific patterns
    const pythonPatterns = [
      /def\s+\w+\s*\([^)]*\)\s*:/,      // def function():
      /class\s+\w+\s*(?:\([^)]*\))?\s*:/, // class Foo: or class Foo(Bar):
      /if\s+.*:\s*$/m,                    // if condition:
      /for\s+\w+\s+in\s+.*:/,             // for x in y:
      /while\s+.*:\s*$/m,                 // while condition:
      /__init__|__main__|__name__/,        // Python dunders
      /print\s*\(/,                        // print()
      /\.py['"]/,                          // .py file references
      /requirements\.txt/i,                // requirements.txt reference
      /pip\s+install/i,                    // pip install reference
      /setup\.py/,                         // setup.py reference
    ];

    return pythonPatterns.some(pattern => pattern.test(content));
  }

  function isValidPythonPackageName(name) {
    // Python packages:
    // - Use lowercase
    // - Use underscores (not hyphens in import, but hyphens in package name)
    // - Don't use camelCase
    // - Usually 2-50 characters
    // - Not just numbers

    if (!name || name.length < 2 || name.length > 50) return false;

    // Reject camelCase (has lowercase followed by uppercase)
    if (/[a-z][A-Z]/.test(name)) return false;

    // Reject if it looks like a JavaScript variable name (mixedCase or concatenated words)
    if (/[a-z]{2,}[A-Z]/.test(name)) return false;

    // Must be all lowercase with underscores only
    if (!/^[a-z][a-z0-9_]*$/.test(name)) return false;

    // Reject common false positive patterns
    const falsePositives = new Set([
      'component', 'components', 'module', 'modules',
      'screen', 'screens', 'page', 'pages', 'view', 'views',
      'button', 'buttons', 'input', 'inputs', 'form', 'forms',
      'header', 'footer', 'sidebar', 'navbar', 'menu',
      'card', 'cards', 'list', 'item', 'items', 'container',
      'wrapper', 'layout', 'content', 'main', 'app',
      'demo', 'test', 'example', 'sample', 'temp',
      'loading', 'error', 'success', 'warning', 'info',
      'style', 'styles', 'theme', 'themes', 'color', 'colors',
      'utils', 'util', 'helper', 'helpers', 'lib', 'libs',
      'config', 'configs', 'settings', 'options', 'constants',
      'api', 'apis', 'service', 'services', 'store', 'stores',
      'action', 'actions', 'reducer', 'reducers', 'state', 'states',
      'type', 'types', 'interface', 'interfaces', 'model', 'models',
      'route', 'routes', 'router', 'navigation',
      'image', 'images', 'icon', 'icons', 'asset', 'assets',
      'data', 'index', 'default', 'null', 'undefined', 'true', 'false',
      'function', 'class', 'object', 'array', 'number', 'string', 'boolean',
    ]);

    if (falsePositives.has(name)) return false;

    return true;
  }

  function isPythonBuiltin(name) {
    const builtins = new Set([
      // Standard library modules
      'os', 'sys', 'json', 'time', 'datetime', 'math', 'random', 're',
      'collections', 'functools', 'itertools', 'typing', 'io', 'pathlib',
      'subprocess', 'threading', 'multiprocessing', 'socket', 'http',
      'urllib', 'logging', 'unittest', 'copy', 'string', 'enum', 'abc',
      'contextlib', 'dataclasses', 'pickle', 'hashlib', 'base64', 'struct',
      'argparse', 'configparser', 'csv', 'sqlite3', 'xml', 'html', 'email',
      'asyncio', 'concurrent', 'queue', 'select', 'signal', 'ssl', 'tempfile',
      'shutil', 'glob', 'fnmatch', 'stat', 'fileinput', 'linecache',
      'textwrap', 'difflib', 'pprint', 'reprlib', 'traceback', 'warnings',
      'weakref', 'array', 'bisect', 'heapq', 'decimal', 'fractions',
      'operator', 'inspect', 'dis', 'code', 'codeop', 'gc', 'types',
      'builtins', 'importlib', 'pkgutil', 'platform', 'uuid', 'secrets',
      'zipfile', 'tarfile', 'gzip', 'bz2', 'lzma', 'zlib',
      // Very common packages that exist publicly
      'numpy', 'pandas', 'requests', 'flask', 'django', 'pytest',
      'setuptools', 'pip', 'wheel', 'virtualenv', 'tox', 'sphinx',
      'matplotlib', 'scipy', 'sklearn', 'tensorflow', 'torch', 'keras',
    ]);
    return builtins.has(name);
  }

  // =====================================================
  // Go Modules Detection
  // =====================================================

  function scanGoImports(content) {
    // Go import statements
    const goImportPattern = /import\s*\(([^)]+)\)|import\s+"([^"]+)"/g;
    const matches = content.matchAll(goImportPattern);

    for (const match of matches) {
      const importBlock = match[1] || match[2];
      if (importBlock) {
        // Parse individual imports from block
        const imports = importBlock.matchAll(/"([^"]+)"/g);
        for (const imp of imports) {
          const path = imp[1];
          // Check if it's a third-party module (not stdlib)
          if (path && !isGoStdlib(path) && path.includes('/')) {
            // Extract the module path (e.g., github.com/user/pkg)
            const parts = path.split('/');
            if (parts.length >= 3) {
              const modulePath = parts.slice(0, 3).join('/');
              reportPackage(modulePath, 'go', window.location.href, 70);
            }
          }
        }
      }
    }

    // Look for go.mod content
    if (content.includes('module ') && content.includes('go ')) {
      const moduleMatch = content.match(/module\s+([^\s]+)/);
      if (moduleMatch) {
        reportPackage(moduleMatch[1], 'go', window.location.href, 95);
      }

      // Require statements in go.mod
      const requireMatches = content.matchAll(/require\s+([^\s]+)\s+v/g);
      for (const match of requireMatches) {
        reportPackage(match[1], 'go', window.location.href, 95);
      }
    }
  }

  function isGoStdlib(path) {
    const stdPrefixes = [
      'fmt', 'os', 'io', 'net', 'http', 'time', 'sync', 'strings', 'strconv',
      'encoding', 'crypto', 'database', 'html', 'image', 'log', 'math',
      'mime', 'path', 'reflect', 'regexp', 'sort', 'testing', 'text', 'unicode'
    ];
    const firstPart = path.split('/')[0];
    return stdPrefixes.includes(firstPart) || !path.includes('.');
  }

  // =====================================================
  // PHP/Composer Detection
  // =====================================================

  function scanPHPNamespaces(content) {
    // PHP namespace/use statements
    const phpPatterns = [
      /use\s+([A-Z][a-zA-Z0-9_]*(?:\\[A-Z][a-zA-Z0-9_]*)+)/g,
      /namespace\s+([A-Z][a-zA-Z0-9_]*(?:\\[A-Z][a-zA-Z0-9_]*)*)/g,
    ];

    phpPatterns.forEach(pattern => {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const namespace = match[1];
        // Convert namespace to Composer package name (vendor/package)
        const parts = namespace.split('\\');
        if (parts.length >= 2) {
          const vendor = parts[0].toLowerCase();
          const pkg = parts[1].toLowerCase();
          // Filter out common PHP built-ins
          if (!isPHPBuiltin(vendor)) {
            reportPackage(`${vendor}/${pkg}`, 'composer', window.location.href, 65);
          }
        }
      }
    });

    // Look for composer.json content
    if (content.includes('"require"') && content.includes('"name"')) {
      try {
        // Try to extract JSON-like content
        const jsonMatch = content.match(/\{[^{}]*"require"[^{}]*\}/s);
        if (jsonMatch) {
          const data = JSON.parse(jsonMatch[0]);
          if (data.require) {
            Object.keys(data.require).forEach(pkg => {
              if (pkg !== 'php' && !pkg.startsWith('ext-')) {
                reportPackage(pkg, 'composer', window.location.href, 95);
              }
            });
          }
        }
      } catch (e) {
        // Not valid JSON
      }
    }
  }

  function isPHPBuiltin(vendor) {
    const builtins = new Set(['php', 'psr', 'ext']);
    return builtins.has(vendor);
  }

  // =====================================================
  // Ruby/Gem Detection
  // =====================================================

  function scanRubyRequires(content) {
    // Ruby require statements
    const rubyPatterns = [
      /require\s+['"]([a-z][a-z0-9_-]*)['"]/gi,
      /gem\s+['"]([a-z][a-z0-9_-]*)['"]/gi,
    ];

    rubyPatterns.forEach(pattern => {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const gemName = match[1];
        if (!isRubyBuiltin(gemName)) {
          reportPackage(gemName, 'gem', window.location.href, 65);
        }
      }
    });

    // Look for Gemfile content
    if (content.includes("source 'https://rubygems.org'") || content.includes('source "https://rubygems.org"')) {
      const gemMatches = content.matchAll(/gem\s+['"]([^'"]+)['"]/g);
      for (const match of gemMatches) {
        reportPackage(match[1], 'gem', window.location.href, 95);
      }
    }
  }

  function isRubyBuiltin(name) {
    const builtins = new Set([
      'json', 'yaml', 'csv', 'net/http', 'uri', 'open-uri', 'fileutils',
      'tempfile', 'pathname', 'date', 'time', 'digest', 'base64', 'set'
    ]);
    return builtins.has(name);
  }

  // =====================================================
  // Rust/Cargo Detection
  // =====================================================

  function scanRustImports(content) {
    // Rust use/extern crate statements
    const rustPatterns = [
      /extern\s+crate\s+([a-z][a-z0-9_]*)/gi,
      /use\s+([a-z][a-z0-9_]*)::/gi,
    ];

    rustPatterns.forEach(pattern => {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const crateName = match[1];
        if (!isRustStdlib(crateName)) {
          reportPackage(crateName, 'cargo', window.location.href, 65);
        }
      }
    });

    // Look for Cargo.toml content
    if (content.includes('[package]') && content.includes('[dependencies]')) {
      const depSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
      if (depSection) {
        const depMatches = depSection[1].matchAll(/^([a-z][a-z0-9_-]*)\s*=/gim);
        for (const match of depMatches) {
          reportPackage(match[1], 'cargo', window.location.href, 95);
        }
      }
    }
  }

  function isRustStdlib(name) {
    const stdlib = new Set(['std', 'core', 'alloc', 'proc_macro', 'test']);
    return stdlib.has(name);
  }

  // =====================================================
  // Embedded Package Files Detection
  // =====================================================

  // Scan for embedded package.json
  function scanEmbeddedPackageJson() {
    const jsonScripts = document.querySelectorAll('script[type="application/json"]');

    jsonScripts.forEach(script => {
      try {
        const data = JSON.parse(script.textContent);

        if (data.dependencies || data.devDependencies) {
          console.log('[Dependency Hunter] Found embedded package.json');

          const allDeps = {
            ...data.dependencies,
            ...data.devDependencies,
            ...data.peerDependencies,
            ...data.optionalDependencies
          };

          Object.keys(allDeps).forEach(pkgName => {
            reportPackage(pkgName, 'npm', window.location.href, 95, {
              version: allDeps[pkgName],
              source: 'package.json'
            });
          });
        }
      } catch (e) {
        // Not valid JSON
      }
    });
  }

  // Scan page text for manifest file content
  function scanPageTextForManifests() {
    const pageText = document.body ? document.body.innerText : '';

    // Look for package.json-like content
    if (pageText.includes('"dependencies"') || pageText.includes('"devDependencies"')) {
      try {
        const jsonMatch = pageText.match(/\{[\s\S]*?"(?:dev)?[dD]ependencies"[\s\S]*?\}/);
        if (jsonMatch) {
          const data = JSON.parse(jsonMatch[0]);
          if (data.dependencies) {
            Object.keys(data.dependencies).forEach(pkg => {
              reportPackage(pkg, 'npm', window.location.href, 90);
            });
          }
          if (data.devDependencies) {
            Object.keys(data.devDependencies).forEach(pkg => {
              reportPackage(pkg, 'npm', window.location.href, 90);
            });
          }
        }
      } catch (e) {}
    }

    // Look for requirements.txt-like content
    const reqMatches = pageText.matchAll(/^([a-z][a-z0-9-_]*)(?:==|>=|<=|~=|!=)[0-9]/gim);
    for (const match of reqMatches) {
      reportPackage(match[1], 'pip', window.location.href, 85);
    }

    // Look for go.mod-like content
    if (pageText.includes('module ') && pageText.includes('go 1.')) {
      const goRequires = pageText.matchAll(/require\s+([^\s]+)\s+v[\d.]+/g);
      for (const match of goRequires) {
        reportPackage(match[1], 'go', window.location.href, 90);
      }
    }
  }

  // =====================================================
  // Dynamic Monitoring
  // =====================================================

  // Monitor dynamic script injections
  function monitorDynamicScripts() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE && node.tagName === 'SCRIPT') {
            if (node.src) {
              try {
                chrome.runtime.sendMessage({
                  action: 'analyzeUrl',
                  url: node.src
                });
              } catch (e) {}
            } else {
              // Scan inline script content
              const content = node.textContent || '';
              const requireMatches = content.matchAll(/require\s*\(\s*['"]([a-z0-9@][a-z0-9-_/]*)['"]\s*\)/gi);
              for (const match of requireMatches) {
                reportPackage(extractPackageName(match[1]), 'npm', window.location.href, 75);
              }
            }
          }
        });
      });
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  // Check for webpack/vite/bundler artifacts
  function scanBundlerArtifacts() {
    if (window.webpackJsonp || window.__webpack_require__) {
      console.log('[Dependency Hunter] Webpack detected');
    }

    const scripts = document.scripts;
    for (let script of scripts) {
      if (script.textContent && script.textContent.includes('//# sourceMappingURL=')) {
        const match = script.textContent.match(/\/\/# sourceMappingURL=([^\s]+)/);
        if (match && match[1]) {
          let mapUrl = match[1];
          if (!mapUrl.startsWith('http')) {
            mapUrl = new URL(mapUrl, window.location.href).href;
          }
          try {
            chrome.runtime.sendMessage({
              action: 'analyzeUrl',
              url: mapUrl
            });
          } catch (e) {}
        }
      }
    }
  }

  // Scan Performance API for resource timing
  function scanResourceTiming() {
    if (window.performance && window.performance.getEntriesByType) {
      const resources = window.performance.getEntriesByType('resource');

      resources.forEach(resource => {
        if (resource.name.match(/\.(js|map)(\?|$)/i)) {
          try {
            chrome.runtime.sendMessage({
              action: 'analyzeUrl',
              url: resource.name
            });
          } catch (e) {}
        }
      });
    }
  }

  // Extract package info from error stack traces
  function monitorErrorStacks() {
    window.addEventListener('error', (event) => {
      if (event.error && event.error.stack) {
        const stack = event.error.stack;
        const moduleMatches = stack.match(/node_modules\/([^\/\s]+)/g);
        if (moduleMatches) {
          moduleMatches.forEach(match => {
            const pkg = match.replace('node_modules/', '');
            reportPackage(pkg, 'npm', window.location.href, 80);
          });
        }
      }
    });
  }

  // Inject script to access page context
  function injectPageContextScript() {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('injected.js');
    (document.head || document.documentElement).appendChild(script);
    script.onload = () => script.remove();
  }

  // Listen for messages from injected script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data.type === 'DEPENDENCY_HUNTER_PACKAGE') {
      reportPackage(event.data.package, event.data.packageType, event.data.source, event.data.confidence || 70);
    }
  });

  // =====================================================
  // Initialization
  // =====================================================

  function init() {
    console.log('[Dependency Hunter] Initializing scanners...');

    // Run scanners
    scanPageScripts();
    scanInlineScripts();
    scanEmbeddedPackageJson();
    scanBundlerArtifacts();
    scanResourceTiming();
    scanPageTextForManifests();

    // Setup monitors
    monitorDynamicScripts();
    monitorErrorStacks();

    // Inject page context script
    injectPageContextScript();

    // Rescan after page loads
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
          scanPageScripts();
          scanInlineScripts();
          scanEmbeddedPackageJson();
          scanBundlerArtifacts();
          scanResourceTiming();
          scanPageTextForManifests();
        }, 1000);
      });
    }

    // Also scan after full load
    window.addEventListener('load', () => {
      setTimeout(() => {
        scanInlineScripts();
        scanEmbeddedPackageJson();
        scanPageTextForManifests();
      }, 1500);
    });
  }

  // Start
  init();
})();
