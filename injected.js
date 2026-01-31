// Injected script running in page context
// Author: OFJAAAH

(function() {
  'use strict';

  console.log('[OFJAAAH Scanner Pro] Injected script loaded');

  // Send package to content script
  function reportPackage(pkgName, source) {
    if (!pkgName || pkgName.length < 3) return;
    // Skip common packages and built-ins
    const skip = ['react', 'react-dom', 'lodash', 'express', 'jquery', 'vue', 'angular', 'axios'];
    if (skip.includes(pkgName.toLowerCase())) return;

    console.log('[OFJAAAH Scanner Pro] Found package:', pkgName);
    window.postMessage({
      type: 'DEPENDENCY_HUNTER_PACKAGE',
      package: pkgName,
      packageType: 'npm',
      source: source || window.location.href
    }, '*');
  }

  // Scan inline scripts for require/import statements
  function scanInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');

    scripts.forEach(script => {
      const content = script.textContent || '';

      // Find require() calls
      const requireMatches = content.matchAll(/require\s*\(\s*['"]([a-z0-9@][a-z0-9-_/]*)['"]\s*\)/gi);
      for (const match of requireMatches) {
        const pkgName = match[1].split('/')[0];
        reportPackage(pkgName, window.location.href);
      }

      // Find import statements
      const importMatches = content.matchAll(/import\s+(?:[\w{},\s*]+\s+from\s+)?['"]([a-z0-9@][a-z0-9-_/]*)['"]/gi);
      for (const match of importMatches) {
        const pkgName = match[1].split('/')[0];
        reportPackage(pkgName, window.location.href);
      }
    });
  }

  // Scan for embedded package.json data
  function scanEmbeddedPackageJson() {
    // Look for script tags with type="application/json"
    const jsonScripts = document.querySelectorAll('script[type="application/json"]');

    jsonScripts.forEach(script => {
      try {
        const data = JSON.parse(script.textContent);

        // Check if it looks like package.json
        if (data.dependencies || data.devDependencies) {
          console.log('[OFJAAAH Scanner Pro] Found embedded package.json');

          const allDeps = {
            ...data.dependencies,
            ...data.devDependencies,
            ...data.peerDependencies,
            ...data.optionalDependencies
          };

          Object.keys(allDeps).forEach(pkgName => {
            reportPackage(pkgName, window.location.href);
          });
        }
      } catch (e) {
        // Not valid JSON, ignore
      }
    });

    // Also check inline scripts that might have JSON
    const allScripts = document.querySelectorAll('script');
    allScripts.forEach(script => {
      const content = script.textContent || '';

      // Look for package.json-like patterns
      const jsonMatch = content.match(/"dependencies"\s*:\s*\{([^}]+)\}/);
      if (jsonMatch) {
        console.log('[OFJAAAH Scanner Pro] Found dependencies in inline script');
        const depsMatch = jsonMatch[1].matchAll(/"([a-z0-9@][a-z0-9-_/]*)"\s*:/gi);
        for (const match of depsMatch) {
          reportPackage(match[1], window.location.href);
        }
      }
    });
  }

  // Scan webpack modules
  function scanWebpackModules() {
    // Check __WEBPACK_MODULES__
    if (window.__WEBPACK_MODULES__) {
      console.log('[OFJAAAH Scanner Pro] Found __WEBPACK_MODULES__');
      Object.keys(window.__WEBPACK_MODULES__).forEach(key => {
        // Extract package name from node_modules path
        const match = key.match(/node_modules\/(@?[^\/]+(?:\/[^\/]+)?)/);
        if (match) {
          reportPackage(match[1], window.location.href);
        }
      });
    }

    // Check webpackJsonp
    if (window.webpackJsonp && Array.isArray(window.webpackJsonp)) {
      console.log('[OFJAAAH Scanner Pro] Found webpackJsonp');
      window.webpackJsonp.forEach(chunk => {
        if (chunk && chunk[1]) {
          Object.keys(chunk[1]).forEach(moduleId => {
            // Check if moduleId looks like a package name
            if (typeof moduleId === 'string' && moduleId.match(/^[a-z@][a-z0-9-_]*$/)) {
              reportPackage(moduleId, window.location.href);
            }
          });
        }
      });
    }

    // Monitor for future webpackJsonp pushes
    if (window.webpackJsonp) {
      const original = window.webpackJsonp.push;
      window.webpackJsonp.push = function(args) {
        if (args && args[1]) {
          Object.keys(args[1]).forEach(moduleId => {
            if (typeof moduleId === 'string' && moduleId.match(/^[a-z@][a-z0-9-_]*$/)) {
              reportPackage(moduleId, window.location.href);
            }

            // Also scan module content for requires
            const moduleStr = args[1][moduleId].toString();
            const requires = moduleStr.matchAll(/require\(['"]([^'"]+)['"]\)/g);
            for (const req of requires) {
              if (req[1] && !req[1].startsWith('.')) {
                reportPackage(req[1].split('/')[0], window.location.href);
              }
            }
          });
        }
        return original.apply(this, arguments);
      };
    }
  }

  // Scan HTML for node_modules references
  function scanHtmlContent() {
    const html = document.documentElement.outerHTML;

    // Find node_modules paths
    const nodeModulesMatches = html.matchAll(/node_modules\/(@?[a-z0-9][a-z0-9-_]*)/gi);
    for (const match of nodeModulesMatches) {
      reportPackage(match[1], window.location.href);
    }

    // Find webpack paths
    const webpackMatches = html.matchAll(/webpack:\/\/\/\.\/node_modules\/(@?[a-z0-9][a-z0-9-_]*)/gi);
    for (const match of webpackMatches) {
      reportPackage(match[1], window.location.href);
    }
  }

  // Intercept require/import calls if available
  function scanRequireCache() {
    if (typeof require !== 'undefined' && require.cache) {
      Object.keys(require.cache).forEach(module => {
        if (module.includes('node_modules')) {
          const parts = module.split('node_modules/');
          if (parts[1]) {
            const pkgName = parts[1].split('/')[0];
            reportPackage(pkgName, window.location.href);
          }
        }
      });
    }
  }

  // Main scan function
  function runScans() {
    console.log('[OFJAAAH Scanner Pro] Running all scans...');

    scanInlineScripts();
    scanEmbeddedPackageJson();
    scanWebpackModules();
    scanHtmlContent();
    scanRequireCache();

    console.log('[OFJAAAH Scanner Pro] Scans complete');
  }

  // Run immediately
  runScans();

  // Run again after DOM is fully loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(runScans, 500);
    });
  } else {
    setTimeout(runScans, 500);
  }

  // Run again after window load (for dynamic content)
  window.addEventListener('load', () => {
    setTimeout(runScans, 1000);
  });
})();
