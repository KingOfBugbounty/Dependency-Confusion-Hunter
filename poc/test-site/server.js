#!/usr/bin/env node

/**
 * Dependency Confusion Hunter - Test Server
 * Author: OFJAAAH
 *
 * Serves the vulnerable test site on port 9999
 * Run: node server.js
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 9999;
const HOST = '127.0.0.1';

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);

  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, filePath);

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404);
        res.end('File not found');
      } else {
        res.writeHead(500);
        res.end('Server error');
      }
    } else {
      // Add CORS headers for extension access
      res.writeHead(200, {
        'Content-Type': contentType,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      res.end(content);
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  Dependency Confusion Hunter - Test Server                    ║');
  console.log('║  Author: OFJAAAH                                             ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  Server running at: http://${HOST}:${PORT}                    ║`);
  console.log('║                                                               ║');
  console.log('║  Open this URL in your browser to test the extension.        ║');
  console.log('║  The extension will detect the vulnerable packages.          ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
});

process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  server.close();
  process.exit(0);
});
