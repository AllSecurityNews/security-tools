#!/bin/bash
#
# Security Header Audit - Check HTTP security headers for any domain
#
# Checks for the presence and configuration of security-critical HTTP headers.
# No dependencies beyond curl and bash.
#
# Usage:
#   ./header_audit.sh example.com
#   ./header_audit.sh https://example.com
#
# Part of AllSecurityNews.com open source security tools
# https://github.com/AllSecurityNews/security-tools

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

TARGET="$1"

# Add https if no protocol specified
if [[ ! "$TARGET" =~ ^https?:// ]]; then
    TARGET="https://$TARGET"
fi

echo ""
echo -e "${CYAN}Security Header Audit${NC}"
echo -e "${CYAN}Target: ${TARGET}${NC}"
echo "======================================"
echo ""

# Fetch headers
HEADERS=$(curl -sI -L --max-time 10 "$TARGET" 2>/dev/null)

if [ -z "$HEADERS" ]; then
    echo -e "${RED}Error: Could not connect to $TARGET${NC}"
    exit 1
fi

# Show HTTP status
STATUS=$(echo "$HEADERS" | grep -i "^HTTP/" | tail -1 | tr -d '\r')
echo -e "Status: ${CYAN}${STATUS}${NC}"
echo ""

PASS=0
WARN=0
FAIL=0

check_header() {
    local name="$1"
    local description="$2"
    local value

    value=$(echo "$HEADERS" | grep -i "^${name}:" | tail -1 | sed "s/^${name}: *//i" | tr -d '\r')

    if [ -n "$value" ]; then
        echo -e "${GREEN}[PASS]${NC} ${name}"
        echo "       ${value}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[FAIL]${NC} ${name}"
        echo "       Missing - ${description}"
        FAIL=$((FAIL + 1))
    fi
}

check_header "Strict-Transport-Security" "Enforces HTTPS. Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
check_header "Content-Security-Policy" "Prevents XSS/injection. Define allowed content sources"
check_header "X-Content-Type-Options" "Prevents MIME sniffing. Add: X-Content-Type-Options: nosniff"
check_header "X-Frame-Options" "Prevents clickjacking. Add: X-Frame-Options: DENY or SAMEORIGIN"
check_header "Referrer-Policy" "Controls referrer info. Add: Referrer-Policy: strict-origin-when-cross-origin"
check_header "Permissions-Policy" "Controls browser features like camera, mic, geolocation"
check_header "X-XSS-Protection" "Legacy XSS filter. Add: X-XSS-Protection: 0 (rely on CSP instead)"

echo ""

# Check for headers that should NOT be present
SERVER=$(echo "$HEADERS" | grep -i "^Server:" | tail -1 | sed 's/^Server: *//i' | tr -d '\r')
if [ -n "$SERVER" ]; then
    echo -e "${YELLOW}[INFO]${NC} Server header exposes: ${SERVER}"
    echo "       Consider removing or minimizing this header"
    WARN=$((WARN + 1))
fi

POWERED=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | tail -1 | sed 's/^X-Powered-By: *//i' | tr -d '\r')
if [ -n "$POWERED" ]; then
    echo -e "${YELLOW}[WARN]${NC} X-Powered-By exposes: ${POWERED}"
    echo "       Remove this header to reduce attack surface"
    WARN=$((WARN + 1))
fi

# Summary
TOTAL=$((PASS + FAIL))
echo ""
echo "======================================"
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} (${TOTAL} headers checked)"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}All security headers present.${NC}"
elif [ "$FAIL" -le 2 ]; then
    echo -e "${YELLOW}Good, but a few headers are missing.${NC}"
else
    echo -e "${RED}Multiple security headers missing. Review your server configuration.${NC}"
fi

echo ""
echo "Learn more: https://allsecuritynews.com/hub/cheatsheets"
echo ""
