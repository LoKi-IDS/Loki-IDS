#!/bin/bash
# Quick test script for local testing

set -e

API_BASE="http://localhost:8080/api"

echo "======================================================"
echo "  Quick Test Script - Loki IDS Web Interface"
echo "======================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test functions
test_endpoint() {
    local name=$1
    local endpoint=$2
    local method=${3:-GET}
    
    echo -n "Testing $name... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$API_BASE$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$API_BASE$endpoint")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo -e "${GREEN}✓${NC} (HTTP $http_code)"
        return 0
    else
        echo -e "${RED}✗${NC} (HTTP $http_code)"
        echo "  Response: $body"
        return 1
    fi
}

# Check if server is running
echo "Checking if web interface is running..."
if ! curl -s "$API_BASE/system/health" > /dev/null; then
    echo -e "${RED}✗ Web interface is not running!${NC}"
    echo "  Start it with: cd Web-Interface && venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8080"
    exit 1
fi
echo -e "${GREEN}✓ Web interface is running${NC}"
echo ""

# Test endpoints
echo "Testing API endpoints..."
echo ""

test_endpoint "Health Check" "/system/health"
test_endpoint "System Status" "/system/status"
test_endpoint "Statistics" "/stats"
test_endpoint "Alerts List" "/alerts?page=1&page_size=10"
test_endpoint "Signatures List" "/signatures"
test_endpoint "Blacklist List" "/blacklist"

echo ""
echo "Testing data operations..."

# Add test signature
echo -n "Adding test signature... "
sig_response=$(curl -s -X POST "$API_BASE/signatures" \
    -H "Content-Type: application/json" \
    -d '{"name":"Quick Test Signature","pattern":"QUICK_TEST_123","action":"alert","description":"Quick test"}')

if echo "$sig_response" | grep -q "id"; then
    echo -e "${GREEN}✓${NC}"
    SIG_ID=$(echo "$sig_response" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
else
    echo -e "${YELLOW}⚠${NC} (may already exist)"
fi

# Add test IP to blacklist
echo -n "Adding test IP to blacklist... "
bl_response=$(curl -s -X POST "$API_BASE/blacklist" \
    -H "Content-Type: application/json" \
    -d '{"ip_address":"192.168.1.200","reason":"Quick test"}')

if echo "$bl_response" | grep -q "id"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}⚠${NC} (may already exist)"
fi

echo ""
echo "======================================================"
echo "  Test Summary"
echo "======================================================"
echo ""
echo "✓ Basic API tests completed"
echo ""
echo "Next steps:"
echo "  1. Check dashboard: http://localhost:8080"
echo "  2. Start IDS: sudo python3 Web-Interface/run_ids_with_integration.py"
echo "  3. Setup iptables: sudo ./Scripts/iptables_up.sh"
echo "  4. Generate test traffic to trigger alerts"
echo ""
echo "For complete testing guide, see: TESTING_GUIDE.md"
echo ""


