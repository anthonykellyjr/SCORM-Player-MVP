#!/bin/bash

echo "=== OrthoSkool Post-Deployment Verification ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Navigate to project
cd /root/scorm-player || exit 1

echo "1. Checking file structure..."
if [ -f "client/index.html" ] && [ -f "client/player.html" ]; then
    echo -e "${GREEN}✓${NC} HTML files exist"
else
    echo -e "${RED}✗${NC} Missing HTML files"
    exit 1
fi

echo ""
echo "2. Checking for inline onclick handlers (should find NONE)..."
ONCLICK_COUNT=$(grep -c 'onclick=' client/index.html client/player.html 2>/dev/null || echo "0")
if [ "$ONCLICK_COUNT" -eq "0" ]; then
    echo -e "${GREEN}✓${NC} No inline onclick handlers found (Good!)"
else
    echo -e "${RED}✗${NC} Found $ONCLICK_COUNT inline onclick handlers (Bad!)"
    echo "   Files with onclick:"
    grep -l 'onclick=' client/*.html
fi

echo ""
echo "3. Checking token storage consistency..."
# Check player.html uses accessToken
if grep -q "localStorage.getItem('accessToken')" client/player.html; then
    echo -e "${GREEN}✓${NC} player.html uses 'accessToken'"
else
    echo -e "${RED}✗${NC} player.html still uses wrong token key"
fi

# Check index.html uses accessToken  
if grep -q "localStorage.getItem('accessToken')" client/index.html; then
    echo -e "${GREEN}✓${NC} index.html uses 'accessToken'"
else
    echo -e "${RED}✗${NC} index.html uses wrong token key"
fi

echo ""
echo "4. Checking users.json..."
if [ -f "server/data/users.json" ]; then
    USER_COUNT=$(jq '. | length' server/data/users.json 2>/dev/null)
    if [ "$?" -eq "0" ]; then
        echo -e "${GREEN}✓${NC} users.json is valid JSON with $USER_COUNT users"
        
        # Check for admin users
        ADMIN_COUNT=$(jq '[.[] | select(.role == "admin")] | length' server/data/users.json 2>/dev/null)
        echo -e "   Admins: $ADMIN_COUNT"
        
        # List admin emails
        echo "   Admin accounts:"
        jq -r '.[] | select(.role == "admin") | "     - \(.email)"' server/data/users.json 2>/dev/null
    else
        echo -e "${RED}✗${NC} users.json has invalid JSON"
    fi
else
    echo -e "${RED}✗${NC} users.json not found"
fi

echo ""
echo "5. Checking PM2 process..."
if command -v pm2 &> /dev/null; then
    if pm2 list | grep -q "scorm-player"; then
        STATUS=$(pm2 jlist | jq -r '.[] | select(.name == "scorm-player") | .pm2_env.status' 2>/dev/null)
        if [ "$STATUS" = "online" ]; then
            echo -e "${GREEN}✓${NC} PM2 process is running"
        else
            echo -e "${YELLOW}⚠${NC} PM2 process status: $STATUS"
        fi
    else
        echo -e "${RED}✗${NC} scorm-player not found in PM2"
    fi
else
    echo -e "${YELLOW}⚠${NC} PM2 not installed"
fi

echo ""
echo "6. Checking server port..."
if netstat -tuln | grep -q ':3000'; then
    echo -e "${GREEN}✓${NC} Server listening on port 3000"
else
    echo -e "${YELLOW}⚠${NC} Port 3000 not listening"
fi

echo ""
echo "7. Checking uploads directory..."
if [ -d "server/uploads" ]; then
    COURSE_COUNT=$(find server/uploads -mindepth 1 -maxdepth 1 -type d | wc -l)
    echo -e "${GREEN}✓${NC} Uploads directory exists"
    echo "   Courses uploaded: $COURSE_COUNT"
else
    echo -e "${YELLOW}⚠${NC} Uploads directory not found"
fi

echo ""
echo "8. Checking .env file..."
if [ -f ".env" ]; then
    if grep -q "JWT_SECRET" .env && grep -q "PORT" .env; then
        echo -e "${GREEN}✓${NC} .env file configured"
        
        # Check if using default JWT secret
        if grep -q "change-this-in-production" .env; then
            echo -e "${YELLOW}⚠${NC} WARNING: Still using default JWT secret!"
            echo "   Run: openssl rand -base64 32"
            echo "   Then update JWT_SECRET in .env"
        else
            echo -e "${GREEN}✓${NC} Custom JWT secret configured"
        fi
    else
        echo -e "${RED}✗${NC} .env file missing required variables"
    fi
else
    echo -e "${RED}✗${NC} .env file not found"
fi

echo ""
echo "=== Summary ==="
echo ""
echo "Next steps:"
echo "1. ${YELLOW}Test in browser:${NC} https://dev.orthoskool.com"
echo "2. ${YELLOW}Check browser console${NC} (F12) for any CSP errors"
echo "3. ${YELLOW}Test upload${NC} of a SCORM package"
echo "4. ${YELLOW}Test course launch${NC} and player"
echo ""
echo "If all tests pass:"
echo "✓ Authentication workflow is fixed"
echo "✓ Ready for security hardening phase"
echo ""