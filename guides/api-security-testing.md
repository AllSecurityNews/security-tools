# API Security Testing

A practical guide to finding and fixing API vulnerabilities. Covers the OWASP API Top 10, hands-on testing techniques with curl, Burp Suite, and Postman, and runtime protection strategies.

---

## Table of Contents

1. [OWASP API Top 10 Overview](#owasp-api-top-10-overview)
2. [BOLA: Broken Object Level Authorization](#bola-broken-object-level-authorization)
3. [Authentication and Authorization Testing](#authentication-and-authorization-testing)
4. [Rate Limiting and Abuse Prevention](#rate-limiting-and-abuse-prevention)
5. [API Discovery and Inventory](#api-discovery-and-inventory)
6. [Testing with curl, Burp, and Postman](#testing-with-curl-burp-and-postman)
7. [Runtime API Protection](#runtime-api-protection)

---

## OWASP API Top 10 Overview

The OWASP API Security Top 10 (2023 edition) is the standard reference for API vulnerabilities. Here is each category with a plain explanation of what goes wrong and how to test for it.

| # | Vulnerability | What Goes Wrong |
|---|--------------|----------------|
| API1 | Broken Object Level Authorization (BOLA) | User A can access User B's data by changing an ID in the request. |
| API2 | Broken Authentication | Weak login, missing MFA, tokens that never expire, credential stuffing. |
| API3 | Broken Object Property Level Authorization | API returns fields the user should not see (e.g., `isAdmin`, `ssn`), or accepts fields it should not (mass assignment). |
| API4 | Unrestricted Resource Consumption | No rate limits. An attacker can make millions of requests, run up your cloud bill, or DoS the service. |
| API5 | Broken Function Level Authorization | Regular user can call admin endpoints by guessing the URL. |
| API6 | Unrestricted Access to Sensitive Business Flows | Bots abuse purchase, reservation, or signup flows because there are no anti-automation controls. |
| API7 | Server-Side Request Forgery (SSRF) | API accepts a URL parameter and fetches it server-side, letting attackers reach internal services. |
| API8 | Security Misconfiguration | Debug mode enabled in production, default credentials, verbose error messages, missing CORS restrictions. |
| API9 | Improper Inventory Management | Old API versions still running, undocumented endpoints, shadow APIs. |
| API10 | Unsafe Consumption of APIs | Your API trusts data from third-party APIs without validation. |

---

## BOLA: Broken Object Level Authorization

BOLA (also called IDOR, Insecure Direct Object Reference) is the #1 API vulnerability. It is simple to exploit and extremely common.

### How It Works

Your API has an endpoint like `GET /api/users/1234/orders`. User A is authenticated and requests their own orders. But what happens if User A changes the ID to 1235? If they get User B's orders, that is BOLA.

### Testing for BOLA

**Step 1: Create two test accounts.**

```bash
# Register User A
curl -X POST https://api.example.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "usera@test.com", "password": "TestPass123!"}'

# Register User B
curl -X POST https://api.example.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "userb@test.com", "password": "TestPass456!"}'
```

**Step 2: Authenticate as User A and get a token.**

```bash
# Login as User A
TOKEN_A=$(curl -s -X POST https://api.example.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "usera@test.com", "password": "TestPass123!"}' \
  | jq -r '.token')

echo "User A token: $TOKEN_A"
```

**Step 3: Access User A's own resources (should work).**

```bash
# Get User A's profile -- should return 200
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN_A" \
  https://api.example.com/api/users/1001/profile
# Expected: 200
```

**Step 4: Access User B's resources with User A's token (should fail).**

```bash
# Try to access User B's profile with User A's token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN_A" \
  https://api.example.com/api/users/1002/profile
# Expected: 403 Forbidden
# If you get 200, you have a BOLA vulnerability
```

**Step 5: Test across all ID-based endpoints.**

```bash
# Automated BOLA check across multiple endpoints
USER_A_ID=1001
USER_B_ID=1002

ENDPOINTS=(
  "/api/users/USERID/profile"
  "/api/users/USERID/orders"
  "/api/users/USERID/settings"
  "/api/users/USERID/billing"
  "/api/users/USERID/documents"
)

for endpoint in "${ENDPOINTS[@]}"; do
  target="${endpoint//USERID/$USER_B_ID}"
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_A" \
    "https://api.example.com${target}")
  if [ "$status" = "200" ]; then
    echo "BOLA FOUND: $target returned $status"
  else
    echo "OK: $target returned $status"
  fi
done
```

### BOLA Variants to Test

| Variant | Example |
|---------|---------|
| Sequential IDs | Change `/users/100` to `/users/101` |
| UUIDs | Enumerate UUIDs from other responses (list endpoints, logs, etc.) |
| Nested resources | `/orgs/1/users/5` -- change both the org ID and user ID |
| File references | `/api/documents/report-1234.pdf` -- change the filename |
| GraphQL | `query { user(id: "1002") { email } }` -- change the argument |

### Fix

Every endpoint that takes an object ID must verify the authenticated user is authorized to access that specific object. Do not just check "is the user logged in." Check "does this user own (or have permission to) this specific resource."

---

## Authentication and Authorization Testing

### Token Testing

```bash
# Test 1: Expired token -- should be rejected
# Use a known-expired JWT
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjAwMDAwMDAwfQ.invalid" \
  https://api.example.com/api/me
# Expected: 401

# Test 2: No token -- should be rejected
curl -s -o /dev/null -w "%{http_code}" \
  https://api.example.com/api/me
# Expected: 401

# Test 3: Malformed token -- should be rejected
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer not-a-real-token" \
  https://api.example.com/api/me
# Expected: 401

# Test 4: Token after logout -- should be rejected
# First logout
curl -X POST -H "Authorization: Bearer $TOKEN_A" \
  https://api.example.com/auth/logout

# Then try using the same token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN_A" \
  https://api.example.com/api/me
# Expected: 401 (if server properly invalidates tokens)

# Test 5: JWT algorithm confusion
# Decode the token header
echo "$TOKEN_A" | cut -d. -f1 | base64 -d 2>/dev/null
# Check if the API accepts "alg": "none" or "alg": "HS256" when RS256 is expected
```

### JWT-Specific Tests

```bash
# Decode a JWT (without verification) to inspect claims
echo "$TOKEN_A" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Check for sensitive data in the token payload
# Tokens should NOT contain passwords, SSNs, or secrets
# They should contain: sub, exp, iat, iss, and maybe roles

# Test: modify the "role" claim and re-encode
# If the server does not verify the signature, this works (critical vulnerability)
# Use jwt.io or jwt_tool for this
```

### Privilege Escalation

```bash
# Test: regular user accessing admin endpoints
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  https://api.example.com/api/admin/users
# Expected: 403

# Test: regular user performing admin actions
curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  https://api.example.com/api/admin/users/1001
# Expected: 403

# Test: mass assignment -- try to set admin flag via user update
curl -s -X PATCH \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Normal User", "role": "admin", "isAdmin": true}' \
  https://api.example.com/api/users/me
# Expected: role and isAdmin fields should be ignored
```

### Password Reset Testing

```bash
# Test: password reset token reuse
# Request a reset
curl -X POST https://api.example.com/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "usera@test.com"}'

# Use the reset token (from email)
curl -X POST https://api.example.com/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN_HERE", "password": "NewPassword123!"}'

# Try using the same reset token again (should fail)
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://api.example.com/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN_HERE", "password": "AnotherPassword456!"}'
# Expected: 400 or 401 (token should be single-use)
```

---

## Rate Limiting and Abuse Prevention

### Testing Rate Limits

```bash
# Simple rate limit test: send 100 requests in quick succession
for i in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    https://api.example.com/api/search?q=test)
  echo "Request $i: $status"
  if [ "$status" = "429" ]; then
    echo "Rate limited at request $i"
    break
  fi
done

# Check rate limit headers
curl -s -D - https://api.example.com/api/search?q=test | grep -i 'rate\|limit\|retry\|x-ratelimit'
# Look for: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After
```

### Login Brute Force Testing

```bash
# Test: is login rate-limited?
for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://api.example.com/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"usera@test.com\", \"password\": \"wrong-$i\"}")
  echo "Attempt $i: $status"
done
# After 5-10 attempts, you should see 429 or account lockout
# If you get 401 for all 20, the login is not rate-limited (vulnerability)
```

### What to Rate Limit

| Endpoint Type | Suggested Limit | Why |
|--------------|----------------|-----|
| Login | 5/minute per IP+account | Credential stuffing |
| Password reset | 3/hour per email | Email bombing |
| Registration | 5/hour per IP | Fake account spam |
| Search | 30/minute per user | Resource exhaustion |
| File upload | 10/minute per user | Storage abuse |
| API-wide (authenticated) | 1000/hour per user | General abuse |
| API-wide (unauthenticated) | 100/hour per IP | Scraping |

### Bypass Techniques to Test

Attackers try to bypass rate limits. Test these:

```bash
# Test: IP rotation via headers (some apps trust these)
curl -H "X-Forwarded-For: 1.2.3.4" https://api.example.com/auth/login -d '...'
curl -H "X-Forwarded-For: 5.6.7.8" https://api.example.com/auth/login -d '...'
# If rate limit resets per X-Forwarded-For, that is a bypass

# Test: case variation in email
curl -X POST https://api.example.com/auth/login -d '{"email":"User@test.com","password":"wrong"}'
curl -X POST https://api.example.com/auth/login -d '{"email":"user@TEST.com","password":"wrong"}'
# Rate limit should apply to the normalized email, not the raw string

# Test: adding whitespace or special characters
curl -X POST https://api.example.com/auth/login -d '{"email":" usera@test.com","password":"wrong"}'
```

---

## API Discovery and Inventory

You cannot secure APIs you do not know about. Shadow APIs (undocumented endpoints) are a major risk.

### Passive Discovery

```bash
# Check for OpenAPI/Swagger documentation
curl -s https://api.example.com/swagger.json | jq '.paths | keys'
curl -s https://api.example.com/openapi.json | jq '.paths | keys'
curl -s https://api.example.com/v2/api-docs | jq '.paths | keys'
curl -s https://api.example.com/api/docs

# Check for GraphQL introspection
curl -s -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}' | jq .
# If this returns the full schema, introspection is enabled (disable in production)

# Check robots.txt and sitemap for API paths
curl -s https://example.com/robots.txt
curl -s https://example.com/sitemap.xml
```

### Active Discovery

```bash
# Brute-force common API paths with ffuf
# Install: https://github.com/ffuf/ffuf
ffuf -u https://api.example.com/api/FUZZ \
  -w /usr/share/wordlists/api-endpoints.txt \
  -mc 200,201,301,302,403 \
  -H "Authorization: Bearer $TOKEN"

# Common API paths to check manually
PATHS=(
  "/api/v1" "/api/v2" "/api/v3"
  "/api/internal" "/api/admin" "/api/debug"
  "/api/health" "/api/status" "/api/metrics"
  "/api/graphql" "/api/graphiql"
  "/api/config" "/api/env" "/api/info"
  "/.well-known/openapi.json"
  "/actuator" "/actuator/env" "/actuator/health"  # Spring Boot
  "/_debug" "/_profiler"  # Django/Symfony
)

for path in "${PATHS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://api.example.com${path}")
  if [ "$status" != "404" ]; then
    echo "FOUND: $path -> $status"
  fi
done
```

### API Versioning Checks

```bash
# Test for old API versions that might lack security fixes
for version in v1 v2 v3 v4 v5; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.example.com/api/${version}/users/me" \
    -H "Authorization: Bearer $TOKEN")
  if [ "$status" != "404" ]; then
    echo "API ${version} is live: $status"
  fi
done
# If v1 is still running and lacks auth checks that v3 has, that is a vulnerability
```

---

## Testing with curl, Burp, and Postman

### curl Recipes for API Testing

**Injection testing:**

```bash
# SQL injection in query parameter
curl -s "https://api.example.com/api/users?id=1'%20OR%201=1--" \
  -H "Authorization: Bearer $TOKEN"

# SQL injection in JSON body
curl -s -X POST https://api.example.com/api/search \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "test\" OR 1=1 --"}'

# NoSQL injection (MongoDB)
curl -s -X POST https://api.example.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": {"$gt": ""}, "password": {"$gt": ""}}'
# If this logs you in, the API is vulnerable to NoSQL injection

# XSS in API input (stored XSS via API)
curl -s -X POST https://api.example.com/api/comments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"body": "<script>alert(1)</script>"}'
# Then check if the script tag is returned unescaped in responses
```

**SSRF testing:**

```bash
# Test URL parameters for SSRF
curl -s -X POST https://api.example.com/api/fetch-url \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
# If you get AWS metadata back, that is SSRF

# Test with internal IPs
curl -s -X POST https://api.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://localhost:8080/admin"}'

# Test with DNS rebinding
curl -s -X POST https://api.example.com/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://your-rebind-domain.com/"}'
```

**CORS testing:**

```bash
# Check CORS headers
curl -s -D - -H "Origin: https://evil.com" \
  https://api.example.com/api/users/me | grep -i 'access-control'

# If you see: Access-Control-Allow-Origin: https://evil.com
# with Access-Control-Allow-Credentials: true
# That is a critical CORS misconfiguration

# Test with null origin
curl -s -D - -H "Origin: null" \
  https://api.example.com/api/users/me | grep -i 'access-control'
```

**Content type testing:**

```bash
# Test: does the API accept unexpected content types?
# Some APIs parse XML even when they expect JSON (XXE vulnerability)
curl -s -X POST https://api.example.com/api/data \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Test: what happens with no Content-Type?
curl -s -X POST https://api.example.com/api/data \
  -d '{"key": "value"}'
```

### Burp Suite Setup for API Testing

1. **Configure Burp as a proxy:** Set your browser or HTTP client to use `127.0.0.1:8080`.

2. **Import your API collection:** Load an OpenAPI spec or Postman collection into Burp.

3. **Useful Burp extensions for API testing:**
   - **Autorize** -- Automated BOLA/IDOR testing. Replays every request with a lower-privilege token.
   - **JSON Web Tokens** -- Decode, modify, and attack JWTs.
   - **Param Miner** -- Discovers hidden parameters.
   - **InQL** -- GraphQL introspection and query building.
   - **Logger++** -- Enhanced request/response logging.

4. **Autorize workflow (BOLA testing):**
   - Install Autorize from the BApp Store.
   - Set the "low privilege" token (User B's token).
   - Browse the API as User A (high privilege).
   - Autorize replays every request with User B's token.
   - Green = enforced, Red = BOLA vulnerability.

### Postman Testing Workflows

**Pre-request scripts for automated auth:**

```javascript
// Pre-request script: auto-login and set token
const loginRequest = {
    url: pm.environment.get("base_url") + "/auth/login",
    method: "POST",
    header: { "Content-Type": "application/json" },
    body: {
        mode: "raw",
        raw: JSON.stringify({
            email: pm.environment.get("test_email"),
            password: pm.environment.get("test_password")
        })
    }
};

pm.sendRequest(loginRequest, (err, res) => {
    const token = res.json().token;
    pm.environment.set("auth_token", token);
});
```

**Test scripts for automated validation:**

```javascript
// Test: response should not contain sensitive fields
pm.test("No sensitive data in response", () => {
    const body = pm.response.json();
    pm.expect(body).to.not.have.property("password");
    pm.expect(body).to.not.have.property("ssn");
    pm.expect(body).to.not.have.property("credit_card");
    pm.expect(body).to.not.have.property("secret");
});

// Test: proper status code for unauthorized access
pm.test("Returns 403 for unauthorized access", () => {
    pm.response.to.have.status(403);
});

// Test: rate limit headers present
pm.test("Rate limit headers exist", () => {
    pm.response.to.have.header("X-RateLimit-Limit");
    pm.response.to.have.header("X-RateLimit-Remaining");
});
```

---

## Runtime API Protection

Testing finds vulnerabilities before production. Runtime protection catches attacks in production.

### API Gateway Security Headers

```nginx
# Nginx API gateway security headers
server {
    listen 443 ssl;
    server_name api.example.com;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Cache-Control "no-store" always;

    # Limit request body size
    client_max_body_size 10m;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
    }

    location /auth/login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }
}
```

### Input Validation at the Gateway

```yaml
# Kong API Gateway rate limiting plugin (declarative config)
plugins:
  - name: rate-limiting
    config:
      minute: 60
      policy: redis
      redis_host: redis
      redis_port: 6379

  - name: request-size-limiting
    config:
      allowed_payload_size: 10    # MB

  - name: ip-restriction
    config:
      deny:
        - 203.0.113.0/24          # Known malicious range

  - name: bot-detection
    config:
      deny:
        - "curl"                   # Block raw curl in production (optional)
        - "python-requests"
```

### API Logging for Security

Log these fields for every API request. You need them for incident response.

| Field | Why |
|-------|-----|
| Timestamp | Incident timeline |
| Client IP | Attribution, rate limiting |
| User ID | Who made the request |
| HTTP method + path | What they did |
| Request body hash | Detect replay attacks |
| Response status code | Success vs. failure patterns |
| Response time | Detect abuse (slow queries) |
| User-Agent | Bot detection |
| Request ID | Correlation across services |

```python
# Python/Flask example: structured API logging
import logging
import json
import time
import uuid

@app.before_request
def log_request():
    request.start_time = time.time()
    request.request_id = str(uuid.uuid4())

@app.after_request
def log_response(response):
    log_entry = {
        "timestamp": time.time(),
        "request_id": request.request_id,
        "client_ip": request.remote_addr,
        "user_id": getattr(current_user, "id", None),
        "method": request.method,
        "path": request.path,
        "status": response.status_code,
        "duration_ms": round((time.time() - request.start_time) * 1000, 2),
        "user_agent": request.user_agent.string,
    }
    logging.info(json.dumps(log_entry))
    response.headers["X-Request-ID"] = request.request_id
    return response
```

### Anomaly Detection Indicators

Watch for these patterns in API logs:

| Pattern | What It Might Mean |
|---------|-------------------|
| 100+ 401s from one IP in 5 minutes | Credential stuffing |
| Sequential ID enumeration | BOLA exploitation |
| Requests to undocumented endpoints | Reconnaissance |
| Unusual User-Agent strings | Automated tooling |
| Requests at 3 AM from a user who normally works 9-5 | Compromised account |
| Large response sizes | Data exfiltration |
| Spike in 500 errors | Injection attacks or fuzzing |

---

## Quick Reference: API Security Testing Checklist

- [ ] BOLA tested across all object-ID endpoints with cross-user tokens
- [ ] Authentication tested: expired tokens, no token, malformed tokens, post-logout tokens
- [ ] JWT algorithm and signature verified (no "alg: none" accepted)
- [ ] Privilege escalation tested: regular user hitting admin endpoints
- [ ] Mass assignment tested: submitting unexpected fields (role, isAdmin)
- [ ] Rate limits verified on login, registration, password reset, and search
- [ ] Rate limit bypass techniques tested (X-Forwarded-For, email case variation)
- [ ] API inventory documented (no shadow APIs)
- [ ] Old API versions decommissioned or equally secured
- [ ] GraphQL introspection disabled in production
- [ ] CORS policy verified (no wildcard with credentials)
- [ ] SSRF tested on all URL-accepting parameters
- [ ] Input validation tested (SQL injection, NoSQL injection, XSS)
- [ ] Security headers present (HSTS, X-Content-Type-Options, etc.)
- [ ] Structured logging capturing all security-relevant fields
- [ ] Error messages do not leak internal details (stack traces, SQL errors)

---

*From [AllSecurityNews.com](https://allsecuritynews.com)*
