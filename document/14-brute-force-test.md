# 14 - Brute Force Test

## TC-BF: Brute Force Attack Testing & Rate Limiting

---

## Tổng quan

| Thuộc tính | Chi tiết |
|-----------|---------|
| **Objective** | Kiểm tra Rate Limiting chặn brute force tấn công login |
| **Tool** | Hydra, curl, Burp Suite Intruder |
| **WAF Protection** | Custom Rule: RateLimitLogin (> 10 req/30s → Block) |
| **Endpoint** | `POST /rest/user/login` |
| **Expected Result** | IP bị block sau 10 requests trong 30 giây |

---

## 1. Cấu hình Rate Limit Rule

WAF Custom Rule đã được cấu hình ở `07-waf-configuration.md`:

```json
{
  "name": "RateLimitLogin",
  "priority": 20,
  "ruleType": "RateLimitRule",
  "rateLimitDuration": "OneMin",
  "rateLimitThreshold": 10,
  "action": "Block",
  "matchConditions": [
    {
      "matchVariable": "RequestUri",
      "operator": "Contains",
      "matchValues": ["/rest/user/login"]
    }
  ]
}
```

---

## 2. TC-BF-01: Brute Force với Hydra

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-BF-01 |
| **Priority** | High |
| **Tool** | Hydra 9.x |
| **Target** | `POST /rest/user/login` |

### Chuẩn bị Wordlist

```bash
# Tạo password wordlist nhỏ cho lab
cat > /tmp/passwords.txt << 'EOF'
password
123456
admin
juice
letmein
qwerty
abc123
password123
juiceshop
admin123
P@ssw0rd
Welcome1
EOF

# Tạo username list
cat > /tmp/users.txt << 'EOF'
admin@juice-sh.op
jim@juice-sh.op
bender@juice-sh.op
user@juice-sh.op
test@test.com
EOF
```

### Test Steps — Phase 1: Baseline (không có Rate Limiting)

```bash
export TARGET_IP="40.x.x.x"

# Hydra HTTP POST form attack
hydra -L /tmp/users.txt \
  -P /tmp/passwords.txt \
  -s 80 \
  $TARGET_IP \
  http-post-form \
  "/rest/user/login:email=^USER^&password=^PASS^:Invalid email" \
  -V \
  -t 4 \
  -w 3 \
  2>&1 | tee tc_bf_01_baseline.txt
```

### Test Steps — Phase 2: Với Rate Limiting

```bash
# Hydra attack với WAF rate limiting active
hydra -L /tmp/users.txt \
  -P /tmp/passwords.txt \
  -s 80 \
  $TARGET_IP \
  http-post-form \
  "/rest/user/login:{\"email\":\"^USER^\",\"password\":\"^PASS^\"}:401" \
  -H "Content-Type: application/json" \
  -V \
  -t 4 \
  2>&1 | tee tc_bf_01_waf.txt

# Kiểm tra kết quả
echo "=== Hydra Results ===" 
cat tc_bf_01_waf.txt | grep -E "(ATTEMPT|ERROR|found|blocked)"
```

### Expected Output với WAF

```
[ATTEMPT] target 40.x.x.x - login "admin@juice-sh.op" - pass "password"
[80][http-post-form] host: 40.x.x.x   login: -   password: -   [HTTP response code: 403]
[ATTEMPT] target 40.x.x.x - login "admin@juice-sh.op" - pass "123456"
[80][http-post-form] host: 40.x.x.x   login: -   password: -   [HTTP response code: 403]
[ERROR] could not connect to http://40.x.x.x:80/rest/user/login
...
[WARNING] 10 requests returned error code 403
[WARNING] This might be a WAF/IPS. Hydra is stopping...
```

---

## 3. TC-BF-02: Rate Limit Verification với curl

### Mô tả

Kiểm tra chính xác ngưỡng Rate Limit: gửi 15 requests liên tiếp, xác nhận block sau request thứ 10.

### Test Steps

```bash
export TARGET="http://40.x.x.x"

# Script gửi 15 requests liên tiếp và ghi HTTP status code
echo "Testing rate limit on /rest/user/login"
echo "Sending 15 rapid requests..."
echo "================================"

for i in $(seq 1 15); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrongpassword"}' \
    "$TARGET/rest/user/login")
  
  TIMESTAMP=$(date +"%H:%M:%S.%3N")
  echo "Request #$i @ $TIMESTAMP → HTTP $STATUS"
  
  # Không sleep để đảm bảo rate limit trigger
done
```

**Expected Output:**
```
Testing rate limit on /rest/user/login
Sending 15 rapid requests...
================================
Request #1  @ 10:30:00.001 → HTTP 401
Request #2  @ 10:30:00.045 → HTTP 401
Request #3  @ 10:30:00.089 → HTTP 401
Request #4  @ 10:30:00.134 → HTTP 401
Request #5  @ 10:30:00.178 → HTTP 401
Request #6  @ 10:30:00.222 → HTTP 401
Request #7  @ 10:30:00.267 → HTTP 401
Request #8  @ 10:30:00.311 → HTTP 401
Request #9  @ 10:30:00.356 → HTTP 401
Request #10 @ 10:30:00.400 → HTTP 401
Request #11 @ 10:30:00.445 → HTTP 403  ← Rate limit triggered
Request #12 @ 10:30:00.490 → HTTP 403
Request #13 @ 10:30:00.535 → HTTP 403
Request #14 @ 10:30:00.580 → HTTP 403
Request #15 @ 10:30:00.624 → HTTP 403
```

### Sau khi Rate Limit Reset (1 phút)

```bash
# Chờ 65 giây
echo "Waiting 65 seconds for rate limit reset..."
sleep 65

# Test lại - phải trả về 401 (bình thường)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}' \
  "$TARGET/rest/user/login")
echo "After reset - HTTP $STATUS"
# Expected: HTTP 401 (rate limit đã reset)
```

---

## 4. TC-BF-03: Burp Suite Intruder Attack

### Thiết lập Burp Suite

1. **Mở Burp Suite Community** → Proxy → Intercept ON
2. Trong browser (configured với Burp proxy 127.0.0.1:8080):
   - Truy cập `http://<AGW_IP>/`
   - Thực hiện login với credentials bất kỳ
3. **Intercept request** trong Burp → Send to Intruder

### Cấu hình Intruder

```http
POST /rest/user/login HTTP/1.1
Host: 40.x.x.x
Content-Type: application/json

{"email":"admin@juice-sh.op","password":"§password§"}
```

**Settings:**
- Attack type: Sniper
- Payload set: Simple list
- Payload list: passwords.txt
- Resource pool: 4 concurrent requests
- Throttle: 100ms between requests

### Expected Result

```
Request 1-9:   Status 401 (wrong password)
Request 10-N:  Status 403 (rate limited by WAF)
```

---

## 5. WAF Log Evidence — Brute Force

### Query: Brute Force Detection

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where action_s == "Blocked"
| where requestUri_s contains "/rest/user/login"
| summarize
    BruteForceAttempts = count(),
    TimeRange = strcat(tostring(min(TimeGenerated)), " - ", tostring(max(TimeGenerated)))
    by clientIp_s
| order by BruteForceAttempts desc
```

### Query: Rate Limit Events

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where ruleSetType_s == "Custom"
| where requestUri_s contains "/rest/user/login"
| project TimeGenerated, clientIp_s, requestUri_s, action_s, ruleName_s
| order by TimeGenerated desc
```

---

## 6. So sánh Kết quả Trước/Sau WAF

| Tiêu chí | Không có WAF | Có WAF Rate Limiting |
|---------|-------------|---------------------|
| **Hydra có thể scan?** | ✅ Scan đầy đủ | ❌ Bị block sau 10 req |
| **Passwords tested** | Toàn bộ wordlist | ≤ 10 attempts |
| **Thời gian crack** | Vài phút | Vô thời hạn (rate limited) |
| **HTTP responses** | 200/401 | 403 sau ngưỡng |
| **Account compromise** | ✅ Có thể | ❌ Không |

---

## 7. Tổng kết Brute Force Tests

### Bảng Kết quả

| TC ID | Test | Expected | Actual | Status |
|-------|------|----------|--------|--------|
| TC-BF-01 | Hydra attack | Blocked after 10 req | *(điền)* | ⬜ |
| TC-BF-02 | curl rate limit test | HTTP 403 từ req #11 | *(điền)* | ⬜ |
| TC-BF-03 | Burp Intruder | Blocked | *(điền)* | ⬜ |
| TC-BF-04 | Rate limit reset | 401 sau 60s | *(điền)* | ⬜ |

---

*Tài liệu tiếp theo: [15-results-analysis.md](15-results-analysis.md)*
