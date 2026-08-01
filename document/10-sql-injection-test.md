# 10 - SQL Injection Test

## TC-SQL: SQL Injection Attack Testing

---

## Tổng quan

| Thuộc tính | Chi tiết |
|-----------|---------|
| **Objective** | Xác minh Azure WAF v2 phát hiện và chặn SQL Injection |
| **Target** | OWASP Juice Shop qua Application Gateway WAF v2 |
| **Tool** | curl, Browser, Burp Suite |
| **WAF Rules** | CRS 942xxx (SQL Injection) |
| **Expected Result** | HTTP 403 Forbidden cho mọi SQLi payload |
| **CRS Version** | OWASP CRS 3.2 |

---

## Thiết lập Biến Môi trường (Kali Linux)

```bash
# Set target IP (thay bằng AGW Public IP thực tế)
export TARGET="http://40.x.x.x"

# Kiểm tra Juice Shop accessible
curl -I $TARGET/
# Expected: HTTP/1.1 200 OK
```

---

## TC-SQL-01: Basic Authentication Bypass

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-SQL-01 |
| **Priority** | Critical |
| **CRS Rule** | 942100, 942180 |
| **Endpoint** | `POST /rest/user/login` |

### Mô tả

SQL Injection cổ điển nhằm bypass authentication — inject `' OR '1'='1` vào trường email để luôn trả về true trong WHERE clause.

### Payload

```sql
' OR '1'='1
```

**SQL bị ảnh hưởng (hypothetical):**
```sql
SELECT * FROM Users WHERE email='' OR '1'='1' AND password='x'
-- Luôn trả về true → bypass auth
```

### Test Steps

```bash
# Bước 1: Test không có WAF baseline (ghi lại để so sánh)
# (Đây là kết quả giả định khi bypass thành công không qua WAF)

# Bước 2: Test với WAF enabled (Prevention Mode)
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR '\''1'\''='\''1","password":"anything"}' \
  $TARGET/rest/user/login \
  2>&1 | tee tc_sql_01_result.txt

# Bước 3: Xem HTTP status
curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"x"}' \
  $TARGET/rest/user/login
```

### Expected Result

```
HTTP/1.1 403 Forbidden
Content-Type: text/html
Server: Microsoft-Azure-Application-Gateway/v2

<html>
<head><title>403 Forbidden</title></head>
<body>The request was rejected...</body>
</html>
```

### WAF Log Evidence

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where action_s == "Blocked"
| where requestUri_s contains "/rest/user/login"
| where ruleId_s startswith "942"
| project TimeGenerated, clientIp_s, requestUri_s, ruleId_s, Message, action_s
| order by TimeGenerated desc
| take 5
```

**Expected Log Entry:**
```json
{
  "TimeGenerated": "2024-01-15T10:30:00Z",
  "clientIp_s": "103.x.x.x",
  "requestUri_s": "/rest/user/login",
  "ruleId_s": "942100",
  "Message": "SQL Injection Attack Detected via libinjection",
  "action_s": "Blocked"
}
```

### Result

| Field | Value |
|-------|-------|
| **HTTP Status** | *(điền sau khi test)* |
| **WAF Rule Triggered** | *(điền sau khi test)* |
| **Status** | ⬜ Pass / ❌ Fail |

---

## TC-SQL-02: UNION SELECT Data Extraction

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-SQL-02 |
| **Priority** | Critical |
| **CRS Rule** | 942200, 942210 |
| **Endpoint** | `GET /rest/products/search` |

### Payload

```sql
' UNION SELECT email,password,3,4,5,6,7,8,9 FROM Users--
```

### Test Steps

```bash
# Test UNION SELECT injection
curl -v -G \
  --data-urlencode "q=' UNION SELECT email,password,3,4,5,6,7,8,9 FROM Users--" \
  $TARGET/rest/products/search \
  2>&1 | tee tc_sql_02_result.txt

# Hoặc dùng URL encoding thủ công
curl -v "$TARGET/rest/products/search?q=%27%20UNION%20SELECT%20email%2Cpassword%2C3%20FROM%20Users--" \
  2>&1 | tee tc_sql_02_encoded_result.txt
```

### Expected Result

```
HTTP/1.1 403 Forbidden
WAF Rule: 942200 - Detects MySQL comment-/space-obfuscated injections
```

---

## TC-SQL-03: Blind SQL Injection — Time-Based

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-SQL-03 |
| **Priority** | High |
| **CRS Rule** | 942160, 942170 |
| **Endpoint** | `GET /rest/products/search` |

### Payload

```sql
' AND SLEEP(5)--
'; SELECT SLEEP(5)--
1; WAITFOR DELAY '0:0:5'--
```

### Test Steps

```bash
# Test time-based blind SQLi
time curl -v -G \
  --data-urlencode "q=' AND SLEEP(5)--" \
  $TARGET/rest/products/search \
  2>&1 | tee tc_sql_03_result.txt
# Nếu WAF hoạt động: response ngay lập tức (< 1s) với 403
# Nếu không có WAF: response sau 5+ giây

# Test WAITFOR (MSSQL)
curl -v -G \
  --data-urlencode "q=1; WAITFOR DELAY '0:0:5'--" \
  $TARGET/rest/products/search \
  2>&1
```


---

## TC-SQL-04: SQL Injection trong POST Body

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-SQL-04 |
| **Priority** | Critical |
| **CRS Rule** | 942100, 942130 |
| **Endpoint** | `POST /api/Feedbacks/` |

### Payload

```json
{
  "comment": "'; DROP TABLE Users; --",
  "rating": 5
}
```

### Test Steps

```bash
# Test SQLi trong JSON body
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"comment":"'\''\\; DROP TABLE Users\\;--","rating":5}' \
  $TARGET/api/Feedbacks/ \
  2>&1 | tee tc_sql_04_result.txt

# Test tautology trong body
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\'' OR '\''1'\''='\''1","password":"anything"}' \
  $TARGET/rest/user/login \
  2>&1
```

### Expected Result

```
HTTP/1.1 403 Forbidden
WAF Rule: 942100 — Request body inspection detected SQL payload
```

---

## TC-SQL-05: URL Encoded SQL Injection

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-SQL-05 |
| **Priority** | High |
| **CRS Rule** | 942100, 942200 |
| **Endpoint** | `GET /rest/products/search` |

### Payload (URL Encoded)

```
%27%20OR%201%3D1%20--         → ' OR 1=1 --
%27%20UNION%20SELECT%20NULL-- → ' UNION SELECT NULL--
%27%3BDROP%20TABLE%20Users--  → ';DROP TABLE Users--
```

### Test Steps

```bash
# URL encoded single quote + OR bypass
curl -v "$TARGET/rest/products/search?q=%27%20OR%201%3D1%20--" \
  2>&1 | tee tc_sql_05_result.txt

# Double URL encoded
curl -v "$TARGET/rest/products/search?q=%2527%2520OR%25201%253D1%2520--" \
  2>&1

# Hex encoded
curl -v "$TARGET/rest/products/search?q=0x27204f5220313d31202d2d" \
  2>&1
```

### Ghi chú về Encoding

| Encoding | `' OR 1=1 --` | WAF Decode? |
|----------|--------------|------------|
| URL encode (1x) | `%27%20OR%201%3D1%20--` | ✅ Có |
| URL encode (2x) | `%2527%2520OR...` | ✅ Có |
| HTML entity | `&#39; OR 1=1` | ✅ Có |

> Azure WAF CRS 3.2 thực hiện URL decode trước khi so sánh rule → bypass bằng encoding thông thường không hiệu quả.

---

## Tổng kết SQL Injection Tests

### Bảng kết quả

| TC ID | Payload | HTTP Status | WAF Rule | Status |
|-------|---------|------------|---------|--------|
| TC-SQL-01 | `' OR '1'='1` | *(điền)* | 942100 | ⬜ |
| TC-SQL-02 | `UNION SELECT email,password FROM Users` | *(điền)* | 942200 | ⬜ |
| TC-SQL-03 | `AND SLEEP(5)--` | *(điền)* | 942160 | ⬜ |
| TC-SQL-04 | POST body `DROP TABLE` | *(điền)* | 942100 | ⬜ |
| TC-SQL-05 | URL encoded `%27 OR 1=1` | *(điền)* | 942100 | ⬜ |

### KQL Query — Tổng hợp SQL Injection Events

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where ruleId_s startswith "942"
| where action_s == "Blocked"
| summarize
    TotalBlocked = count(),
    UniquePayloads = dcount(requestUri_s)
    by ruleId_s, Message
| order by TotalBlocked desc
```

### Phân tích Kết quả

WAF Azure với OWASP CRS 3.2 chặn SQL Injection thông qua:

1. **libinjection library** — phân tích cú pháp SQL trong input (rule 942100)
2. **Pattern matching** — tìm keywords như `UNION`, `SELECT`, `DROP`, `INSERT`, `OR 1=1`
3. **Tautology detection** — phát hiện `1=1`, `'a'='a'` patterns (rule 942130)
4. **Comment detection** — phát hiện `--`, `/**/`, `#` SQL comments
5. **Anomaly scoring** — tổng điểm từ nhiều rules → block khi >= 5

---

*Tài liệu tiếp theo: [11-xss-test.md](11-xss-test.md)*
