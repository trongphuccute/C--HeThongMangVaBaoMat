# 12 - Path Traversal Test

## TC-PATH: Directory Traversal Attack Testing

---

## Tổng quan

| Thuộc tính | Chi tiết |
|-----------|---------|
| **Objective** | Xác minh WAF chặn Path/Directory Traversal attacks |
| **Target** | OWASP Juice Shop qua Application Gateway WAF v2 |
| **Tool** | curl |
| **WAF Rules** | CRS 930100, 930110, 930120, 930130 |
| **Expected Result** | HTTP 403 Forbidden |
| **Risk** | Critical — có thể đọc `/etc/passwd`, source code, config files |

---

## Bối cảnh Tấn công

Path Traversal xảy ra khi attacker dùng `../` sequences để navigate ra ngoài web root:

```
Web root: /var/www/html/
Target: /etc/passwd

Payload: ../../../../etc/passwd
Path resolved: /var/www/html/../../../../etc/passwd = /etc/passwd
```

---

## TC-PATH-01: Basic Path Traversal

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-PATH-01 |
| **Priority** | Critical |
| **CRS Rule** | 930100, 930110 |

### Payload

```
../../../../etc/passwd
../../../etc/shadow
../../../../../../etc/hosts
../../../../windows/system32/drivers/etc/hosts
```

### Test Steps

```bash
export TARGET="http://40.x.x.x"

# Test 1: etc/passwd traversal
curl -v "$TARGET/../../../../etc/passwd" \
  2>&1 | tee tc_path_01_result.txt

# Test 2: Nhiều levels
curl -v "$TARGET/../../../etc/shadow" \
  2>&1

# Test 3: Windows path
curl -v "$TARGET/../../../../windows/system32/drivers/etc/hosts" \
  2>&1

# Test via parameter
curl -v -G \
  --data-urlencode "file=../../../../etc/passwd" \
  "$TARGET/ftp/" \
  2>&1

# Batch test
echo "=== Path Traversal Tests ===" > tc_path_01_batch.txt
for DEPTH in 1 2 3 4 5 6; do
  PAYLOAD=$(printf '../%.0s' $(seq 1 $DEPTH))"etc/passwd"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$PAYLOAD")
  echo "Depth $DEPTH: $PAYLOAD → HTTP $STATUS" | tee -a tc_path_01_batch.txt
done
```

### Expected Result

```
HTTP/1.1 403 Forbidden
WAF Rule: 930100 — Path Traversal Attack (/../)
```

### WAF Log Evidence

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where ruleId_s startswith "930"
| where action_s == "Blocked"
| project TimeGenerated, clientIp_s, requestUri_s, ruleId_s, Message
| order by TimeGenerated desc
| take 10
```

---

## TC-PATH-02: URL Encoded Path Traversal

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-PATH-02 |
| **Priority** | High |
| **CRS Rule** | 930100, 930110 |

### Encoding Reference

| Character | URL Encode | Double Encode |
|-----------|-----------|--------------|
| `.` | `%2E` | `%252E` |
| `/` | `%2F` | `%252F` |
| `\` | `%5C` | `%255C` |

### Payload

```
# Single URL encode
..%2F..%2F..%2Fetc%2Fpasswd

# Double URL encode
..%252F..%252F..%252Fetc%252Fpasswd

# Mix encoding
%2E%2E/%2E%2E/%2E%2E/etc/passwd

# Dot encoding
%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
```

### Test Steps

```bash
# Test URL encoded slash
curl -v "$TARGET/..%2F..%2F..%2Fetc%2Fpasswd" \
  2>&1 | tee tc_path_02_result.txt

# Test double encoded
curl -v "$TARGET/..%252F..%252F..%252Fetc%252Fpasswd" \
  2>&1

# Test mixed encoding
curl -v "$TARGET/%2E%2E/%2E%2E/%2E%2E/etc/passwd" \
  2>&1

# Test với --path-as-is để curl không normalize path
curl -v --path-as-is "$TARGET/..%2F..%2F..%2Fetc%2Fpasswd" \
  2>&1
```

---

## TC-PATH-03: Double Encoding và Advanced Bypass

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-PATH-03 |
| **Priority** | High |
| **CRS Rule** | 930100, 930110 |

### Payload (Advanced)

```
# Unicode encoding
..%c0%af../etc/passwd          (overlong UTF-8)
..%c1%9c../etc/passwd

# Backslash (Windows bypass attempt)
..\..\..\etc\passwd
..\..\windows\system32\

# Null byte injection (legacy)
../../../../etc/passwd%00.jpg
../../../../etc/passwd%00.html

# Double dot variations
....//....//....//etc/passwd   (bypass simple filter)
..../etc/passwd

# Absolute path
/etc/passwd
/etc/shadow
/proc/self/environ
```

### Test Steps

```bash
# Test double dot bypass
curl -v "$TARGET/....//....//....//etc/passwd" \
  2>&1 | tee tc_path_03_result.txt

# Test absolute path
curl -v "$TARGET//etc/passwd" \
  2>&1

# Test với Juice Shop ftp endpoint
curl -v "$TARGET/ftp/../../../../etc/passwd" \
  2>&1

# Test null byte (legacy)
curl -v "$TARGET/../../../../etc/passwd%00.jpg" \
  2>&1

# Test via query parameter (common in PHP apps)
curl -v "$TARGET/rest/products/1?filename=../../../../etc/passwd" \
  2>&1
```

---

## TC-PATH-04: LFI — Local File Inclusion

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-PATH-04 |
| **Priority** | Critical |
| **CRS Rule** | 930120, 930130 |

### Payload

```
?page=../../../../etc/passwd
?template=../../../../etc/shadow
?file=/etc/passwd
?include=../../../../boot.ini
?load=../../../../windows/win.ini
```

### Test Steps

```bash
# Test LFI via page parameter
curl -v -G \
  --data-urlencode "page=../../../../etc/passwd" \
  "$TARGET/index.php" \
  2>&1 | tee tc_path_04_result.txt

# Test sensitive file access
SENSITIVE_FILES=(
  "/etc/passwd"
  "/etc/shadow"
  "/etc/hosts"
  "/proc/self/environ"
  "/var/log/auth.log"
  "/.env"
  "/app/config.js"
)

for FILE in "${SENSITIVE_FILES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -G --data-urlencode "file=$FILE" \
    "$TARGET/")
  echo "File: $FILE → HTTP $STATUS"
done
```

---

## Tổng kết Path Traversal Tests

### Bảng Kết quả

| TC ID | Payload | HTTP Status | WAF Rule | Status |
|-------|---------|------------|---------|--------|
| TC-PATH-01 | `../../../../etc/passwd` | *(điền)* | 930100 | ⬜ |
| TC-PATH-02 | `..%2F..%2Fetc%2Fpasswd` | *(điền)* | 930100 | ⬜ |
| TC-PATH-03 | `....//....//etc/passwd` | *(điền)* | 930110 | ⬜ |
| TC-PATH-04 | `?page=../../../../etc/passwd` | *(điền)* | 930120 | ⬜ |

### KQL Query — Path Traversal Summary

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where ruleId_s startswith "930"
| where action_s == "Blocked"
| summarize
    TotalBlocked = count(),
    UniqueAttackers = dcount(clientIp_s)
    by ruleId_s, Message
| order by TotalBlocked desc
```

---

*Tài liệu tiếp theo: [13-sqlmap-test.md](13-sqlmap-test.md)*
