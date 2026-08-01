# 04 - Kiến trúc Hệ thống

## System Architecture Design

---

## 1. Kiến trúc Tổng thể (Overall Architecture)

```mermaid
graph TB
    subgraph Internet["🌐 Internet Zone"]
        ATK["🔴 Kali Linux\nAttacker\n(External)"]
        USR["👤 Legitimate User\n(Browser)"]
        PIP["Public IP Address\n40.x.x.x (Static)"]
    end

    subgraph AzureCloud["☁️ Microsoft Azure - Southeast Asia Region"]
        subgraph RG["Resource Group: waf-lab-rg"]

            subgraph VNET["Virtual Network: waf-lab-vnet (10.0.0.0/16)"]

                subgraph GWSUB["Subnet: AppGatewaySubnet (10.0.1.0/24)"]
                    AGW["Azure Application Gateway WAF v2\nPrivate IP: 10.0.1.4\nSKU: WAF_v2\nCapacity: Auto-scale 1-3"]
                    WAFPOL["WAF Policy\nOWASP CRS 3.2\nMode: Prevention"]
                end

                subgraph APPSUB["Subnet: AppSubnet (10.0.2.0/24)"]
                    NSG["NSG: app-nsg\nAllow: 10.0.1.0/24 :3000\nDeny: All Other Inbound"]
                    VM["Ubuntu VM 22.04 LTS\nStandard_B2s\nPrivate IP: 10.0.2.4\nNo Public IP"]
                    JS["OWASP Juice Shop\nDocker Container\nPort: 3000"]
                end
            end

            subgraph MONITOR["Monitoring Stack"]
                DIAG["Diagnostic Settings\n- ApplicationGatewayAccessLog\n- ApplicationGatewayFirewallLog"]
                LAW["Log Analytics Workspace\nwaf-lab-law\nRetention: 30 days"]
                AM["Azure Monitor\nMetrics & Alerts"]
            end

        end
    end

    ATK -->|"Attack Traffic\nHTTP :80"| PIP
    USR -->|"HTTP :80"| PIP
    PIP --> AGW
    AGW -.->|"WAF Inspect"| WAFPOL
    WAFPOL -->|"Block → 403"| ATK
    AGW -->|"Allow → Forward\nHTTP :3000"| NSG
    NSG --> VM
    VM --> JS
    AGW -->|"Logs"| DIAG
    DIAG -->|"Stream"| LAW
    LAW --> AM
    AM -->|"Alert"| NOTIFY["📧 Alert\nNotification"]

    style ATK fill:#cc0000,color:#fff
    style AGW fill:#0078d4,color:#fff
    style WAFPOL fill:#005a9e,color:#fff
    style LAW fill:#00b4d8,color:#000
    style AM fill:#00b4d8,color:#000
```

---

## 2. Network Architecture

### 2.1 Network Topology

```mermaid
graph LR
    subgraph "Internet"
        EXT["External Traffic\n0.0.0.0/0"]
    end

    subgraph "Azure VNet: 10.0.0.0/16"
        subgraph "AppGatewaySubnet\n10.0.1.0/24"
            AGW["Application Gateway\nWAF v2\n10.0.1.4"]
        end

        subgraph "AppSubnet\n10.0.2.0/24"
            VM["Ubuntu VM\n10.0.2.4"]
        end

        subgraph "AzureFirewallSubnet\n(Reserved - Future)"]
            FW["Azure Firewall\n(Not Deployed)"]
        end
    end

    EXT -->|":80, :443"| AGW
    AGW -->|":3000\n(Internal only)"| VM
    VM -.->|"No direct\nInternet access"| EXT

    style AGW fill:#0078d4,color:#fff
    style VM fill:#107c10,color:#fff
    style FW fill:#888,color:#fff
```

### 2.2 Subnet Design

| Subnet | CIDR | Mục đích | NSG |
|--------|------|----------|-----|
| `AppGatewaySubnet` | 10.0.1.0/24 | Azure Application Gateway | Không bắt buộc* |
| `AppSubnet` | 10.0.2.0/24 | Ubuntu VM + Juice Shop | `app-nsg` |
| `AzureBastionSubnet` | 10.0.3.0/27 | Azure Bastion (optional) | Managed by Azure |

> *Application Gateway Subnet không cần NSG theo Microsoft recommendation, nhưng Azure tự quản lý security.

### 2.3 NSG Rules — `app-nsg`

| Priority | Name | Direction | Protocol | Source | Destination | Port | Action |
|----------|------|-----------|----------|--------|-------------|------|--------|
| 100 | Allow-AGW-Inbound | Inbound | TCP | 10.0.1.0/24 | 10.0.2.0/24 | 3000 | Allow |
| 110 | Allow-SSH-Bastion | Inbound | TCP | 10.0.3.0/27 | 10.0.2.4 | 22 | Allow |
| 200 | Allow-AGW-Probe | Inbound | TCP | 10.0.1.0/24 | 10.0.2.4 | 3000 | Allow |
| 4096 | Deny-All-Inbound | Inbound | Any | * | * | * | Deny |

---

## 3. Security Architecture

### 3.1 Security Layers

```mermaid
graph TB
    subgraph "Security Defense Layers"
        L1["Layer 1: Azure DDoS Basic Protection\n(Built-in, Free)"]
        L2["Layer 2: Application Gateway WAF v2\nOWASP CRS 3.2 + Custom Rules"]
        L3["Layer 3: Network Security Group (NSG)\nSubnet-level firewall rules"]
        L4["Layer 4: OS-level Firewall\nufw (Ubuntu Firewall)"]
        L5["Layer 5: Application Security\nJuice Shop (Intentionally Vulnerable - Lab Only)"]
    end

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5

    style L2 fill:#0078d4,color:#fff
    style L3 fill:#107c10,color:#fff
```

### 3.2 WAF Policy Structure

```mermaid
graph LR
    subgraph "WAF Policy: waf-lab-policy"
        subgraph "Managed Rules"
            MR1["OWASP CRS 3.2\nRule Groups:"]
            MR2["- REQUEST-913: Scanner Detection"]
            MR3["- REQUEST-920: Protocol Enforcement"]
            MR4["- REQUEST-930: LFI (Path Traversal)"]
            MR5["- REQUEST-931: RFI"]
            MR6["- REQUEST-932: RCE / Command Injection"]
            MR7["- REQUEST-933: PHP Injection"]
            MR8["- REQUEST-941: XSS"]
            MR9["- REQUEST-942: SQLi"]
            MR10["- REQUEST-943: Session Fixation"]
            MR11["- REQUEST-944: Java Attacks"]
        end

        subgraph "Custom Rules"
            CR1["Rate Limit Login\n>10 req/30s → Block"]
            CR2["Block Scanner UA\nSQLMap/Nikto → Block"]
            CR3["Block IMDS Access\n169.254.169.254 → Block"]
        end

        subgraph "Policy Settings"
            PS1["Mode: Prevention"]
            PS2["Inspection Body: ON"]
            PS3["Max Request Body: 128KB"]
            PS4["File Upload Limit: 100MB"]
        end
    end
```

### 3.3 Zero Trust Principles Applied

| Principle | Áp dụng trong đồ án |
|-----------|---------------------|
| **Verify explicitly** | Mọi request đều được WAF inspect |
| **Least privilege** | VM không có Public IP, NSG chỉ allow port 3000 từ AGW subnet |
| **Assume breach** | Log Analytics ghi lại tất cả activity, alert khi phát hiện attack |

---

## 4. Data Flow Architecture

### 4.1 Legitimate Traffic Flow

```mermaid
sequenceDiagram
    participant U as 👤 User Browser
    participant PIP as Public IP
    participant AGW as Application Gateway
    participant WAF as WAF Engine
    participant VM as Ubuntu VM
    participant JS as Juice Shop

    U->>PIP: HTTP GET / (HTTP :80)
    PIP->>AGW: Route to Frontend IP
    AGW->>WAF: Inspect request
    WAF->>WAF: Check OWASP CRS rules
    WAF->>WAF: Check Custom Rules
    Note over WAF: No rules matched
    WAF->>AGW: ALLOW
    AGW->>VM: HTTP GET / (:3000)
    VM->>JS: Forward request
    JS-->>VM: HTTP 200 OK + HTML
    VM-->>AGW: HTTP 200 OK
    AGW-->>U: HTTP 200 OK (response)
```

### 4.2 Attack Traffic Flow (SQL Injection)

```mermaid
sequenceDiagram
    participant ATK as 🔴 Kali Linux
    participant PIP as Public IP
    participant AGW as Application Gateway
    participant WAF as WAF Engine
    participant LOG as Log Analytics

    ATK->>PIP: POST /rest/user/login<br/>body: {"email":"' OR 1=1--"}
    PIP->>AGW: Forward request
    AGW->>WAF: Inspect request body
    WAF->>WAF: Decode body
    WAF->>WAF: Match CRS Rule 942100 (SQLi)
    WAF->>WAF: Anomaly Score >= Threshold (5)
    Note over WAF: BLOCK ACTION
    WAF->>AGW: Block request
    AGW-->>ATK: HTTP 403 Forbidden<br/>"The request was rejected"
    WAF->>LOG: Write FirewallLog entry<br/>{action:"Blocked", ruleId:"942100"}
```

### 4.3 Logging Data Flow

```mermaid
flowchart LR
    AGW["Application Gateway\nWAF v2"] -->|"ApplicationGatewayFirewallLog\n(JSON)"| DIAG["Diagnostic Settings"]
    AGW -->|"ApplicationGatewayAccessLog\n(JSON)"| DIAG
    AGW -->|"Metrics\n(BlockedRequests, etc.)"| AM["Azure Monitor"]

    DIAG -->|"Stream to workspace"| LAW["Log Analytics Workspace"]
    LAW -->|"KQL Query"| DASH["Dashboard\n& Reports"]
    AM -->|"Alert Rule"| ALERT["Alert → Email/SMS"]
    LAW -->|"Scheduled Query"| ALERT
```

---

## 5. Component Architecture

### 5.1 Application Gateway Internal Components

```mermaid
graph LR
    subgraph "Azure Application Gateway WAF v2"
        FIP["Frontend IP\n(Public: 40.x.x.x)"]
        LIST["Listener\nProtocol: HTTP\nPort: 80"]
        WAF_ENG["WAF Engine\nOWASP CRS 3.2"]
        RULE["Routing Rule\n(Basic)"]
        BES["Backend Settings\nProtocol: HTTP\nPort: 3000\nTimeout: 30s"]
        HP["Health Probe\nPath: /\nInterval: 30s\nThreshold: 3"]
        BPOOL["Backend Pool\n[VM: 10.0.2.4]"]
    end

    FIP --> LIST
    LIST --> WAF_ENG
    WAF_ENG -->|"ALLOW"| RULE
    RULE --> BES
    BES --> BPOOL
    HP -->|"Health Check"| BPOOL
```

### 5.2 Ubuntu VM Component Stack

```mermaid
graph TB
    subgraph "Ubuntu VM (10.0.2.4)"
        OS["Ubuntu Server 22.04 LTS"]
        UFW["ufw Firewall\nAllow: 22 (SSH), 3000"]
        DOCKER["Docker Engine 24.x"]
        CONTAINER["Docker Container\nimage: bkimminich/juice-shop:latest"]
        APP["Node.js Application\nPort: 3000"]
        DB["SQLite Database\n/opt/juice-shop/data"]
    end

    OS --> UFW
    UFW --> DOCKER
    DOCKER --> CONTAINER
    CONTAINER --> APP
    APP --> DB
```

---

## 6. Deployment Architecture Diagram

```mermaid
C4Container
    title Container Diagram - WAF Lab System

    Person(attacker, "Attacker", "Kali Linux user performing attack tests")
    Person(user, "Legitimate User", "Normal web browser user")

    System_Boundary(azure, "Microsoft Azure") {
        Container(agw, "Application Gateway WAF v2", "Azure PaaS", "Reverse proxy + WAF. OWASP CRS 3.2. Prevention Mode.")
        Container(vm, "Ubuntu VM", "Azure IaaS - Standard_B2s", "Hosts OWASP Juice Shop via Docker")
        Container(js, "OWASP Juice Shop", "Docker / Node.js", "Intentionally vulnerable web application")
        Container(law, "Log Analytics", "Azure PaaS", "Centralized log storage and query engine")
        Container(am, "Azure Monitor", "Azure PaaS", "Metrics collection and alerting")
    }

    Rel(attacker, agw, "Attack requests", "HTTP/80")
    Rel(user, agw, "Browse website", "HTTP/80")
    Rel(agw, js, "Forward clean requests", "HTTP/3000")
    Rel(agw, law, "Stream WAF & Access logs", "Diagnostic Settings")
    Rel(agw, am, "Send metrics", "Azure Monitor API")
    Rel(am, attacker, "Block", "HTTP 403")
```

---

## 7. High Availability Consideration

Đây là môi trường lab, HA không phải mục tiêu chính. Tuy nhiên, Application Gateway WAF v2 đã có sẵn:

| Feature | Application Gateway WAF v2 | Ghi chú |
|---------|---------------------------|---------|
| **Autoscaling** | ✅ Min 1, Max 10 instances | Cấu hình Min=1 cho lab |
| **Zone Redundancy** | ✅ Availability Zones | Kích hoạt nếu region hỗ trợ |
| **Health Probes** | ✅ Tự động | Phát hiện VM down |
| **Backend HA** | ❌ Single VM | Lab chỉ cần 1 VM |

---

*Tài liệu tiếp theo: [05-azure-resource-design.md](05-azure-resource-design.md)*
