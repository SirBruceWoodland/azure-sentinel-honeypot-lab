# Azure Sentinel SIEM Honeypot Lab

**Cybersecurity Portfolio Project - Edward Antonucci - June 2026**

---

## Overview

This project demonstrates end-to-end deployment and operation of a cloud-native SIEM using Microsoft Azure. A Windows Server 2022 honeypot VM was intentionally exposed to the public internet across three services (RDP, SSH, HTTP) to attract real-world attack traffic, which was ingested, analyzed, visualized, and responded to using Microsoft Sentinel and Microsoft Defender XDR.

**Portal Note:** During this project, Microsoft began migrating Sentinel from the Azure portal into the unified Microsoft Defender portal (`security.microsoft.com`). Screenshots reflect both environments — this mirrors real-world conditions during the active transition period (full migration expected March 31, 2027).

---

## Dashboard Summary

| Metric | Value |
|---|---|
| Total Security Events | 80,800+ |
| Total Alerts Fired | 95 |
| Total Incidents | 6 |
| Unique Attacker IPs | 43+ |
| Countries of Origin | 15 across 5 continents |
| SSH Probe Events (NOUSER) | 5,742+ |
| IIS Web Probe Requests | 599+ |

<img width="792" height="624" alt="image" src="https://github.com/user-attachments/assets/8600c070-2ae0-4ecc-b8ea-bd0560845421" />

> 📸 *Screenshot: Microsoft Sentinel Overview Dashboard - 80.8K events, 95 alerts, 6 incidents*

---

## Architecture

All resources deployed in a dedicated resource group (`RG-Sentinel-Lab`, West US region):

| Component | Details |
|---|---|
| **Log Analytics Workspace** | `LAW-Sentinel-Lab` - centralized data store |
| **Microsoft Sentinel** | SIEM layer on top of the workspace |
| **Honeypot VM** | Windows Server 2022 Datacenter, Standard D2s v3 |
| **Network Security Group** | `DANGER_AllowAnyInbound` rule - all ports exposed; targeted deny added during IR |
| **Data Collection Rule** | `DCR-Honeypot` - Azure Monitor Agent streaming Security Events + IIS logs |
| **Exposed Services** | RDP (3389), SSH (22 via OpenSSH), HTTP (80 via IIS) |

### Why Disable the Firewall?

The Windows Firewall was disabled and NSG inbound was set to allow all traffic to maximize honeypot effectiveness. In production, this would be a catastrophic misconfiguration, but here it's intentional to create the highest possible attack surface and observe what automated scanners and botnets probe first.

### Why Priority 200 for the Deny Rule?

NSG rules are evaluated lowest-number-first. Priority 100 was already taken by `DANGER_AllowAnyInbound`, so the attacker-specific deny rule was placed at priority 200. In production, the "allow-all" rule would not exist and targeted deny rules would sit at a low priority number above more permissive rules.

---

## Live Attack Dashboard

A multi-panel Sentinel Workbook visualizes attack traffic in real time with 5-minute auto-refresh.

### Workbook Description (Title Block)

> **Real-Time Global Attack Map from Azure Sentinel Honeypot Lab**
>
> This dashboard visualizes live attack traffic captured by a Windows Server 2022 honeypot deployed on Microsoft Azure. The honeypot intentionally exposes RDP (3389), SSH (22), and HTTP (80) to the public internet to attract real-world threat actors and automated scanners.
>
> Attack data is enriched with geolocation metadata via a custom Sentinel Watchlist (AttackerGeoDataV2), populated using ipinfo.io. The map uses a green-to-red heatmap scaled by failed authentication count. The bar chart shows total attack volume by country across all observed attackers.
>
> All data shown is real, unsolicited attack traffic from external threat actors.

### Panel 1: Global Attack Map

IP addresses geo-enriched via custom Sentinel Watchlist (`AttackerGeoDataV2`) populated with latitude/longitude from ipinfo.io. Heatmap scaled by failed login count.

**KQL:**
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by AttackerIP = IpAddress
| join kind=inner (_GetWatchlist('AttackerGeoDataV2')) on $left.AttackerIP == $right.IPAddress
| project AttackerIP, FailedLogins, Country, Latitude, Longitude
```

> 📸 *Screenshot: Final attack map showing global attack origins*

### Panel 2: Top 10 Attacking Countries Bar Chart

```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedLogins = count() by AttackerIP = IpAddress
| join kind=inner (_GetWatchlist('AttackerGeoDataV2')) on $left.AttackerIP == $right.IPAddress
| summarize TotalAttempts = sum(FailedLogins) by Country
| sort by TotalAttempts desc
| take 10
```

### Final Attack Map Statistics (All-Time)

| Country | Attempts | Notable ASNs |
|---|---|---|
| 🇳🇱 Netherlands | 441 | SKYNET NETWORK LTD (AS214295), Liteserver |
| 🇮🇩 Indonesia | 232 | PT Telekomunikasi Indonesia |
| 🇺🇸 United States | 120 | Multiple VPS providers |
| 🇻🇳 Vietnam | 76 | VNPT Corp |
| 🇫🇷 France | 46 | Contabo GmbH, OVH |
| 🇸🇬 Singapore | 36 | Contabo Asia, Tencent |
| 🇧🇷 Brazil | 28 | BattleHost, Gamers Club |
| 🇬🇧 United Kingdom | 26 | Contabo, Kamatera |
| 🇵🇪 Peru | 22 | Red Cientifica Peruana, ON Empresas |
| Other | 20 | Romania, Finland, Germany, Belgium, Hong Kong |

> 📸 *Screenshot: Combined workbook attack map + bar chart panel*

---

## Key Finding: SSH Attack Traffic & the NOUSER Phenomenon

After enabling OpenSSH Server, **5,742 failed authentication events appeared with no IP address and the account name `NOUSER` or blank**.

### Why SSH Failures Show No IP in Windows Logs

This is a fundamental difference between SSH and RDP at the OS authentication layer:

When an SSH connection fails **before** reaching Windows authentication — for example, when the client disconnects after the key exchange but before sending credentials — Windows logs Event ID 4625 but has **no IP context to record**, since the failure occurred at the SSH protocol layer rather than the Windows Security layer.

Additionally, OpenSSH on Windows logs to its own files (`C:\ProgramData\ssh\logs\`) separately from the Windows Security Event Log. Failed SSH attempts that reach password authentication may not generate Event ID 4625 at all, depending on authentication method attempted.

### What This Means

The 5,742 NOUSER events represent **automated SSH scanners in a reconnaissance phase** — probing for open SSH, checking supported authentication methods, and disconnecting before attempting credentials. This is consistent with SSH-targeting botnet behavior.

### How to Capture SSH IPs Properly (Production Approach)

- Deploy a **Linux VM** alongside the honeypot - Linux `sshd` logs capture full IP context
- Enable **Azure Defender for Servers** for additional network-level telemetry
- Configure **OpenSSH verbose logging** on Windows and ingest via a custom Log Analytics data collection rule
- Use **Azure Network Watcher NSG flow logs** to capture all connection-level data regardless of authentication outcome

> 📸 *Screenshot: KQL results showing top attacking IPs with failed login counts*

---

## KQL Queries Written

### Event Inventory - All Security Event Types
```kql
SecurityEvent
| summarize count() by EventID, Activity
| sort by count_ desc
```

### Failed Logon Analysis by Attacker IP
```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedLogins = count() by AttackerIP = IpAddress
| sort by FailedLogins desc
```

### Full Logon Event Timeline
```kql
SecurityEvent
| where EventID in (4625, 4624, 4648)
| summarize count() by EventID, Activity, IpAddress
| sort by count_ desc
```

### Brute Force Detection (Analytics Rule)
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(5m)
| summarize FailedAttempts = count() by AttackerIP = IpAddress, Computer, Account
| where FailedAttempts >= 10
```

### Attack Map with Watchlist Geo-Enrichment
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by AttackerIP = IpAddress
| join kind=inner (_GetWatchlist('AttackerGeoDataV2')) on $left.AttackerIP == $right.IPAddress
| project AttackerIP, FailedLogins, Country, Latitude, Longitude
```

### Top 10 Countries Bar Chart
```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedLogins = count() by AttackerIP = IpAddress
| join kind=inner (_GetWatchlist('AttackerGeoDataV2')) on $left.AttackerIP == $right.IPAddress
| summarize TotalAttempts = sum(FailedLogins) by Country
| sort by TotalAttempts desc
| take 10
```

### Web Attack Probe Detection (IIS)
```kql
W3CIISLog
| where csUriStem in ("/wp-admin", "/wp-login.php", "/.env",
    "/phpmyadmin", "/admin", "/administrator", "/xmlrpc.php",
    "/.git/config", "/config.php", "/backup", "/.aws/credentials")
| summarize ProbeCount = count() by AttackerIP = cIP, csUriStem
| where ProbeCount >= 1
```

---

## Analytics Rules

> 📸 *Screenshot: Analytics page showing both rules active with MITRE ATT&CK tags*

### Rule 1: Brute Force Detection - Failed Logons

| Setting | Value |
|---|---|
| Severity | Medium |
| Query Frequency | Every 5 minutes |
| Lookup Window | Last 5 minutes |
| Alert Threshold | Triggers when query returns > 0 results |
| Logic | Alerts when a single IP has 10+ failed logons within 5 minutes |
| MITRE ATT&CK | Credential Access — **T1110 (Brute Force)** |
| Alert Grouping | Same IP grouped into single incident within 5 hours |

### Rule 2: Web Attack Probe Detection

| Setting | Value |
|---|---|
| Severity | Medium |
| Query Frequency | Every 1 hour |
| Lookup Window | Last 1 hour |
| Alert Threshold | Triggers when query returns > 0 results |
| Logic | Alerts when any IP probes common web attack paths on IIS |
| MITRE ATT&CK | Reconnaissance — **T1595 (Active Scanning)** |
| Alert Grouping | Same IP grouped into single incident within 1 hour |

---

## Automated Response - Logic App Playbook

A Logic App playbook (`Notify-BruteForce-Alert`) was built to automate incident notification. The playbook uses the Microsoft Sentinel incident trigger and sends an HTTP POST to ntfy.sh when a brute force incident fires.

**HTTP action (workaround for email connector auth limitations):**
```json
{
  "Send_an_alert": {
    "type": "Http",
    "inputs": {
      "method": "POST",
      "uri": "https://ntfy.sh/sentinel-honeypot-alert",
      "body": "Brute Force Detected on honeypot-vm - check Microsoft Sentinel"
    }
  }
}
```

**RBAC Limitation Note:** Connecting the playbook to the analytics rule via the Automation tab required the `Microsoft Sentinel Automation Contributor` role on the Sentinel managed identity. This role was unavailable on the free tier. In production, this is resolved by granting that role via IAM at the resource group level. The playbook itself was successfully built and published.

---

## Incident Response Walkthrough

Full SOC incident response workflow executed for the primary threat actor (`45.142.193.166` / SKYNET NETWORK LTD, Netherlands):

| Step | Action |
|---|---|
| **1. Detection** | 14 failed RDP logon attempts via KQL on Event ID 4625. IP attributed to SKYNET NETWORK LTD (AS214295), Netherlands. |
| **2. Incident Creation** | Incident #2 created in Microsoft Defender XDR. Severity: Medium. Category: Credential Access (MITRE ATT&CK). Asset: honeypot-vm. |
| **3. Assignment & Triage** | Incident assigned to analyst, status changed New → In Progress. |
| **4. Investigation** | KQL confirmed zero successful logons from attacker IP. Anonymous network scans assessed as low-risk (Logon Type 3, no credentials). |
| **5. Remediation** | NSG inbound deny rule added for `45.142.193.166` (Priority 200) to block further access at the network perimeter. |
| **6. Closure** | Incident classified: **True Positive — Malicious user activity**. Status: Resolved. Official Microsoft Security incident report exported as PDF. |

> 📸 *Screenshot: Resolved incident showing investigation notes, True Positive classification, and audit trail*

---

## Threat Intelligence Observations

### Contabo GmbH - Recurring Infrastructure
Contabo GmbH (AS51167), a low-cost German VPS provider, appeared across France, Singapore, and other regions. Contabo is frequently cited in threat intel reports as infrastructure heavily abused by attackers due to low cost, minimal identity verification, and historically slow abuse response.

### SKYNET NETWORK LTD - Top Attacker
The top attacker, SKYNET NETWORK LTD (AS214295, Netherlands), accumulated **441 failed logon attempts** across 3 IPs in the same /24 subnet (`45.142.193.x`). Multiple IPs from one ASN targeting simultaneously indicates an **automated botnet operation**, not a manual attacker.

### Coordinated Botnet Behavior
Multiple IPs sharing the same ASN were observed targeting the honeypot simultaneously (Netherlands, Vietnam/VNPT, Finland/Bashinskii, France/Contabo). This is consistent with shared credential list botnets rather than independent actors.

---

## Data Connectors Active

- Windows Security Events via AMA *(primary - honeypot VM logs)*
- Azure Activity
- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Identity
- Microsoft Entra ID Protection
- Microsoft Defender for Office 365
- Microsoft 365 Insider Risk Management

---

## Skills Demonstrated

| Skill | Details |
|---|---|
| **Cloud Infrastructure** | Azure VMs, NSGs, Log Analytics Workspaces, Data Collection Rules |
| **SIEM Administration** | Microsoft Sentinel deployment, 10+ data connector configuration |
| **KQL** | Custom queries for threat detection, aggregation, watchlist joins, geo-enrichment |
| **Threat Detection Engineering** | Two custom analytics rules with scheduled queries, MITRE ATT&CK mapping, entity mapping |
| **Incident Response** | Full SOC workflow: detection → triage → investigation → remediation → closure |
| **Dashboard & Visualization** | Multi-panel Workbook with live attack map, heatmap, auto-refresh, bar chart |
| **Threat Intelligence** | IP/ASN attribution, botnet pattern identification, Contabo/SKYNET actor profiling |
| **Network Security** | NSG rule management, perimeter-level IP blocking, multi-service attack surface analysis |
| **SOAR** | Logic App playbook design and deployment for automated incident notification |
| **Offensive Security** | RDP brute force simulation using ncrack and xfreerdp from Kali Linux |

---

## Tools & Technologies

- Microsoft Azure (Virtual Machines, NSG, Log Analytics, Resource Groups, Azure Monitor)
- Microsoft Sentinel (SIEM) + Microsoft Defender XDR (unified portal)
- KQL — Kusto Query Language
- Azure Monitor Agent (AMA) + Data Collection Rules (DCR)
- Sentinel Workbooks (multi-panel dashboard, auto-refresh)
- Sentinel Watchlists (custom geo-enrichment)
- Azure Logic Apps (SOAR playbook)
- Windows Server 2022 Datacenter (OpenSSH Server, IIS Web Server)
- Kali Linux (ncrack, xfreerdp for attack simulation)
- ipinfo.io (IP geolocation and ASN attribution)
- MITRE ATT&CK Framework (T1110, T1595)

---

## Ethical Disclosure

This honeypot was deployed on a fully isolated Azure VM with no connection to any production systems or sensitive data. All attack traffic shown is real, unsolicited traffic from external threat actors. The VM was intentionally configured to be vulnerable for research and educational purposes only. All brute force simulation was conducted against this VM only, which is owned and controlled by the author.

---

*Built with: Microsoft Azure · Microsoft Sentinel · KQL · Windows Server 2022 · Kali Linux*
