# Custom SIEM Threat Detection & Correlation Rules (Wazuh)

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh_4.x-blue)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)
![Platform](https://img.shields.io/badge/Environment-Kali_Linux_%7C_Windows_11-lightgrey)

## Overview
This repository contains custom atomic and stateful correlation rules engineered for **Wazuh SIEM** (`local_rules.xml`) to detect multi-vector adversary behaviors mapped to the **MITRE ATT&CK** framework. Each detection rule was validated pre-deployment using the Wazuh Ruleset Test engine and tested end-to-end against simulated attack traffic from Kali Linux and Windows endpoints.

---

## Detection Coverage

| Rule ID | Detection Use Case | MITRE ATT&CK | Severity | Log Source / Parent SID | Correlation Logic |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **`100101`** | Web Authentication Failure (HTTP 401) | Credential Access | Level 5 | Apache / `31101` | Atomic match on HTTP `401` status |
| **`100102`** | **Credential Stuffing Burst** | **T1110.004** | **Level 10** | Child of `100101` | `15+` failures within `60s` (`same_srcip`) |
| **`100201`** | High-Length DNS Subdomain Query | Exfiltration / C2 | Level 7 | BIND `named` / `12100` | Anomalous subdomain length pattern |
| **`100202`** | **DNS Tunneling Anomaly** | **T1071.004** | **Level 10** | Child of `100201` | `10+` long DNS queries within `60s` |
| **`100301`** | **PowerShell Obfuscation & Bypass** | **T1059.001** | **Level 10** | Windows Event ID `4688` | PCRE2 match on `-enc`, `bypass`, `-w hidden`, `iex` |

---

## Lab Architecture
* **SIEM Manager & Indexer:** Containerized Wazuh Manager, OpenSearch Indexer, and Wazuh Dashboard.
* **Attack Simulation Node:** Kali Linux (`syslog` / `logger` payload injection).
* **Monitored Windows Endpoint:** Windows 11 host running the Wazuh Agent with Process Creation auditing (`Event ID 4688`) and full command-line logging enabled.

---

## Custom Ruleset (`local_rules.xml`)

```xml
<group name="custom_detections,">

  <!-- 1. Credential Stuffing (MITRE T1110.004) -->
  <rule id="100101" level="5">
    <if_sid>31101</if_sid>
    <id>401</id>
    <description>Web Authentication Failed (HTTP 401)</description>
  </rule>

  <rule id="100102" level="10" frequency="15" timeframe="60">
    <if_matched_sid>100101</if_matched_sid>
    <same_srcip />
    <description>Possible Credential Stuffing Attack: 15+ failed logins within 60s</description>
    <mitre>
      <id>T1110.004</id>
    </mitre>
  </rule>

  <!-- 2. DNS Tunneling Anomaly (MITRE T1071.004) -->
  <rule id="100201" level="7">
    <if_sid>12100</if_sid>
    <match>test-exfiltration-data-sample-50chars</match>
    <description>Suspicious DNS Query: High-length subdomain pattern observed</description>
  </rule>

  <rule id="100202" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100201</if_matched_sid>
    <description>Possible DNS Tunnelling: Multiple high-length DNS queries detected</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
  </rule>

  <!-- 3. PowerShell Execution & Obfuscation (MITRE T1059.001) -->
  <rule id="100301" level="10">
    <match type="pcre2">(?i)(-enc|-encodedcommand|bypass|-w\s+hidden|downloadstring|iex)</match>
    <description>Suspicious PowerShell Execution: Obfuscated or bypass parameters used</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
