# Config audit — PLANT-ACCESS-SW1

- Rule pack: **Cisco IOS hardening baseline** (dialect: cisco-ios)
- Score: **0/100** (grade F)
- Checks: 17 — passed 0, failed 17, errors 0
- Failures by severity: **1 critical**, **6 high**, **5 medium**, **3 low**, **2 info**

## Failures

### [CRITICAL] Enable secret (not enable password) is used
- Rule: `PWD-001`
- Detail: required configuration not found: /^enable secret/
- Remediation: Use 'enable secret' (PBKDF/scrypt) instead of 'enable password'.
- Reference: CIS Cisco IOS 1.1.2

### [HIGH] AAA new-model is enabled
- Rule: `AAA-001`
- Detail: required configuration not found: /^aaa new-model/
- Remediation: Configure 'aaa new-model' and model authentication/authorization with AAA.
- Reference: CIS Cisco IOS 1.1.1

### [HIGH] Legacy 'enable password' is not present
- Rule: `PWD-002`
- Detail: disallowed configuration present: /^enable password/
- Remediation: Remove 'enable password'; it uses weak/clear storage.
- Reference: CIS Cisco IOS 1.1.2

### [HIGH] No SNMP community 'public' or 'private'
- Rule: `SNMP-001`
- Detail: present: /^snmp-server community\s+public/, /^snmp-server community\s+private/
- Remediation: Remove default SNMP communities; prefer SNMPv3 with auth+priv.
- Reference: CIS Cisco IOS 2.2

### [HIGH] SNMP communities are not read-write
- Rule: `SNMP-002`
- Detail: disallowed configuration present: /^snmp-server community\s+\S+\s+RW/
- Remediation: Avoid RW communities; use read-only or SNMPv3.
- Reference: CIS Cisco IOS 2.2

### [HIGH] Secure management plane (SSH present, Telnet VTY transport removed)
- Rule: `SVC-003`
- Detail: required configuration not found: /^ip ssh version 2/
- Remediation: Set 'ip ssh version 2' and generate a >=2048-bit RSA key.
- Reference: CIS Cisco IOS 1.5

### [HIGH] VTY lines use SSH transport only (no Telnet)
- Rule: `VTY-001`
- Detail: disallowed configuration present: /^\s*transport input (telnet|all)\b/
- Remediation: Set 'transport input ssh' on all VTY lines.
- Reference: CIS Cisco IOS 1.5.3

### [MEDIUM] Access ports have port-security or BPDU guard _(interface interface GigabitEthernet0/1)_
- Rule: `IF-001`
- Detail: missing /switchport port-security|spanning-tree bpduguard enable|spanning-tree portfast/
- Remediation: On edge access ports, enable PortFast + BPDU guard and/or port-security.
- Reference: CIS Cisco IOS 4.x

### [MEDIUM] Access ports have port-security or BPDU guard _(interface interface GigabitEthernet0/2)_
- Rule: `IF-001`
- Detail: missing /switchport port-security|spanning-tree bpduguard enable|spanning-tree portfast/
- Remediation: On edge access ports, enable PortFast + BPDU guard and/or port-security.
- Reference: CIS Cisco IOS 4.x

### [MEDIUM] Logging to a syslog server is configured
- Rule: `LOG-001`
- Detail: required configuration not found: /^logging host|^logging \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
- Remediation: Send logs to a central syslog/SIEM with 'logging host <ip>'.
- Reference: CIS Cisco IOS 3.2

### [MEDIUM] Password encryption service is enabled
- Rule: `SVC-001`
- Detail: required configuration not found: /^service password-encryption/
- Remediation: Add 'service password-encryption'.
- Reference: CIS Cisco IOS 1.1.4

### [MEDIUM] Insecure small/legacy services are disabled
- Rule: `SVC-002`
- Detail: present: /^ip http server\b/, /^service tcp-small-servers/
- Remediation: Disable the HTTP server (use HTTPS), and remove small-servers/finger services.
- Reference: CIS Cisco IOS 2.1

### [LOW] A login/MOTD banner is present
- Rule: `BANNER-001`
- Detail: required configuration not found: /^banner (login|motd)/
- Remediation: Add an authorized-use banner with 'banner login'.
- Reference: CIS Cisco IOS 1.7

### [LOW] NTP authentication is enabled
- Rule: `NTP-001`
- Detail: missing: /^ntp authenticate/, /^ntp authentication-key/
- Remediation: Enable 'ntp authenticate' and configure authentication keys.
- Reference: CIS Cisco IOS 3.1

### [LOW] VTY lines have an exec-timeout
- Rule: `VTY-002`
- Detail: required configuration not found: /^\s*exec-timeout\s+\d/
- Remediation: Set 'exec-timeout 10 0' (or site standard) on console and VTY lines.
- Reference: CIS Cisco IOS 1.6

### [INFO] Unused-looking interfaces are shut down _(interface interface GigabitEthernet0/1)_
- Rule: `IF-002`
- Detail: has /no shutdown/
- Remediation: Administratively shut interfaces that are not in use ('shutdown').
- Reference: CIS Cisco IOS 1.2

### [INFO] Unused-looking interfaces are shut down _(interface interface GigabitEthernet0/2)_
- Rule: `IF-002`
- Detail: has /no shutdown/
- Remediation: Administratively shut interfaces that are not in use ('shutdown').
- Reference: CIS Cisco IOS 1.2

## All checks

| Status | Severity | Rule | Title | Scope |
|---|---|---|---|---|
| fail | critical | `PWD-001` | Enable secret (not enable password) is used |  |
| fail | high | `AAA-001` | AAA new-model is enabled |  |
| fail | high | `PWD-002` | Legacy 'enable password' is not present |  |
| fail | high | `SNMP-001` | No SNMP community 'public' or 'private' |  |
| fail | high | `SNMP-002` | SNMP communities are not read-write |  |
| fail | high | `SVC-003` | Secure management plane (SSH present, Telnet VTY transport removed) |  |
| fail | high | `VTY-001` | VTY lines use SSH transport only (no Telnet) |  |
| fail | medium | `IF-001` | Access ports have port-security or BPDU guard | interface GigabitEthernet0/1 |
| fail | medium | `IF-001` | Access ports have port-security or BPDU guard | interface GigabitEthernet0/2 |
| fail | medium | `LOG-001` | Logging to a syslog server is configured |  |
| fail | medium | `SVC-001` | Password encryption service is enabled |  |
| fail | medium | `SVC-002` | Insecure small/legacy services are disabled |  |
| fail | low | `BANNER-001` | A login/MOTD banner is present |  |
| fail | low | `NTP-001` | NTP authentication is enabled |  |
| fail | low | `VTY-002` | VTY lines have an exec-timeout |  |
| fail | info | `IF-002` | Unused-looking interfaces are shut down | interface GigabitEthernet0/1 |
| fail | info | `IF-002` | Unused-looking interfaces are shut down | interface GigabitEthernet0/2 |

_Generated by netconfig-auditor. A passing audit is not a guarantee of security — it means the config matches this baseline. Review the rule pack against your own standard._
