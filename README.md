# React2Shell PRO v2 – NSE Script

**Author:** Saad Ayady (enhanced)  
**License:** Same as Nmap (open source)  
**Category:** Safe, Discovery, Vulnerability Detection  
**Status:** Detection-only, non-exploitative  

---

## Overview

**React2Shell PRO v2** is an advanced Nmap NSE script for detecting potentially vulnerable React Server Components (RSC) and unsafe SSR (Server-Side Rendering) endpoints.  
It focuses on:

- Detecting React SSR/RSC JSON patterns
- Identifying React Flight serialization markers
- Highlighting unsafe deserialization indicators
- Safe GET and non-exploitative POST checks

The script calculates a weighted score to estimate risk levels and generates a concise report with recommendations.

---

## Features

- **Safe, detection-only:** No exploitation performed
- **Supports multiple HTTP ports:** 80, 443, 3000, 3001, 4200, 5000, 8000, 8080, 9000
- **Weighted scoring:** Prioritizes strong React markers and RSC endpoints
- **React version detection:** Attempts to extract React version from responses
- **Report generation:** Summarizes findings, risk level, and remediation advice
- **Lightweight & optimized:** Minimal false positives, throttled requests

---

## Usage

1. Place the script in your Nmap scripts directory:

```bash
sudo cp react2shell-pro-v2.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```


2. Run against a target host/port:
```bash
nmap -p 80,443 --script react2shell-pro-v2 <target-ip>
```

3. Output example:
```text
============================================================
REACT2SHELL PRO DETECTOR v2 - RESULTS
============================================================
Target: 192.168.1.10:3000
Findings: 3 | Total Score: 18
Detected React Version: 18.2.0

🟡 RISK: MEDIUM

----------------------------------------
Finding #1
Endpoint: /rsc [GET]
Status: 200
Score: 10 (total)
Snippet: {"$$typeof":"react.element","type":"div","props":{"children":"Test"}...
...
============================================================
RECOMMENDATIONS:
- Update React to latest stable (if applicable)
- Audit and sanitize server-side deserialization paths
- Limit public exposure of bundle/package endpoints
- Monitor and rate-limit suspicious POST payloads
============================================================
```

4. Endpoints Scanned
Main pages: `/, /index, /home, /app`
APIs:` /api, /api/v1, /api/v2, /graphql, /graphiql`
SSR/Render: `/render, /ssr, /_render, /_ssr`
React RSC / Flight: `/rsc, /_rsc, /_flight, /react, /_react, /server`
Next.js specific: `/_next, /_next/data, /_next/static, /_next/server`
Testing endpoints: `/test, /debug, /health, /status, /metrics`
POST requests (non-exploitative) are tested only on `/api, /graphql, /rsc, /_flight, /render`.

5. Risk Scoring
   
| Total Score | Risk Level | Emoji |
| :------- | :------: | -------: |
|0-9 | LOW | 🟢
|10-19 |	MEDIUM	| 🟡 |
|20-29 |	HIGH	| 🟠 |
|30+ | CRITICAL	| 🔴 |

6. Legal Notice:
- ⚠️ Use only on assets you own or have explicit permission to test.
- This script is detection-only and does not exploit vulnerabilities. Unauthorized scanning can be illegal.

7. Contributing:
. Pull requests and suggestions welcome.
. Ensure detection-only behavior remains intact.
. Maintain NSE compatibility and safe HTTP handling.


