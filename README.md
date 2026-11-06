# Network Traffic Incident Analysis — NetSupport RAT Investigation

**Project type:** Guided SOC investigation / packet analysis lab  
**Primary tool:** Wireshark  
**Focus:** Network traffic analysis, host identification, and user-account correlation

## Overview

In this guided security operations exercise, I investigated packet-capture evidence associated with suspected **NetSupport Manager remote-access trojan (RAT)** activity. My objective was to identify the internal Windows host communicating with a suspicious external IP address and associate the host with a user account.

This is an **analysis of a provided training capture**, not a live production incident. The investigation documents network observations and attribution; it does not include live endpoint containment or malware eradication.

**Lab source:** [Malware Traffic Analysis — February 28, 2026](https://www.malware-traffic-analysis.net/2026/02/28/index.html)

## Executive Summary

The exercise identified network communication involving external IP address **45.131.214.85** and an internal Windows host at **10.2.28.88**. I used Wireshark to investigate HTTP/TLS traffic, pivoted to host-identifying network artifacts, and examined Kerberos-related packet details to associate the host with an account.

| Finding | Value |
| --- | --- |
| External IP investigated | `45.131.214.85` |
| Internal host IP | `10.2.28.88` |
| Hostname | `DESKTOP-TEYQ2NR` |
| Host MAC address | `00:19:d1:b2:4d:ad` |
| Account name observed | `brolf` |
| User name identified in capture | Becka Rolf |
| Initial activity time cited in exercise report | 19:55 UTC |
| Suspected threat context | NetSupport Manager RAT activity |

**Conclusion:** The packet evidence connects the suspicious traffic to the listed Windows host and provides an account association. **Network traffic alone does not prove that the named person knowingly initiated the activity**, nor does this report establish full endpoint compromise or cleanup.

## Investigation Workflow

### 1. Identify traffic involving the suspicious IP

I started with the external address from the scenario and applied this Wireshark display filter:

~~~wireshark
(http.request or tls.handshake.type eq 1) and !(ssdp) and ip.addr eq 45.131.214.85
~~~

The filtered traffic included multiple HTTP POST requests involving `http://45.131.214.85/1`. In the context of the provided RAT investigation exercise, these requests were relevant leads for identifying the communicating internal host.

![Wireshark view showing traffic filtered for the suspicious external IP](https://github.com/user-attachments/assets/833de01a-8e10-4313-9799-f8e696be6044)

*Evidence 1 — Wireshark traffic filtering and HTTP request observations.*

### 2. Pivot from external traffic to the internal host

I traced the relevant communication to internal IP address **10.2.28.88**. I then inspected NBNS traffic and related packet details for identifying information.

- **Internal IP:** `10.2.28.88`
- **Hostname:** `DESKTOP-TEYQ2NR`
- **MAC address:** `00:19:d1:b2:4d:ad`

![Wireshark host identification view using NBNS and packet details](https://github.com/user-attachments/assets/51059482-7731-44a2-97f4-ec810410504d)

*Evidence 2 — Hostname and hardware address investigation.*

### 3. Correlate the host with a user account

To investigate account information, I filtered for the Wireshark Kerberos field `kerberos.CNameString`. The capture showed account name **brolf**. I then used Wireshark's **Find Packet** feature to search for **Rolf** in packet details, identifying the full name **Becka Rolf**.

This is an **account association visible in the training traffic**, not proof of the user's intent or an independent endpoint-forensic finding.

![Kerberos field inspection in Wireshark](https://github.com/user-attachments/assets/6c273898-a2f8-4ae3-b9d7-7d1b49b688e2)

*Evidence 3 — Kerberos-related packet inspection.*

![Wireshark packet search used during account investigation](https://github.com/user-attachments/assets/071ac32a-7df4-4ab4-a18d-5bd0bc5f3943)

*Evidence 4 — Packet search workflow.*

![Additional Kerberos and identity-related packet details](https://github.com/user-attachments/assets/4093ef2a-e980-42c5-91c3-a029bdc4d480)

*Evidence 5 — Account details in the capture.*

![Additional packet inspection supporting user-name correlation](https://github.com/user-attachments/assets/c96f0c40-2283-4ba1-b5ba-496ec5701af3)

*Evidence 6 — Follow-up packet inspection.*

![Final Wireshark evidence view for associated user details](https://github.com/user-attachments/assets/21b3d381-9ad5-4cdd-a1f9-8f61418f44b8)

*Evidence 7 — Final identity-related observation.*

## Evidence and Reasoning

| Stage | Evidence observed / documented | Analytical significance | Reference |
| --- | --- | --- | --- |
| Initial triage | Communication involving `45.131.214.85`; HTTP POST requests to `/1` | Identified relevant network conversations to inspect | Evidence 1 |
| Host identification | Internal IP `10.2.28.88`, hostname `DESKTOP-TEYQ2NR`, MAC `00:19:d1:b2:4d:ad` | Associated the suspicious traffic with a Windows host | Evidence 2 |
| Account correlation | Kerberos field `kerberos.CNameString` showed `brolf` | Provided an account identifier visible in the capture | Evidence 3 |
| Full-name investigation | Packet-detail search for “Rolf” produced “Becka Rolf” | Added a human-readable user-name association | Evidence 4–7 |

**Evidence limitation:** The original notes did not record packet/frame numbers or a complete timestamped event sequence. Those should be added from the source capture in a future verification pass rather than guessed.

## Recommended Incident Response Actions (Not Performed)

If these findings arose in a live company environment, I would recommend that the responsible security team:

1. **Escalate and validate:** Notify the incident response lead; correlate the observed IP, host, and timing with EDR, DNS, proxy, and firewall telemetry.
2. **Contain if warranted:** Isolate the affected host through approved EDR or network controls while preserving relevant evidence.
3. **Preserve evidence:** Secure packet captures, relevant Windows event logs, endpoint alerts, and other forensic artifacts with consistent timestamps.
4. **Assess scope and impact:** Investigate associated processes, persistence mechanisms, other affected endpoints, and any potential credential misuse.
5. **Remediate and recover:** Follow the organization's incident response process for malware removal or host reimaging, account protection where necessary, and post-recovery monitoring.
6. **Monitor indicators:** Consider time-bounded monitoring or blocking of confirmed malicious destinations after checking operational impact and applicable security policies.

These are **proposed response steps**, not actions taken during this packet-analysis lab.

## Skills Demonstrated

- **Wireshark filtering:** Focused on HTTP, TLS handshake activity, and traffic involving a specific external IP.
- **Network investigation:** Pivoted from an external indicator to an internal host.
- **Host identification:** Used NBNS and packet context to document hostname and MAC address.
- **Account correlation:** Examined Kerberos-related fields and packet details to associate an account with the host.
- **Incident documentation:** Organized observations, conclusions, evidence, and follow-up recommendations into a readable technical report.

## What I Learned

This exercise helped me practice a structured network-based security investigation: starting from a suspicious destination, finding the internal endpoint, and correlating identity-related traffic. It also reinforced the need to separate **what packets directly show** from **what still requires endpoint investigation**.

### Next Improvements

- Revisit the capture and add exact frame numbers and UTC timestamps for the key evidence.
- Document source/destination ports and the protocol details for each relevant conversation.
- Where possible, correlate the network findings with endpoint logs or simulated EDR telemetry.
- Add a short incident timeline once the packet timestamps have been verified.

---

**Scope note:** This repository documents an educational investigation of a third-party training capture. All observations and screenshots are presented as lab evidence; no real-world incident response actions are claimed.
