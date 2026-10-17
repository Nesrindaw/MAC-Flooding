# MAC-Flooding

## SOC Investigation: Layer 2 MAC Flooding (CAM Table Exhaustion)

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK-T1040%20%7C%20T1498-darkred) ![SOC Role](https://img.shields.io/badge/SOC%20Role-L1%20%2F%20L2%20Analyst-blue) ![Telemetry](https://img.shields.io/badge/Telemetry-PCAP%20%7C%20Splunk%20%7C%20Switch-green)

This repository serves as an end-to-end incident handling demonstration of a **Layer 2 MAC Flooding attack** within a virtual SOC lab. It establishes threat emulation, packet forensics, custom SIEM behavioral detection (overcoming static IDS gaps), blast radius scoping, and architectural remediation.

---

### Executive Incident Summary (Ticket: INC-2026-1011-NET02)

* **Incident Title:** Layer 2 Switch Fail-Open & Unicast Traffic Interception
* **Severity:** High (P2)
* **Impacted Asset:** `WS-014` (`192.168.56.10` / `00:0c:29:7b:4d:54`)
* **Attributed Attacker:** Rogue VM `kali` (`192.168.56.11` / `00:0c:29:fd:17:a1`)
* **Target Gateway:** `pfSense-GW` (`192.168.56.1` / True MAC: `00:0c:29:c8:9a:03`)
* **Blast Radius:** Single Broadcast Domain (`192.168.56.0/24`) — Contained locally.
* **Findings:** The switch's CAM table was exhausted using the `macof` utility, forcing a "fail-open" hub state. Splunk recorded a peak of 374 flows/second from randomized, spoofed MAC addresses. The attacker successfully sniffed sensitive Unicast traffic (DNS queries) originating from the victim workstation before containment.

---

### Lab Baseline & Known Assets

| Device Role | Hostname | IP Address | Ground Truth MAC | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Default Gateway** | `pfSense-GW` | `192.168.56.1` | `00:0c:29:c8:9a:03` | Verified Baseline |
| **Corporate Victim** | `WS-014` (Win 10) | `192.168.56.10` | `00:0c:29:7b:4d:54` | Targeted Asset |
| **Adversary Anchor** | `kali` (Rogue) | `192.168.56.11` | `00:0c:29:fd:17:a1` | Isolated Threat |

---

### Investigation Artifacts & Evidence Chain

**1. SIEM Behavioral Detection (Overcoming IDS Gaps):**
Static IDS signatures (like Suricata) failed to detect the attack due to the randomization of frames. A custom Splunk behavioral rule was engineered to detect anomalies based on flow metadata (Threshold `> 25` flows per second from unique MACs).

**2. Packet Forensics (Unicast Sniffing Proof):**
Wireshark filters (`ip.src == 192.168.56.10 && eth.dst != ff:ff:ff:ff:ff:ff`) applied to the attacker's capture proved that the switch forwarded frames intended exclusively for the gateway directly to the attacker's interface.

---

### Repository Contents & Quick Links

Explore the full investigation artifacts by navigating through the detailed files below:

* [**Analysis & Playbook**](MAC%20Flooding%20Analysis.md) - Step-by-step technical breakdown, MITRE mapping, packet forensics, and lessons learned.
* [**Incident Report**](Report%20INC-2026-1011-NET02.md) - Official SOC report documenting triage, containment, and eradication.
* [**Splunk Investigation Rules**](Splunk%20Investigation%20Rules.spl) - Custom SPL queries used for baseline tuning and the final detection alert.
* [**Raw Network Capture (PCAP)**](MAC%20Flooding.pcapng) - The network traffic captured during the simulated attack.
* [**Splunk Ingestion Data (CSV)**](mac_flood_evidence.csv) - The exported flow logs fed into Splunk to build the detection queries.
