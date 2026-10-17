# Incident Report: INC-2026-1011-NET02

## 1. Incident Metadata
* **Incident ID:** INC-2026-1011-NET02
* **Date of Detection:** 2026-10-11
* **Incident Type:** Layer 2 Network Attack (MAC Flooding / DoS / Sniffing)
* **Severity:** HIGH (P2)
* **Status:** CLOSED
* **Lead Investigator:** Senior SOC Analyst

## 2. Executive Summary
On October 11, 2026, the SOC detected a massive anomaly in Layer 2 network traffic within the `192.168.56.0/24` subnet. Investigation confirmed a MAC Flooding attack designed to exhaust the virtual switch's CAM table. The switch successfully entered a "fail-open" state, resulting in a broadcast storm and localized network degradation. Forensic analysis of the packet capture confirmed that the attacker successfully intercepted Unicast traffic (DNS queries) originating from the victim workstation before the switch port was isolated.

## 3. Scope & Impact
* **Target Network:** `192.168.56.0/24` (VMware VMnet2)
* **Compromised Host (Attacker):** `192.168.56.11` (MAC: `00:0c:29:fd:17:a1`)
* **Impacted Victim:** `192.168.56.10` (MAC: `00:0c:29:7b:4d:54`)
* **Gateway:** `192.168.56.1`
* **Impact:** 
  * **DoS:** Legitimate DNS requests from the victim were dropped due to network congestion.
  * **Confidentiality:** Attacker successfully sniffed targeted Unicast data.

## 4. Technical Findings & Evidence
1. **Initial Execution:** The attacker utilized the `macof` tool to rapidly generate thousands of Ethernet frames containing randomized Source and Destination MAC/IP addresses.
2. **SIEM Detection:** Splunk flow logs (`eve.json`) recorded a peak of 374 flows per second originating from randomized IP addresses traversing the affected VLAN. Static IDS signatures (Suricata) failed to trigger due to the lack of recognizable malicious payloads in the frames.
3. **Packet Analysis:** PCAP analysis (`mac_flood_attack.pcapng`) proved that the attacker's interface captured frames where `ip.src == 192.168.56.10 && eth.dst != ff:ff:ff:ff:ff:ff`, confirming successful Layer 2 sniffing of unicast traffic.

## 5. Containment & Eradication
* **Immediate Containment:** The SOC simulated the isolation of the physical switch port connected to `192.168.56.11`.
* **Eradication:** The dynamic CAM table on the affected switch was cleared to immediately restore normal unicast routing and stop the broadcast storm.

## 6. Root Cause & Recommendations
**Root Cause:**
The network switch lacked Layer 2 port security configurations, allowing a single physical access port to dynamically register an unlimited number of MAC addresses.

**Corrective Actions:**
1. **Implement Port Security:** Apply `switchport port-security` on all edge access ports, limiting the maximum number of allowed MAC addresses to 2.
2. **Configure Violation Modes:** Set the violation action to `err-disable` to automatically shut down the port if a MAC flood occurs.
3. **Deploy Behavioral Alerts:** Implement the newly engineered Splunk SPL rule (Threshold `> 25` flows/sec from unique MACs) into the production SIEM to catch behavioral anomalies missed by static IDS.
