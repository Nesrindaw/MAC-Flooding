# MAC Flooding Analysis 

## Attack Card
| Record Field | Operational Value |
| :--- | :--- |
| **Attack Name** | MAC Flooding |
| **Alternative Names** | CAM Table Exhaustion, Switch Flooding, Fail-Open Attack |
| **Category** | Network & Protocol Attacks |
| **MITRE ATT&CK Technique** | T1040 (Network Sniffing), T1498 (Network Denial of Service) |
| **Tactic** | Credential Access (TA0006), Discovery (TA0007), Impact (TA0040) |
| **Severity** | High (P2) |
| **Attack Prerequisites** | Local Layer 2 Network Adjacency (Same Broadcast Domain / VLAN) |
| **Target Platforms** | Network Switches (Layer 2) |
| **Required Access** | Unprivileged Local Network Access |
| **Typical Attacker Objective** | Force Switch into Fail-Open (Hub) Mode, Unicast Interception, DoS |
| **SOC Relevance** | Switch Telemetry, IDS Gap Analysis, Flow Anomaly Detection |
| **Difficulty** | Low (Automated open-source tooling like `macof` readily available) |
| **Estimated Reading Time** | 20 Minutes |

## What Is It?
The Address Resolution Protocol (ARP) and Layer 2 switching rely on a Content Addressable Memory (CAM) table to map MAC addresses to physical switch ports. 
**The Underlying Weakness:**
A switch's CAM table has a finite amount of memory. When a switch receives a frame with a Source MAC address it has not seen before, it records it in the CAM table. It does not natively authenticate or limit the number of MACs originating from a single physical port unless specifically configured to do so.
**Attacker Objectives:**
- Overwhelm the CAM table's capacity to force the switch into a "Fail-Open" state.
- In Fail-Open mode, the switch behaves like a legacy Hub, broadcasting all incoming frames to all ports to maintain network availability.
- The attacker can then capture (sniff) sensitive Unicast traffic (e.g., HTTP, DNS) intended for other devices on the network.
**Endpoint/User Experience:**
Users will experience severe network degradation, high latency, and dropped connections (such as failed DNS requests) due to the massive broadcast storm caused by the flood of fake MAC frames.

## How It Works
1. **Normal Operational Behavior:**
   - The switch learns MAC addresses dynamically. If Host A sends a frame to Host B, the switch looks up Host B's MAC in the CAM table and forwards the frame *only* to Host B's specific port.
2. **Malicious Behavior:**
   - The attacker uses a tool (like `macof`) to generate hundreds of thousands of frames with random, spoofed Source MAC addresses and IP addresses per second.
   - The switch blindly logs each fake MAC into its CAM table until the memory is 100% full.
   - Legitimate MACs are aged out or dropped. The switch defaults to broadcasting all traffic (Fail-Open), allowing the attacker to passively sniff data using Wireshark.

## Attack Lifecycle (MITRE ATT&CK Mapping)
- **Initial Access:** Securing physical access to an Ethernet port or joining an unsecured VLAN.
- **Impact (TA0040):** Executing T1498 (Network DoS) via CAM table exhaustion, leading to resource spikes and dropped packets.
- **Credential Access (TA0006) & Collection (TA0009):** Executing T1040 (Network Sniffing) to capture plaintext credentials or session tokens leaked during the fail-open state.

## Hands-on Lab & Baseline Validation
All emulation steps were executed within an isolated host-only subnet (VMware VMnet2: 192.168.56.0/24).

**Verified Enterprise Baseline:**
| Device Role | Hostname | IP Address | Authentic MAC Address | Interface |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway** | pfSense | `192.168.56.1` | `00:0c:29:c8:9a:03` | em1 |
| **Corporate Victim** | Windows 10 | `192.168.56.10` | `00:0c:29:7b:4d:54` | Ethernet0 |
| **Adversary Host** | Kali Linux | `192.168.56.11` | `00:0c:29:fd:17:a1` | eth0 |

**Attacker Execution Commands (Kali Linux):**
```bash
# Execute MAC Flooding to exhaust the CAM table
sudo macof -i eth0
```

## Attack Evidence Map

| Telemetry Source |Evidence Classification | Observed Artifacts in Lab |
| :--- | :--- | :--- |
| **Wireshark (PCAP)** | Direct Evidence | Massive flood of frames with randomized Source/Dest MACs and IPs. |
| **Wireshark (PCAP)** | Direct Evidence | Unicast traffic (Victim DNS to Gateway) captured by Kali interface. |
| **Splunk SIEM** | Direct Evidence | Unusually high volume of unique source IPs and flows in a single second. |
| **Switch Telemetry** | Supporting Evidence | High CPU/Memory utilization, CAM table overflow Syslogs. |
| **Suricata IDS** | Missing Evidence / Gap | 0 Alerts generated (Signatures failed due to random payload/IPs).` |

## Detection Engineering
### 1. Wireshark Packet Filters:

- **Detect MAC Flood Storm:** Check for thousands of frames lacking typical protocols.

- **Proof of Unicast Sniffing:** `ip.src == 192.168.56.10 && eth.dst != ff:ff:ff:ff:ff:ff` (Isolating victim traffic captured on attacker machine).

### 2. Splunk Enterprise Investigation Query (SPL):

Proof of Execution & Behavioral Detection:

## Investigation & Timeline Analysis

* **T0:** Attacker executes macof on Kali Linux (192.168.56.11).
* **T1 (+0.5s):** Wireshark captures a massive influx of malformed frames. Flow count in SIEM spikes to 374 flows/second.
* **T2 (+2.0s):** Switch CAM table reaches capacity; switch enters Fail-Open mode.
* **T3 (+5.0s):** Victim (Windows 10) attempts to browse the web. DNS requests fail due to network congestion (DoS impact).
* **T4 (+6.0s):** Attacker successfully sniffs victim's Unicast DNS packets intended for the Gateway.
* **Defensible Conclusion:** Verified Layer 2 MAC Flooding resulting in successful AiTM/Sniffing and localized DoS. IDS signatures failed, requiring flow-based behavioral detection.
 ## Hypothesis-Driven Threat Hunting
**Hunting Hypothesis:** An adversary flooding the network will generate an anomalous ratio of unique Source IP/MAC addresses compared to total network flows originating from a single physical port or VLAN within a microsecond window.
**Hunting Query (SPL):**

## Scoping the Incident

| Scope Dimension | Observed Extent | Telemetry Justification |
| :--- | :--- | :--- | 
| **Affected Hosts** | Entire Subnet | Broadcast storm affected all hosts in `192.168.56.0/24` |
| **Corporate Victim** | 1 Host (Kali) | Origin of the initial execution (identified via port tracking). |
| **Adversary Host** | Localized (Layer 2) | Flooding cannot cross routers; contained to the local Switch/VLAN. |

## Response & Containment Protocol
1. **Immediate Containment:** Administratively shut down the physical switch port connected to the attacker (`shutdown`).

2. **Short-Term Containment:** Clear the dynamic CAM table on the affected switch (`clear mac address-table dynamic`) to restore normal routing operations.

3. **Eradication:** Locate the rogue device physically or isolate the VM; revoke network access.

4. **Recovery Verification:** Verify network latency returns to normal and unicast traffic is no longer visible in promiscuous mode.

## Architectural Hardening & Prevention

- **Port Security (MAC Limiting):** Configure edge switches to restrict the maximum number of MAC addresses allowed per port (e.g., switchport port-security maximum 2).
- **Violation Actions:** Enforce switchport port-security violation restrict or err-disable to immediately shut down the port upon detecting a flood.
- **802.1X Port Security:** Enforce network access control (NAC) requiring certificate-based authentication before granting Layer 2 access.

## Common SOC Analyst Mistakes

- **Relying Exclusively on Static IDS Signatures:** Default Suricata rules missed the attack completely because macof randomizes IPs and MACs. Behavioral analysis is mandatory.
- **Dismissing "Network Slowness" as an IT Issue:** Analysts often ignore alerts about dropped packets or slow network response, assuming it's an IT routing problem rather than a CAM table exhaustion attack.
- **Ignoring the "Noise" to Miss the "Signal":** Focusing only on the massive flood of MACs and forgetting to check if the attacker successfully sniffed sensitive credentials (Unicast data) during the chaos.

## Analyst Decision Tree

```text
  Alert: Anomalous Flow Spike / High Switch CPU
               │
   Is it a known vulnerability scanner or network mapper?
          YES ──>  Close as Benign / Update Baseline 
          NO
               │
   Are the Source MACs/IPs completely randomized and massive in volume?
         NO  ──>  Investigate as standard network loop or broadcast storm
         YES ──>  CONFIRMED MAC FLOODING / CAM EXHAUSTION
                  1. Identify physical switch port.
                  2. Isolate/Shutdown Attacker Switch Port.
                  3. Clear switch dynamic CAM table.
                  4. Analyze PCAP for Plaintext Data Exposure.
                  5. Implement Port Security (MAC Limiting).
                  
   ```
## Final Attack Cheat Sheet

| Scope Dimension | Observed Extent |
| :--- | :--- |
| **Attack Name** | MAC Flooding / CAM Exhaustion | 
| **MITRE ATT&CK** | T1040 (Network Sniffing), T1498 (DoS) | 
| **Primary Objective** | Force Fail-Open state to sniff unicast traffic) |
| **Key Evidence** | Splunk Flow Anomalies, PCAP frame storms, Switch CPU logs | 
| **First Response Action** | Isolate Attacker Switch Port -> Clear Switch CAM Table) | 
| **Core Prevention** | Port Security (MAC Limit & Err-Disable) |
