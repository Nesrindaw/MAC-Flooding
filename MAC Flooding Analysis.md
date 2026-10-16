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
