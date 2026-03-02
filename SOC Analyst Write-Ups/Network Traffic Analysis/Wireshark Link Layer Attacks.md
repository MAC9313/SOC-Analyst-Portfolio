### ARP Spoofing
`Understanding Identity Impersonation at the Data Link Layer`

`ARP Spoofing` is a technique where an attacker sends falsified ARP messages onto a local area network to link their MAC address with the IP address of a legitimate host. Unlike a general "poisoning" attack that might target an entire subnet for discovery, `Spoofing` is typically a targeted strike aimed at a specific victim or the default gateway.

By successfully spoofing an identity, the attacker positions themselves as a "middleman" in the network conversation. This allows them to:
- **Intercept Traffic:** View sensitive data, such as login credentials or unencrypted session tokens, that were intended for the legitimate host.
- **Manipulate Data:** Alter the contents of network packets in real-time before forwarding them to the actual destination.
- **Session Hijacking:** Steal active web sessions by capturing the necessary cookies or tokens from the intercepted stream.
In the following analysis of `ARP_Spoof.pcapng`, we will identify how a single hardware address (`08:00:27:53:0C:ba`) systematically impersonates other network assets to gain unauthorized access to data streams.
`Streamline The View By Filtering For ARP Requests And Replies`
```Wireshark
arp.opcode
```

![](../attachments/Pasted image 20251231132834.png]]
At a glance, this traffic appears to be normal ARP traffic, but having a closer look shows that the source ARP request comes from host at `08:00:27:53:0C:ba | 192.168.10.5`, which subsequently starts sending ARP replies that states that `192.168.10.4` is at the `08:00:27:53:0C:ba`. This is a tell tale sign of ARP spoofing as the suspicious MAC address is telling the router to send it all communications that is destined for `192.168.10.4`

`Dig Further Into The ARP Traffic`
1. **Opcode == 1:** Represents ARP Requests
2. **Opcode == 2:** Represents ARP Replies

```Wireshark 
arp.opcode == 1
```

![[Pasted image 20251231134523.png]]![[Pasted image 20251231134652.png]]
A duplicate IP address is detected by Wireshark, which should warrant a further investigation into the hardware addresses that have this IP. The security analyst should view the asset inventory and ascertain if the addresses are owned by the company. If it is determined that the suspicious `08:00:27:53:0C:ba` is not part of the company owned hardware, then it should be blocked immediately. 

`Advanced Identification: Tracking Conflict and Unsolicited Replies`
In the refined analysis of `ARP_Spoof.pcapng`, we can observe a rapid succession of ARP operations where a single hardware address linked to `08:00:27:53:0C:ba`repeatedly asserts its identity across the subnet. A significant indicator of an active spoofing attack is the presence of **unsolicited unicast replies**.
- **Forced Identity:** The attacker is seen responding to queries for diverse IP addresses, such as in sources through, where the same MAC address is provided as the owner of different IP targets.
- **Gateway Impersonation:** A critical discovery in the packet stream shows the attacker claiming the MAC address `P๋๖์` (likely the gateway) while the true IP resides at `192.168.10.1`, creating a conflict with the attacker's actual IP of `192.168.10.5`.

Although it was already discovered that `08:00:27:53:0C:ba` had an original IP address of `192.168.10.5` , a large data set would've made gathering this valuable information difficult. Therefore, could hone in on the activity that took place from the suspicious hardware address.

```Wireshark
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
```

![[Pasted image 20251231141354.png]]

Observing the traffic from the two hardware addresses may lead to some insightful discoveries.
```Wireshark
eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba
```

![[Pasted image 20251231141648.png]]
There may be some inconsistencies with TCP connections, such as dropped connections due to an attacker not forwarding the traffic between the victim and the router. However, an attacker may forward traffic between the devices, potentially reading, manipulating, or exfiltrating sensitive data. Also known as a man in the middle attack.

`Mitigation and Defense`
If a security analyst identifies this pattern, the following remediation steps are recommended:
- **Dynamic ARP Inspection (DAI):** Configure switches to validate ARP packets against a trusted DHCP snooping database, dropping any packets with invalid MAC-to-IP bindings.
- **ARP Rate Limiting:** Implement rate limits on access ports to prevent a single compromised device from flooding the network with over 800 discovery requests .
- **Static ARP Entries:** For critical infrastructure like the default gateway, manual mapping of MAC to IP prevents the ARP cache from being poisoned by dynamic updates.
- **Immediate Isolation:** The suspicious MAC address ending in `0c:ba` should be isolated at the switch level and the physical port disabled for further forensic investigation.
### ARP Poisoning
`Detecting Cache Corruption and Host Discovery Floods`
While ARP Spoofing focuses on the identity theft of a specific host, **ARP Poisoning** is the act of injecting false entries into the ARP cache of victims to intercept, modify, or block traffic. In the provided capture `ARP_Poison.pcapng`, we observe a massive volume of ARP activity that deviates significantly from normal network behavior.

`Analyze Request-Based Poisoning` In many modern operating systems, the ARP cache is updated not only by replies but also by observing the source information in broadcast **requests**. An attacker can "poison" an entire subnet by sending a broadcast request claiming to be a specific IP, as every host that receives the broadcast may update its local table.

`Detecting ARP Poisoning By Searching For Requests `
```
arp.opcode == 1
```

![[Pasted image 20251231153349.png]]
 In this capture, we see a continuous flood of ARP requests coming from the device at hardware address `08:00:27:53:0c:ba` that is repeatedly querying for different IP addresses across the network.

`Identify Host Discovery and Scanning` A key characteristic of this attack is the **Host Discovery phase**. The attacker sweeps the network to see which IPs are active before choosing a target for interception.
1. **High Frequency:** Over 800 packets were captured in a very short duration, indicating an automated scanning tool.
2. **Repetitive Source:** The same hardware address is responsible for the vast majority of these queries .
3. **Target Variation:** The requests target a wide range of IP addresses to map the live assets on the subnet.

`Viewing The Replies That Were Sent Back To The Suspicious Hardware Address`
```Wireshark
arp.opcode == 2 && eth.dst == 08:00:27:53:0c:ba
```

![[Pasted image 20251231153932.png]]
The attacker now knows that these IP addresses are active on the network, which can then prompt the attacker to send false ARP replies to perform a man in the middle attack. Lets investigate if this activity took place.

`Viewing If Any ARP Replies Were Sent By The Suspicious Hardware Address `
```Wireshark
arp.opcode == 2 && eth.src == 08:00:27:53:0c:ba
```

![[Pasted image 20251231154910.png]]
These are very concerning results as the now confirmed malicious address `08:00:27:53:0c:ba` is sending multiple ARP replies to multiple addresses, including the gateway for the network. 
`Track The Duplicate Addresses`
```Wireshark
arp.duplicate-address-detected && arp.opcode == 2
```

Looking at the `Conversations` located in the `Statistics` drop down menu, it can be seen that th4 address at `08:00:27:53:0c:ba` was successful in spoofing 8 network addresses.
![[Pasted image 20251231160601.png]]
`Mitigation and Defense` 
If a security analyst identifies this pattern—where a single MAC address is claiming multiple IPs or flooding requests—the following steps should be taken:
- **Dynamic ARP Inspection (DAI):** Enable DAI on switches to validate ARP packets against a trusted DHCP snooping database. Packets with invalid bindings or those arriving on untrusted ports are dropped.
- **Rate Limiting:** Implement ARP rate limiting on access ports to prevent a single compromised device from flooding the network with discovery requests.
- **Static ARP Entries:** For high-value targets (like the default gateway or core servers), use static ARP entries to prevent the cache from being updated by dynamic (and potentially malicious) packets.
- **Isolation:** The suspicious MAC address (in this case, ending in `0c:ba`) should be immediately isolated and the physical port disabled until the device can be inspected for malicious software.
