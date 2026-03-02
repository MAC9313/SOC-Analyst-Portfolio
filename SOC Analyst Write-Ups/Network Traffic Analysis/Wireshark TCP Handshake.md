To establish a normal `TCP Connection,` a `TCP Three-Way Handshake` takes place that follow the flow of `SYN->SYN/ACK->ACK`.
![](attachments/Pasted%20image%2020251231165640.png)
There are many types of flags:

| Name                 | Meaning                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------ |
| Synchronization(SYN) | Used to create a TCP connection                                                            |
| Acknowledgement(ACK) | Used to acknowledge the reception of data or SYN packets                                   |
| Push(PSH)            | Instruct the network stacks to bypass buffering                                            |
| Urgent(URG)          | Indicates out of band data that must be processed by the network stacks before normal data |
| Finish(FIN)          | Gracefully terminate the TCP connection                                                    |
| Reset(RST)           | Immediately terminate the connection and drop any-in transmit data                         |
When performing packet analysis, there are some signs that a security analyst can look for to identify suspicious activity:
1. Too many flags of the same kind can identify scanning is occurring within the network.
2. The abnormal use of flags can indicate a TCP RST attack, hijacking, or an attempt for an intruder to stay hidden in their enumeration activities.
3. One host sending flags to multiple ports or hosts.
### Excessive SYN Flags
![](attachments/Pasted%20image%2020251231171804.png)
As can be seen by the PCAP above, there in an excessive amount of SYN scans be directed to `192.168.10.1` from `192.168.10.5.` This is indicative of an `NMAP SYN Scan` which will send numerous SYN packets to a server in an attempt to find a vulnerable port/service being open. If the port is open, the server will send the SYN/ACK response, which will be followed by scanning machine dropping the connection with a RST. By sending a RST instead of completing the handshake with an ACK, the scanner prevents the completion of the TCP connection from being logged by the target sever, making the scan more stealthy. If the port is closed, the scanning machine will receive a RST/ACK.

`View Open Ports That Sent A SYN/ACK To The Scanning Machine`
```Wireshark
tcp.flags.syn == 1 && tcp.flag.ack == 1
```
This filter only showed one result of a SYN/ACK response in the given PCAP file. Using the packet number, we're able to see that the scanning machine sent a RST packet to end the connection.

![](attachments/Pasted%20image%2020251231172513.png)

`Remediation`
It's important to note that the scanning machine is on the same network as the server that is being enumerated. Looking into the hardware address of the scanning machine and verifying the address with the asset inventory would be a wise next step. If not, then blocking the hardware would be warranted. If the address is company-owned and the activity was not an approved scan by the IT /Security team, then following the previous or subsequent events that may have taken place with the scanning address using a SIEM would be need to measure the extent of the compromise. 

`A Possible Splunk Query To Track Events Of The Suspicious Address`
```Splunk
index="main" sourcelog="WinEventLog:Sysmon" "192.168.10.5" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe")
sort _time
stats count by _time, CommandLine, Image, ParentImage 
```
### NULL Scans
`Identifying "Flagless" Packets Used for Firewall Evasion`
![](attachments/Pasted%20image%2020251231175416.png)

A **NULL scan** is a specialized TCP scanning technique where a packet is sent with **no flags set** (all control bits are 0). Because a standard TCP connection requires flags like `SYN` to initiate, a packet with no flags is technically invalid. As can be seen in the above PCAP, there are an excessive amount of packets containing no flags.

`Why Attackers Use NULL Scans` 
The primary goal of a NULL scan is to bypass stateless firewalls or Access Control Lists (ACLs) that are configured to only filter packets with specific flags (like `SYN`).
- **If the port is closed:** The target system will respond with a `RST/ACK` packet.
- **If the port is open/filtered:** The target system will typically ignore the packet and send no response at all.
Therefore, if an attacker doesn't get a response from a port/service, then they can assume that port is open. If that port is used by an unsecure protocol, then the attacker may have just found an easy way in. 

`Taking A Look At Vulnerable Ports That Responded To The Scanner`
```Wireshark
tcp.srcport in {21, 23, 25, 80, 445}
```

![](attachments/Pasted%20image%2020251231181316.png)

While not an exhaustive list, the PCAP filter above shows that all the ports listed are closed besides 80, which hosts HTTP. The `remediation` would follow the same logic as that for a `SYN Scan`. Essentially any type of abnormal TCP scanning attempts, whether it be ACK scans, FIN scans, or XMAS scans are looking for open ports that are hosting `unsecure and vulnerable` services. Looking for any excessive flows of TCP traffic that don't follow the typical three-way handshake is a clear indicator that more investigation is needed to see if scanning or malicious activity is taking place.

