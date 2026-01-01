### Project Overview
This investigation demonstrates a systematic approach to threat hunting and incident analysis using `Splunk`. By analyzing logs from the `Hack The Box (HTB) "Investigating With Splunk"` lab, I identify several Indicators of Compromise (IoCs) and trace an attacker's lifecycle from initial execution to lateral movement.

Beyond the standard lab requirements, this write-up includes `custom SPL queries` to identify `root cause analysis`utilizing Windows Sysmon events to provide a comprehensive look at the compromise. 
### Narrow Down Your Searches  
`Start Off By Finding The Source Types In The Data Set`
```SPL
index="main" 
| stats count by sourcetype
```
![](../attachments/Pasted%20image%2020251226183032.png)
`Query The Desired Source Type To Uncover Fields`
```SPL
index="main" sourcetype="WinEventLog:Sysmon"
```
![](../attachments/Pasted%20image%2020251226183841.png)

`Event Codes Can Uncover Valuable Information; Let's Find Out Which One's We're Working With`
```SPL
index="main" sourcetype="WinEventLog:Sysmon"
| stats count by EventCode
```
![](../attachments/Pasted%20image%2020251226184222.png)
`Use Preliminary Queries To Uncover Suspicious Parent/Child Relationships`
```SPL
index="main" sourcetype="WinEventLog:Sysymon" EventCode=1
| stats count by ParentImage, Image
```
![](../attachments/Pasted%20image%2020251226185822.png)
`Narrow Down Results By Searching For Processes That Are Often Used By Malicious Actors`
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe")
| stats count by ParentImage, Image
```
![](../attachments/Pasted%20image%2020251226190836.png)
Notice that notepad.exe is spawning both cmd.exe and powershell.exe. This is suspicious and worth investigating further.

`Further Look Into The Events Involving Notepad.exe`
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\notepad.exe"
| stats count by _time, ParentImage, CommandLine
```
![](../attachments/Pasted%20image%2020251227214604.png)
There are some very suspicious commands that were performed from notepad.exe. One of which appears to have downloaded a file from a server with the IP of 10.0.0.229. We can either investigate what initiated **notepad.exe** or we can look into other machines on the network that may have interacted with the IP in question. 
### Investigating The Actions Of The Suspicious IP
Due to the fact that malicious actions may have already been performed on the network, investigating the suspicious IP to find the extent of the compromise is appropriate. 
`Look Further Into 10.0.0.229`
```SPL
index="main" 10.0.0.229 
| stats count by sourcetype
```
![](../attachments/Pasted%20image%2020251227202346.png)
`Noticing That A Source Type From A Linux System Is Introduced In Our Search, Further Investigation Is Needed `
```SPL
index="main" 10.0.0.229 sourcetype="linux:syslog"
```
![](../attachments/Pasted%20image%2020251227203552.png)
From the results, it can be seen that 10.0.0.229 is held by a Linux machine. The fact that the Windows machine is communicating with a Linux machine by downloading executable files through PowerShell is concerning. This activity points to possible compromise of the Linux machine as well. Time to dig deeper!
`Look Into The Sysmon Logs`
```SPL
index="main" 10.0.0.229 sourcetype="WinEventLog:Sysmon"
| stats count by _time, CommandLine
```
![](../attachments/Pasted%20image%2020251227205509.png)
##### Escalation & Remediation Strategy
At this stage of the investigation, the activity observed (Tool Ingress, Lateral Movement, and Credential Staging) constitutes a `confirmed compromise `rather than a suspicious event. As a SOC Analyst, this incident must be escalated to the Incident Response (IR) or Tier 2 team. The presence of `SharpHound` and `DCSync` attempts suggests an advanced stage of the attack lifecycle (Actions on Objectives).

`Example Escalation Report Of Findings:`
##### Subject: CRITICAL INCIDENT: Active Lateral Movement and Credential Theft (10.0.0.229)

`Status: Critical / Active Breach`

**Summary:** We have identified a Linux host (10.0.0.229) acting as a command-and-control (C2) server. It is actively pushing malware and hacking tools to our Windows environment.

**Key Risks Identified:**
- **Credential Compromise**: Evidence of `DCSync` attacks and `lsass` memory dumping attempts. The account `UNIWALDO\Waldo` is confirmed compromised.
- **Lateral Movement:** The attacker has successfully moved from the initial victim to at least one other machine `(10.0.0.47)` using `PsExec`.
- **Tooling:** Attackers are deploying `SharpHound` (used for mapping Active Directory vulnerabilities).

**Recommended Immediate Actions:**
1. Isolate 10.0.0.229 and 10.0.0.47 from the network immediately.
2. Force a password reset for the UNIWALDO\Waldo account.
3. Begin a hunt for further activity using the hardcoded password found in the logs.

`Technical Breakdown Of Report`

| Command Component | Attacker Goal                                                                                | Severity | MITRE ATT&CK Technique                                |
| ----------------- | -------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------- |
| SharpHound.exe    | Enumeration: Mapping the entire Active Directory structure to find the path to Domain Admin. | High     | **T1087.002** (Account Discovery: Domain Account)     |
| DCSync.ps1        | Privilege Escalation: Impersonating a Domain Controller to steal all user password hashes.   | Critical | **T1003.006** (OS Credential Dumping: DCSync)         |
| psexec64.exe      | Lateral Movement: Using stolen credentials to take control of other systems.                 | High     | **T1570** (Lateral Tool Transfer)                     |
| comsvcs.dll       | Credential Dumping: Specifically used to dump lsass.exe to steal passwords from memory.      | Critical | **T1003.001** (OS Credential Dumping: LSASS Memory)\| |

`The Job Is Not Done Yet. Further Analysis Of The Hosts Executing These Commands Is Necessary`
```SPL
index="main" 10.0.0.229 sourcetype="WinEventLog:Sysmon:
| stats count by CommandLine, Hosts
```
![](../attachments/Pasted%20image%2020251227215603.png)
It appears that there are now two hosts that are under threat from the Linux machine. It also appears that the DCSync PowerShell script was executed on the second host , indicating a likely DCSync attack. 
### Investigating The Origins Of Notepad.exe
1. Use the **ParentProcessId** of notepad.exe as the **ProcessId** for the next query. Be alert when investigating by the process id. They are temporary and change processes frequently, so it may be a good idea to query by the process name. In our case, that is notepad.exe.
![](../attachments/Pasted%20image%2020251226211312.png)
`Stats Count The Event Code`
```SPL
index="main" Processid=7736 notepad.exe
| stats count by EventCode
```
![](../attachments/Pasted%20image%2020251226223515.png)

2. It may be beneficial to dive a little deeper into each of these event codes. Using Event Code 7: Image Loading, a query will be used to show the loaded dlls. Also, there will be example queries that show all the event codes being processed at once. Notice that most of the images are not notepad.exe, but this is still a good practice lesson. If you want to specifically search for notepad, then just simply add notepad.exe after the event code. 
`There May Be Duplicates In Some Of The Query Results. The Fields Will Need To Be Modified Depending On The EventCode `
```SPL
index="main" ProcessId=7736 EventCode=7
| dedup Image, ImageLoaded
| sort _time
| table _time, Image, ImageLoaded
```
![](../attachments/Pasted%20image%2020251226224956.png)

`This May Not Scale Well, But We'll Get A View Of All Event Codes Related To NotePad.exe`
```SPL
index="main" ProcessId=7736 
| stats values(EventCode) as EventID, 
        values(ImageLoaded) as dlls_loaded, 
        values(CommandLine) as cmd 
        by ProcessId, Image
```
![](../attachments/Pasted%20image%2020251226230310.png)

`Also May Not Scale Well, But It's A Pretty Dope Query That Taught Me Some Neat Tricks`
```SPL
index="main" ProcessId=7736 EventCode IN (1, 3, 7, 11, 13, 22)
| stats 
    values(Image) as process_path,
    values(CommandLine) as execution_cmd,
    values(ImageLoaded) as dlls_loaded, 
    values(QueryName) as dns_queries,
    values(DestinationIp) as network_conns,
    values(TargetFilename) as files_created,
    values(TargetObject) as registry_modified
    by ProcessId, _time, EventCode
| rename values(*) as * 
| sort - _time
```
![](../attachments/Pasted%20image%2020251226215529.png)
3. Enough playing around with neat, but probably unnecessary queries. With the data set in use, the Notepad.exe instance with process id 7736 has a total of 96 events. Start from the first instance of notepad and track it's activity before it makes a connection with the suspicious IP.
`Take Note That I Am In A HTB Lab Environment, Therefore Using The Messages(RuleName) In The Logs Is A Great Way To Learn What Events Are Unfolding. Not Only That, But All The Logs Have This Field In Common, So No Logs Will Be Left Out Of The Query Results`
```SPL
index="main" ProcessID=7736 notepad.exe
| table _time, EventCode, Image, Message
| sort _time
```
![](../attachments/Pasted%20image%2020251227000836.png)




