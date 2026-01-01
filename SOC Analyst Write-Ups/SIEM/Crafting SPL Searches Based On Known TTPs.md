### Introduction
In this write-up, I conduct a deep-dive investigation into the Hack The Box (HTB) module: **Detecting Attacker Behavior With Splunk Based On TTPs**. I developed this document to serve as both a technical portfolio piece and a comprehensive "cheat sheet" to support my continued growth as I grow in the cybersecurity field.

While this report aligns with the core HTB curriculum, I have intentionally gone "off-script" in several key areas. For example, the section Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com) goes significantly deeper than the actual lesson. In these sections, I move beyond simple detection to perform a full root cause analysis, tracing the activity from high-level tactical alerts back to the "Patient Zero" drive-by compromise.
### Detection Of Reconnaissance Activities Leveraging Native Windows Binaries
Attackers often leverage native Windows binaries (such as net.exe) to gain insights into the target environment, identify potential privilege escalation opportunities, and perform lateral movement. Sysmon Event ID 1(Process Creation) can assist in identifying such behavior.
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe 
| stats count by Image,CommandLine 
| sort - count
```
![](./attachments/Pasted%20image%2020251228175515.png)
### Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com)
Attackers often utilize GitHub as a hosting platform for their payloads, therefore monitoring for this network traffic can result in good findings.
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22  QueryName="*github*" | stats count by Image, QueryName
```
![](./attachments/Pasted%20image%2020251228180230.png)

`Dig Deeper Into Activity Being Performed On GitHub`
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 "*github*" 
| stats count by _time, User, Image, CommandLine
```
![](./attachments/Pasted%20image%2020251228180623.png)
Further research shows that https://github.com/l4rm4nd/ is a repository containing hacking tools, therefore further investigation is needed. 
`By Simply Looking Into The Event, Adding A Time Range Of 5+ Hours, And Modifying The Query, We're Able To Get Some Valuable Output`
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
| stats count by _time, Image, CommandLine
```
![](./attachments/Pasted%20image%2020251228182226.png)
It can be seen that malicious events are taking place within the network and immediate containment of the affected hosts should be performed.
##### The Malicious Toolkit And Intent

| Time     | Activity           | Command/Tool                             | Risk Level | Severity & Impact                                                                                                    |
| -------- | ------------------ | ---------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------- |
| 12:42:38 | Initial Staging    | iex (Invoke-Expression) via GitHub       | Critical   | Attacker downloads and executes a malicious script (likely Invoke-DCSync) directly into memory.                      |
| 12:43:37 | Memory Dump        | WerFault.exe -pss -p 11072               | High       | The attacker is using a legitimate Windows tool to dump the memory of a process (likely LSASS) to steal credentials. |
| 12:45:22 | AD Enumeration     | powershell get-netdomain                 | Medium     | Mapping the domain structure and identifying high-value targets (Domain Controllers).                                |
| 12:46:44 | DC Discovery       | nslookup uniwaldo.local                  | Medium     | Finding the IP address of the Domain Controller to target it for replication attacks.                                |
| 12:47:02 | Second Memory Dump | WerFault.exe -pss -p 3960                | High       | A second attempt or targeting a different high-privilege process to harvest more secrets.                            |
| 12:47:11 | DCSync Success     | notepad.exe ...DCSync_NTLM_LOGFILE.txt   | Critical   | The "Game Over" moment. Attacker has successfully dumped NTLM hashes for the domain and is reviewing the results.    |
| 12:47:18 | Data Review        | notepad.exe ...\_DCSync_NTLM_LOGFILE.txt | Critical   | Reviewing a second log file, likely containing different sets of domain credentials or the KRBTGT hash.              |
##### Tracking Root Cause 
First, I tracked down the ComputerName that initiated the powershell command to GitHub.
![](./attachments/Pasted%20image%2020251228185937.png)
Next, by using Splunks built-in feature, I filtered for the events that happened within the last hour of the download. Using this query, I sorted the times from earliest to latest and looked for any process creations. 
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 ComputerName="DESKTOP-UN7T4R8.uniwaldo.local" 
| sort _time
| stats count by _time, Image, CommandLine
```
![](./attachments/Pasted%20image%2020251228190630.png)
There is a lot to be concerned with, but I decided to look into the log with the CommandLine invoking DCsync. The parent command line shows as \\10.0.0.47\C$\Windows\PSEXECSCVCS.exe. This is a major red flag as the PSExecSvcs is typosquatted to masquerade as a legitimate Windows process. A tell-tale sign of malware. 
Also, the path: `\10.0.0.47\C\$\\Windows\\PSEXECSCVCS.exe` indicates that this executable was pushed to a machine over the network using an Administrative Share (C$).
 This is a textbook sign of Lateral Movement. An attacker who has already compromised one machine (likely 10.0.0.47) is now using stolen credentials to spread to other machines on the network.
`Using Windows Security Logs, We Dive Deeper Into The IP`
```SPL
index="main" sourcetype="wineventlog:security" "10.0.0.47" 
| stats count min(_time) as first_seen max(_time) as last_seen by Source_Network_Address, Account_Name, Workstation_Name
| rename Source_Network_Address as Source_IP, Account_Name as Compromised_Account
| sort - last_seen
```
![](./attachments/Pasted%20image%2020251228195516.png)
The machine 10.0.0.253 used the account waldo to establish a network connection to the victim machine. 
`Verify If There Are Any Strange Login Occurances Using Event Codes 4624 and 4625`
```SPL
index="main" "10.0.0.253" EventCode=4624 OR EventCode=4625
| stats count by _time, EventCode
```
![](./attachments/Pasted%20image%2020251228204951.png)
It can be noticed that there were 14 failed login attempts before a successful login attempt in a very short amount of time, indicating a brute force attack. It would now appear that the `10.0.0.253` machine is also compromised.
`Look Into When 10.0.0.253 Was Compromised`
```SPL
index="main" DestinationIp="10.0.0.253" 
| sort _time 
| stats count by SourceIp
```
![](./attachments/Pasted%20image%2020251228205922.png)
The IP Address 10.0.0.230 can be seen, as well as a broadcast address. We'll further look into the 10.0.0.230 address.
```SPL
index="main" "10.0.0.230" 
| sort _time
```
There are too many results to sift through, so after looking at some of the fields, I decide to hone in on Event Code 15.
```SPL
index="main" "10.0.0.230" EventCode=15 
| dedup Image, TargetFilename
| sort _time 
| stats count by _time, Image, TargetFilename
```
![](./attachments/Pasted%20image%2020251228211605.png)
Alas, it appears that we have found `Patient-Zero`, which was performed through a drive-by compromise. `Demon.dll` is the primary agent (implant) for the Havoc C2 Framework.

`Havoc` is a modern, open-source Command and Control framework that has become a popular alternative to Cobalt Strike. The "Demon" agent is the part that sits on the infected machine, waits for commands from the attacker, and executes them. It is highly evasive and uses advanced techniques to bypass EDR (Endpoint Detection and Response) systems.
### Detection Of PsExec Usage
`PsExec`, a part of the Windows Sysinternals suite, is a lightweight telnet-replacement that allows system administrators to execute processes on remote systems. It is accessible to members of the Local Administrator group and provides a full interactive command-line interface without requiring manual installation of client software.
##### Mechanism Of Action
`PsExec` operates through a specific sequence of events:
1. **File Transfer:** It copies a service executable (`PSEXESVC.exe`) to the remote system's hidden Admin$ share.
2. **Service Installation**: It utilizes the `Windows Service Control Manager (SCM)` API to create and start a service on the target machine.
3. **Communication:** The service establishes a connection back to the source machine using named pipes for input/output.
4. **Privilege Escalation:** A key feature is its ability to run processes as NT AUTHORITY\SYSTEM, providing the highest level of local privilege.
##### Adversary Use & MITRE ATT&CK Mapping
Because PsExec is a legitimate administrative tool already present in many environments, malicious actors use it for `"living off the land"` to avoid detection.

| Technique ID | Name                                      | Description                                                                       |
| ------------ | ----------------------------------------- | --------------------------------------------------------------------------------- |
| T1569.002    | System Services: Service Execution        | Adversaries use PsExec to execute commands by installing it as a Windows service. |
| T1569.002    | Remote Services: SMB/Windows Admin Shares | PsExec relies on SMB and administrative shares to move the executable.            |
| T1570        | Lateral Tool Transfer                     | It is frequently used to move tools or malware laterally across a network.        |

Here are some good articles that can be of use for detecting PsExec. [Traces of Windows remote command execution](https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution) and [Splunking with Sysmon Part 3: Detecting PsExec in your Environment](https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/). By studying these two sources, it can be deduced the Sysmon Event ID's 11, 13, 17, and 18 can assist in locating usage of PsExec.
`Levaraging Sysmon Event ID 13`
```SPL
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" 
| rex field=Details "(?<reg_file_name>[^\\\]+)$" 
| eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) 
| stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
```
This query is looking for instances where `services.exe` process has modified the `ImagePath` value of any service. The output will include the details of these modifications, including the name of the modified service, the new ImagePath value, and the time of the modification.

**Breaking Down The Query:**

`EventCode 13:` 
Represents an event where a registry value was set.

`Image:` `C:\\Windows\\system32\\services.exe`

Used to filter for events where services.exe process was involved, which is a Windows process responsible for handling service crreation and management.

`TargetObject:` `HKLM\\System\\CurrentControlSet\\Services.` 

This field is looking for any changes in the `ImagePath`value under any(\*) service key in `TargetObject` The `ImagePath` registry value of a service specifies the path to the executable file for the service.

`| rex field=Details "(?<reg_file_name>[^\\\]+)$":` 

The rex command is extracting the filename from the `Details` field using a regular expression. The pattern `[^\\\]+)$` captures the part of the path after the last backslash, which is usually the file name. This value is stored in a new field `reg_file_name.`

Original

![](./attachments/Pasted%20image%2020251228172508.png)

Extracted
![](./attachments/Pasted%20image%2020251228172131.png)
Take note that the rex command extracted CredentialEnrollmentManager.exe from the details section and the following eval command changed all characters to lowercase and placed the output to the file_name value.
`| eval file_name = if(isnull(file_name),reg_file_name,(file_name)):`
The eval command checks if the `file_name` field is null. If it is, it sets `filename` to the value of `reg_file_name`. If `file_name`is not null, then it remains the same.

**Results Of The Query**
![](./attachments/Pasted%20image%2020251228174444.png)

### Detection Of Utilizing Archive Files For Transferring Tools Or Data Exfiltration
