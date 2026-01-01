### Executive Summary
An investigation was launched into a suspicious file download and execution on host `DESKTOP-ND6FH5D`. The attack involved a drive-by compromise resulting in high-integrity process execution, manual reconnaissance, and the creation of a backdoor administrative account.
### Initial Access & Network Analysis
The investigation began by identifying abnormal network connections. A file with a double extension, `application_form.pdf.exe`, was downloaded from a remote IP using a non-standard port.

`Event ID 3`: Logs TCP/UDP network connections made by processes, including source and destination IP addresses, ports, and associated process details. Useful for detecting command-and-control (C2) communications. 
`Obtain Fields Of Interest`
```SPL
source="sysmon.json" "Event.System.EventID"=3
```
![](../attachments/Pasted%20image%2020251229154439.png)

`Use The Utc Time, User, And Image Filters`
```SPL
 source="sysmon.json" "Event.System.EventID"=3 
 | stats count by Event.EventData.UtcTime, Event.EventData.User, Event.EventData.Image
```
![](../attachments/Pasted%20image%2020251229160719.png)
As can be seen above, the download of the double extension file has taken place.

### Investigating The Suspicious Payload
`Look Further Into The Suspicious File`
```SPL
source="sysmon.json" "application_form.pdf.exe" 
| sort Event.System.TimeCreated.#attributes.SystemTime
```
![](../attachments/Pasted%20image%2020251229165008.png)
The URL `http://13.232.55.12:8080/` uses port `8080`. While 8080 is often used for legitimate web development, it is also a favorite for attackers hosting temporary `Staging Servers` or `C2 (Command & Control)` infrastructure because it often bypasses basic firewall filters that only look at port 80 or 443.
`Looking Into The Suspicious IP`
```SPL
source="sysmon.json" Event.EventData.DestinationIp="13.232.55.12" 
| eval UtcTime='Event.EventData.UtcTime'
| table UtcTime, Event.EventData.ProcessId, Event.EventData.DestinationIp, Event.EventData.DestinationPort
```
![](../attachments/Pasted%20image%2020251229193822.png)
### Execution & Process Tree Analysis
```
source="sysmon.json" "application_form.pdf.exe"   "Event.System.EventID"=1 
| sort Event.EventData.UtcTime 
| stats count by Event.EventData.UtcTime, Event.EventData.ParentImage, Event.EventData.Image
```
![](../attachments/Pasted%20image%2020251229173349.png)
1. **Manual Execution:** The fact that `explorer.exe` spawned `application_form.pdf.exe` confirms that the user likely went into their Downloads folder and **double-clicked** the file. This wasn't a silent exploit; it was successful social engineering.
2. **The Pivot:** Almost immediately (about 48 seconds later), the malware spawned `cmd.exe`. That 48-second gap is often the time it takes for the malware to initialize, check for an internet connection, or decrypt its internal payload before dropping to a shell.
### Post-Exploitation Reconnaissance
In order to follow the events that take place after cmd.exe is spawned, I use the Process ID of cmd.exe(3520) and label it as the parent to see what commands are executed. 
```SPL
source="sysmon.json" Event.EventData.ParentProcessId=3520 
| sort Event.EventData.UtcTime 
| stats count by Event.EventData.UtcTime, Event.EventData.ParentImage, Event.EventData.Image, Event.EventData.CommandLine
```
![](../attachments/Pasted%20image%2020251229183721.png)
As can be seen by the logs, Post Exploitation Reconnaissance is taking place:
- **`whoami.exe`**: The attacker is checking their privileges. Since you already saw this shell has `High Integrity`, they now know they have administrative rights.
- **`tasklist.exe`**: They are looking for security software (Antivirus, EDR, or Sandbox tools) that might detect them.
- **`net.exe`**: Enumerating users and groups; specifically used for the creation of the `jumpadmin` backdoor account.
- **`powershell.exe`**: This is the "Main Event." Attackers move from `cmd.exe` to PowerShell because it is much more powerful for fileless attacks, obfuscation, and interacting with the Windows API. 
### PowerShell Activity 
`Look Up PowerShell Commands Using It's Process ID(8208)`
```SPL
source="sysmon.json" Event.EventData.ParentProcessId=8208 
| sort Event.EventData.UtcTime 
| stats count by Event.EventData.UtcTime, Event.EventData.CommandLine
```
![](../attachments/Pasted%20image%2020251229174903.png)
`Tracking PowerShell Activity`
```SPL
source="sysmon.json" (Event.EventData.ProcessId=8208 OR Event.EventData.ParentProcessId=8208)
| table Event.EventData.UtcTime, Event.EventData.Image, Event.EventData.OriginalFileName, Event.EventData.TargetFilename, Event.EventData.CommandLine
| sort Event.EventData.UtcTime
```
![](../attachments/Pasted%20image%2020251229193017.png)
### Remediation Steps (Containment & Eradication)

Since the attacker gained `High Integrity` access and established persistence, the following steps are critical:
- **Isolate the Host:** Immediately disconnect `DESKTOP-ND6FH5D` from the network to prevent further Command & Control (C2) communication or lateral movement.
- **Remove Backdoor Accounts:** Delete the `jumpadmin` account created by the attacker via the `net user` command.
- **Terminate Malicious Processes:** Kill any active instances of `application_form.pdf.exe` (PID 1464), `cmd.exe` (PID 3520), and `powershell.exe` (PID 8208).
- **Block Malicious Infrastructure:** Blacklist the IP `13.232.55.12` and block traffic on ports `8080` and `30` at the perimeter firewall.
- **Clean Temporary Directories:** Securely delete the malicious executable and any scripts located in `C:\Users\LetsDefend\Downloads\` or `C:\Windows\Temp\`.
###  Prevention & Mitigation Strategies
To prevent a user from downloading and executing a double-extension file like `application_form.pdf.exe` in the future, implement these defensive layers:
#### **1. Technical Controls**
- **Disable "Hide Extensions for Known File Types":** By default, Windows hides `.exe` extensions. Disabling this via GPO ensures a user sees `file.pdf.exe` instead of just `file.pdf`.
- **AppLocker or Software Restriction Policies (SRP):** Prevent executables from running directly out of the `Downloads` or `Temp` folders.
- **Attack Surface Reduction (ASR) Rules:** Enable Microsoft Defender ASR rules specifically designed to block "untrusted and unsigned processes that run from USB" or "executable content from email client and webmail."
- **PowerShell Constrained Language Mode:** Enforce Constrained Language Mode to limit the ability of scripts to call sensitive Windows APIs, which would have hindered the attacker's use of `UrlMon.dll`
#### **2. Security Tooling**
- **Endpoint Detection and Response (EDR):** Deploy an EDR that flags suspicious parent-child relationships, such as a web browser spawning a high-integrity command shell.
- **Web Content Filtering:** Use a secure web gateway to block connections to known malicious IPs or non-standard ports (like 8080 or 30) for standard user workstations.
#### **3. User Awareness**
- **Social Engineering Training:** Conduct simulation training to help users identify the "double extension" trick and the dangers of downloading unexpected attachments from the web.
