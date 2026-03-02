### Scenario
An alert was generated from Microsoft Defender for a suspicious .NET assembly process being loaded. Using the Advanced Hunting, the investigation begins:

`Querying The Alert ID`
```KQL
AlertEvidence
| where AlertId == "da6871540c-a97f-40cf-992c-2102257ea8dd_1"
| sort by TimeGenerated desc
| project-order TimeGenerated, ProcessCommandLine
```

![](attachments/Pasted%20image%2020260228205922.png)

It was discovered that the user SOC-Administrator on Desktop2 from a remote IP connection of 192.168.112.129 initiated the command. Upon discovery of obfuscated PowerShell commands, the Base64 was decoded in CyberChef. After one round of Base64 decoding, the following find and replace algorithm was used to further break down the string:

```Recipe
Find_/_Replace({'option':'Regex','string':'\'\\s*\\+\\s*\''},'',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'iec'},'\'',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'p45'},'$',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'jxV'},'"',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'jRI'},'|',true,false,true,false)
```

The final result provided a clearer picture for the objective of the command: 
![](attachments/Pasted%20image%2020260228200307.png)

Following .Replace() in the obfuscated code, the URL corresponds to `hxxp[://]144[.]172[.]100[.]220/img/optimized_MSI[.]png`, which appears to download a file named `Name_File` in the C:\Users\Public\Downloads folder. Upon further deconstruction of the encoding, this is confirmed:
![](attachments/Pasted%20image%2020260228201656.png)

Further investigation through VirusTotal shows that the URL is from a known "`highly sophisticated RAT`"

![](attachments/Pasted%20image%2020260228195744.png)

Query to find more information into `name_file.js`
![](attachments/Pasted%20image%2020260228203108.png)

`Query to search for events regarding name_file.js`
```KQL
union DeviceEvents, DeviceFileEvents, DeviceProcessEvents, SecurityAlert, AlertEvidence
| where * has "Name_File.js"
| summarize arg_min(TimeGenerated, *) by ProcessCommandLine
| sort by TimeGenerated asc
| project-reorder TimeGenerated, AccountName, ProcessCommandLine
```

![](attachments/Pasted%20image%2020260228205517.png)

At this point, it would be time to escalate the issue to SOC level 2 as it is clear that the obfuscated Powershell command reached out to a known malicious url to download a file. Furthermore, after downloading the file another Powershell command was used to silently gain persistence onto the system. In my professional opinion, the Desktop should be quarantined from the rest of the network so that any malicious processes/scheduled tasks can be removed.
### Root Cause Analysis
First and foremost, I want to see when the SOC-Administrator account started exhibiting abnormal behavior. The initial suspicious events occurred around 02-28 12:12:54 UTC time. By looking at the timeline on Defender alerts, we see a suspicious login from an external address. 
![](attachments/Pasted%20image%2020260228232550.png)

Next, querying virus total gives the following results:
![](attachments/Pasted%20image%2020260228232820.png)

It is unclear whether or not the IP address is malicious in nature as it appears to be a VPN located in the UK. Further investigation is needed. However mere seconds afterwards, the remote session initiator IP of 192.168.112.129 is established.  To obtain a better look into the events that took place after the connection 192.168.112.129 initiated, the following query was executed:

```KQL
AlertEvidence
| extend ParsedFields = todynamic(AdditionalFields)
| extend RemoteIP = tostring(ParsedFields.RemoteSessionInitiatorIpAddress.Address)
| where RemoteIP == "192.168.112.129"
| project-reorder TimeGenerated, RemoteIP, ProcessCommandLine
| sort by TimeGenerated desc
```

![](attachments/Pasted%20image%2020260228213527.png)

The same commands that were observed in the initial investigation appear. I decided to look up the PID of the alert to observe if it spawned any processes. The parent process id is located in the `AdditionalFields` section, therefore needs to be parsed.
![](attachments/Pasted%20image%2020260228160351.png)

`Querying to view spawned processes from the powershell instances`
```KQL
AlertEvidence
| extend ParsedFields = todynamic(AdditionalFields)
| extend PPID = tostring(ParsedFields.ParentProcess.ProcessId)
| where PPID in (9884, 2716, 4480)
| project Timestamp, DeviceName, FileName, PPID
```

`Querying to view the parent process of the suspicious obfuscated powershell event`
```KQL
AlertEvidence
| extend ParsedFields = todynamic(AdditionalFields)
| extend PID = tostring(ParsedFields.ProcessId)
| where PID == "9084"
| project-reorder Timestamp, DeviceName, FileName, PID
```

For this particular event, no parent process is found for the obfuscated Powershell command and the different process that were spawned from it did not create any new processes. Now to dig deeper into the SOC-Administrator account to view activities before and after the execution of the obfuscated commands. 

```KQL
AlertEvidene
| extend ParsedFields = todynamic(AdditionalFields)
| extend Account = tostring(ParsedFields.Account.Name)
| where Account == "SOC-Administrator"
```

![](attachments/Pasted%20image%2020260228164600.png)


```KQL
AlertEvidence
| extend ParsedFields = todynamic(AdditionalFields)
| extend Account = tostring(ParsedFields.Account.Name)
| where Account == "SOC-Administrator"
// arg_min keeps only the earliest instance of each unique command line.
| summarize arg_min(TimeGenerated, *) by ProcessCommandLine
| sort by TimeGenerated desc
| project TimeGenerated, Account, ProcessCommandLine
```

![](attachments/Pasted%20image%2020260228183109.png)

Upon detection, 
`Query for all tables containg the javascript file`
```KQL
search "New Purchaee Order 00045757.js" 
| summarize count() by $table
```

`Query for events relating to the javascript file in the discovered tables`
```KQL
union DeviceProcessEvents, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents, BehaviorEntities, SecurityAlert, AlertEvidence
| where * has "New Purchaee Order 00045757.js"
| sort by TimeGenerated asc
//project-reorder simply changes the order of the fields, without removing the fields that are not selected.
| project-reorder TimeGenerated, Type, ProcessCommandLine, FileName
```

![](attachments/Pasted%20image%2020260301134540.png)

Upon acquiring the file hash of New Purchaee Order 00045757.js, it was determined that the file is malicious. 
![](attachments/Pasted%20image%2020260301134954.png)

Looking into events that preceded this file do not indicate that the file was downloaded from the web or an email attachment. Further investigation shows no indication of when the file originated, but the abnormal behavior where Desktop-2 reached out to the malicious domain happened after the interaction with the malicious file. This is a lab environment and files are discarded after 30 days, which may be the cause resulting in lack of telemetry for the origination of the file. Regardless, New Purchaee Order appears to be patient zero!

![](attachments/Pasted%20image%2020260301141409.png)
