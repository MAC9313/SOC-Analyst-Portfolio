### Scenario 1
An alert about a possible `Brute-Force Attack` has came in. Using Splunk, we'll determine whether the alert was a `False Positive` or a confirmed threat. Using Linux auth.log, we will get a look into our logs and fields of interest. 
```SPL
index="linux-alert" sourcetype="linux_secure" 10.10.242.248   
| search "Accepted password for" OR "Failed password for" OR "Invalid user"  
| sort + _time
```
![](attachments/Pasted%20image%2020251229224638.png)
The first page of logs shows multiple attempts within seconds of an attempted connection to a user that doesn't exist. Further investigation is necessary.
`View The Number Of Login Attempts Per Each User`
```SPL
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```
`Explanation Of Query Using An Auth Log`
```
2025-09-17T09:06:35.029531+00:00 tryhackme-2404 
```

`| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"`

- **`^`**: Start at the very beginning of the string.
- **`\d{4}-\d{2}-\d{2}T`**: Matches `2025-09-17T`
- **`[^\s]+`**: Matches the timestamp (`09:06:35.029531+00:00`) because it matches every character that is **not** a space.
- **`\s+`**: Matches the space between the timestamp and the hostname.
- **`(?<log_hostname>\S+)`**: Captures **tryhackme-2404** because it is the next sequence of non-space characters.

```
sshd[3104]: Failed password for john.smith from 10.10.242.248 port 36706 ssh2
```
`| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"`
- **`sshd\[\d+\]:`**: Matches the literal string `sshd` followed by any digits inside brackets and a colon (`sshd[3104]:`).
- **`\s*(?<action>Failed|Accepted)`**: Matches the space, then captures **Failed** because it matches one of the two options (Failed or Accepted).
- **`\s+\S+\s+for`**: Matches the space, skips the word `password` (the `\S+` part), and matches the word `for`.
- **`(?: invalid user)?`**: Since this log does **not** contain the words "invalid user", this optional group is simply ignored by the engine.
- **`\s+(?<username>\S+)`**: Matches the space and captures **john.smith** as the username.
- **`from\s+(?<src_ip>...)`**: Matches the word `from` and captures the IP address **10.10.242.248**.

| Field        | Extracted Value |
| ------------ | --------------- |
| log_hostname | tryhackme-2404  |
| action       | Failed          |
| username     | john.smith      |
| src_ip       | 10.10.242.248   |
![](attachments/Pasted%20image%2020251229233234.png)
![](attachments/Pasted%20image%2020251229233436.png)
It can be seen that there were 503 attempts made on the john.smith account. Now to see if any of them were successful.
`Pro Tip: Simply Adding Signature="Accepted Password" And Cross-Referencing The Time The Brute-Force Attempt Took Place Will Give The Answer.`
![](attachments/Pasted%20image%2020251229234017.png)
However, if you hate yourself or you just want to practice regex, then you can use this query:
```SPL
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process  by username
```
A tool that can help your regex: [regex101](https://regex101.com/)

![](attachments/Pasted%20image%2020251229235204.png)
So, it is confirmed that there was a successful login attempt from the brute-force that appears to have happened from an internal IP. This leads to the question, how long has the threat actor been in the network....

### Scenario 2 Windows Workstation

```SPL
index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message
```
![](attachments/Pasted%20image%2020251230003803.png)
![](attachments/Pasted%20image%2020251230003829.png)
At this point, we can already see the first signs of malicious activity. This task will use `**certutil**` to download `**rv.exe**` from the **tryhotme** domain into the Temp folder under the name `**DataCollector.exe**`. It will then launch this file using a `**Start-Process**` PowerShell command. All of this activity will be executed under the user **oliver.thompson**. This is a clear example of persistence.

### Scenario 3

```SPL
index=web-alert 171.251.232.40  
| table _time clientip useragent uri_path method status   
| sort + _time
```
![](attachments/Pasted%20image%2020251230004915.png)

```SPL
index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)" 
| table  _time clientip useragent uri_path referer referer_domain method status
```
![](attachments/Pasted%20image%2020251230005205.png)

```SPL
index=web-alert 171.251.232.40 b374k.php  
| table _time clientip useragent uri_path referer referer_domain method status  
| sort + _time
```
![](attachments/Pasted%20image%2020251230005520.png)
![](attachments/Pasted%20image%2020251230005759.png)
