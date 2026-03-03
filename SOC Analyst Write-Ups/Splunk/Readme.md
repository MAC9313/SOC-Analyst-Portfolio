## Splunk: SIEM Operations & Threat Hunting

 This directory documents my process in using Splunk for security monitoring, incident triage, and forensic reconstruction. The projects within demonstrate a transition from high-level alerts to root-cause analysis using Search Processing Language (SPL).

### Technical Core Competencies

* **Robust SPL Querying**: Crafting complex searches across diverse indexes (linux-alert, win-alert, web-alert) and sourcetypes (linux_secure, WinEventLog:Sysmon, wineventlog:security).

* **Regex Data Extraction**: Using the rex command to perform field extraction on raw, unparsed logs (e.g., pulling action, username, and src_ip from Linux auth.log). 

* **Behavioral Detection (TTPs)**: Mapping attacker behavior to the MITRE ATT&CK framework, specifically identifying "Living off the Land" (LotL) techniques using native binaries like net.exe, whoami.exe, and certutil.exe. 

* **Forensic Pivoting**: Utilizing ProcessId and ParentProcessId to reconstruct process trees and identify malicious child processes spawned from legitimate parents (e.g., explorer.exe -> malware.exe -> cmd.exe). 

* **Statistical Analysis**: Leveraging stats, eval, and table commands to aggregate login attempts, identify brute-force patterns, and track lateral movement across network segments. 

### Investigative Methodology

* The documentation in this folder follows a standardized SOC workflow:Ingestion & Scoping: Identifying relevant sourcetypes and narrowing search parameters to minimize "noise."

* **Indicator Identification**: Hunting for Indicators of Compromise (IoCs) such as double-extension files (.pdf.exe), non-standard port communication (e.g., 8080), and typosquatted process names (e.g., PSEXECSCVCS.exe).
  
* **Cross-Log Correlation**: Correlating Windows Event Logs (EventCodes 4624/4625) with Sysmon (EventCode 1) and network telemetry to confirm successful unauthorized access.

* **Root Cause & Persistence**: Tracing the lifecycle of an attack back to "Patient Zero" and identifying persistence mechanisms like Scheduled Tasks (EventCode 4698). 
