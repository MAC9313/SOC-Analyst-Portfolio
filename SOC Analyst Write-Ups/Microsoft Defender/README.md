## Microsoft Defender for Endpoint (MDE) - Threat Hunting & IR

This section of the portfolio documents the practical application of Microsoft Defender for Endpoint in a Security Operations Center (SOC) environment. The focus is on leveraging telemetry to identify, analyze, and remediate security incidents.

`Technical Focus`

* **Kusto Query Language (KQL)**: Crafting precise queries to hunt through telemetry across various schemas, including DeviceProcessEvents, DeviceNetworkEvents, and AlertEvidence. 

* **Threat Hunting**: Proactively searching for "Living off the Land" (LotL) techniques, obfuscated scripts, and unauthorized persistence mechanisms. 

* **Data Parsing**: Utilizing KQL functions like todynamic() and parse_json() to extract actionable intelligence from nested data fields. 


* **Threat Intelligence Integration**: Validating internal telemetry against external intelligence sources and file reputation services. 

`Investigative Methodology`

Each investigation within this module follows a structured forensic approach:


* **Alert Triage**: Analyzing the fidelity of generated alerts to determine the scope of a potential compromise. 

* **Telemetry Pivoting**: Using initial indicators (IPs, Hashes, PIDs) to reconstruct a chronological timeline of attacker activity. 

* **Root Cause Analysis (RCA)**: Identifying the initial infection vector and "Patient Zero" to understand the entry point. 

* **Impact Assessment**: Determining the extent of lateral movement, data exfiltration, or persistence. 

* **Remediation**: Outlining tactical steps for containment, eradication, and system hardening.
