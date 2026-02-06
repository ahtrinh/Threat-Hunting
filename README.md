# Threat Hunt Report: ❌ Crosscheck

**Participant:** Alex Trinh
**Date:** February 2026


## Platforms and Languages Leveraged
- Log Analytics Workspaces (Microsoft Azure)
- Kusto Query Language (KQL)

## Scenario
At the onset of December, routine monitoring detects irregular access patterns during year-end compensation and performance review activities. 

What initially appears as legitimate administrative and departmental behavior reveals a multi-stage sequence involving unauthorized script execution, sensitive file access, data staging, persistence mechanisms, and outbound communication attempts. 

Participants must correlate endpoint telemetry across multiple user contexts and systems to reconstruct the full access chain and determine how year-end bonus and performance data was accessed, prepared, and transmitted.

### High-Level IoC Discovery Plan
- **Check `DeviceProcessEvents`** to identify unauthorized PowerShell execution, execution-policy bypass activity, and suspicious system utility usage.
- **Check `DeviceFileEvents`** to identify sensitive employee artifact access, shortcut creation behavior, data staging, and archive generation.
- **Check `DeviceNetworkEvents`** to identify anomalous remote session activity, outbound connection attempts, and attacker-controlled egress destinations.

---

### 🚩 1. Initial Execution Detection

Objective: 
Determine which endpoint first shows activity tied to the user context involved in the chain.

What to Hunt: 
Process telemetry where a specific local account is observed. Use this to identify the associated device.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-08))
| where FileName contains "powershell"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="390" height="68" alt="image" src="https://github.com/user-attachments/assets/779fe6b3-c894-4d5b-b5a5-53f0564cddcb" />

Question :Identify the DeviceName in question

<details>
<summary>Click to see answer</summary>
  
  Answer: `sys1-dept`
</details>

---

### 🚩 2. Remote Session Source Attribution

Objective: 
Identify the remote session source information tied to the initiating access on the first endpoint.

What to Hunt: 
Remote session metadata (source IP) for the remote session device involved in early activity on the first system.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-03) .. datetime(2025-12-08))
| where DeviceName == "sys1-dept"
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| project TimeGenerated, DeviceName,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessRemoteSessionIP,
          RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="671" height="145" alt="image" src="https://github.com/user-attachments/assets/0583cbcb-8871-4be4-a875-74a931fedc9d" />

Question: Provide the IP of the remote session accessing the system

<details>
<summary>Click to see answer</summary>
  
  Answer: `192.168.0.110`
</details>

---

### 🚩 3. Support Script Execution Confirmation

Objective: 
Confirm execution of a support-themed PowerShell script from a user-accessible directory.

What to Hunt: 
PowerShell process creation referencing execution of a script located under the user profile (commonly Downloads).

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-03) .. datetime(2025-12-08))
| where FileName == "powershell.exe"
| where ProcessCommandLine has "-File"
| where ProcessCommandLine contains @"C:\Users\"
| where ProcessCommandLine contains @"\Downloads\"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="778" height="127" alt="image" src="https://github.com/user-attachments/assets/3d6e87e9-2f25-42a4-98fd-621658e84861" />

Question: What was the command used to execute the program?

<details>
<summary>Click to see answer</summary>
  
  Answer: `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1`
</details>

---

### 🚩 4. System Reconnaissance Initiation

Objective: 
Identify the first reconnaissance action used to gather host and user context.

What to Hunt: 
Execution of common reconnaissance utilities and command patterns used to enumerate identity, sessions, and active processes.

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where AccountName == "5y51-d3p7"
| where Timestamp >= datetime(2025-12-01)
| where InitiatingProcessFileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Get-Process", "tasklist", "-ExecutionPolicy Bypass", "Get-LocalUser", "Get-LocalGroup",
"Get-LocalGroupMember Administrators", "Get-DomainUser","Get-DomainGroup","Get-DomainComputer", "whoami","net user", "Get-LocalUser", "nltest", "query user", "quser")
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

```
<img width="588" height="146" alt="image" src="https://github.com/user-attachments/assets/3a29fa66-742a-41cb-a8da-e8652f2c8d7d" />

Question: Identify the first recon command attempted

<details>
<summary>Click to see answer</summary>
  
  Answer: `"whoami.exe" /all`
</details>

---

### 🚩 5. Sensitive Bonus-Related File Exposure

Objective: 
Identify the first sensitive year-end bonus-related file that was accessed during exploration.

What to Hunt: 
Process activity indicating discovery behavior around bonus-related content, and confirm which sensitive file is involved.

```kql
DeviceProcessEvents
| where InitiatingProcessAccountName == "5y51-d3p7"
| where Timestamp >= datetime(2025-12-01)
| where ProcessCommandLine contains "bonus"
| project Timestamp, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="822" height="125" alt="image" src="https://github.com/user-attachments/assets/97831cd4-05e6-4fad-a6e6-78c9392281d9" />

Question: Which sensitive file was likely targeted by actor(s)?

<details>
<summary>Click to see answer</summary>
  
  Answer: `BonusMatrix_Draft_v3.xlsx`
</details>

---

### 🚩 6. Data Staging Activity Confirmation

Objective: 
Confirm that sensitive data was prepared for movement by staging into an export/archive output.

What to Hunt: 
File creation activity consistent with archived/exported content and extract the initiating process identifier.

```kql
DeviceFileEvents
| where Timestamp >= datetime(2025-12-03)
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName == "5y51-d3p7"
| where FileName has_any ("export", "archive")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessUniqueId, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="814" height="87" alt="image" src="https://github.com/user-attachments/assets/5353b71f-58f5-421d-b74c-df3f960ca6a3" />

Question: Identify the ID of the initiating unique process

<details>
<summary>Click to see answer</summary>
  
  Answer: `2533274790396713`
</details>

---

### 🚩 7. Outbound Connectivity Test

Objective: 
Confirm that outbound access was tested prior to any attempted transfer.

What to Hunt: 
A PowerShell-driven network connection to a benign external endpoint and determine the earliest reach attempt.

```kql
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName == "5y51-d3p7"
| where TimeGenerated >= datetime(2025-12-01)
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))   // external only
| order by TimeGenerated asc
| project TimeGenerated, InitiatingProcessAccountName,ActionType, RemoteIP, RemotePort, Protocol, InitiatingProcessCommandLine
```
<img width="569" height="129" alt="image" src="https://github.com/user-attachments/assets/e5b765e0-65b1-4c2c-b014-7b4a913d7d88" />

Question: When was the first outbound connection attempt initiated?

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-12-03T06:27:31.1857946Z`
</details>

---

### 🚩 8. Registry-Based Persistence

Objective: 
Identify evidence of persistence established via a user Run key.

What to Hunt: 
Registry modifications under the standard user Run path that indicate an auto-start execution mechanism.

```kql
DeviceRegistryEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >= datetime(2025-12-03)
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryKey startswith "HKEY_CURRENT_USER"
| where ActionType in ("RegistryValueSet","RegistryValueModified")
| project Timestamp,
          RegistryKey,
          RegistryValueName,
          RegistryValueData,
          InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="827" height="114" alt="image" src="https://github.com/user-attachments/assets/cbd38562-6d9c-4622-bce8-1f3d15386432" />

Question: Provide the associated RegistryKey value

<details>
<summary>Click to see answer</summary>
  
  Answer: `HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
</details>

---

### 🚩 9. Scheduled Task Persistence

Objective: 
Confirm a scheduled task was created or used to automate recurring execution.

What to Hunt: 
Scheduled task creation/execution via command line, focusing on the task name used.

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName == "5y51-d3p7"
| where TimeGenerated >= datetime(2025-12-01)
| where ProcessCommandLine contains "/SC"
|project TimeGenerated, InitiatingProcessAccountName, ProcessCommandLine, FileName, InitiatingProcessFileName
```
<img width="802" height="115" alt="image" src="https://github.com/user-attachments/assets/7a4fd3e0-ca42-48c0-9e64-f2e7cdc4fc9b" />

Question: What was the Task Name value tied to this particular activity?

<details>
<summary>Click to see answer</summary>
  
  Answer: `BonusReviewAssist`
</details>

---

### 🚩 10. Secondary Access to Employee Scorecard Artifact

Objective: 
Identify evidence that a different remote session context accessed an employee-related scorecard file.

What to Hunt: 
File telemetry involving an employee scorecard artifact and determine which remote session device is associated.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-03) .. datetime(2025-12-08))
| where DeviceName == "sys1-dept"
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| project TimeGenerated, DeviceName,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          RemoteIP, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated desc
```
<img width="916" height="236" alt="image" src="https://github.com/user-attachments/assets/edf1e12f-08a0-4ea8-b813-0546dbb09edd" />

Question: Identify the other remote session user that attempted to access employee related files

<details>
<summary>Click to see answer</summary>
  
  Answer: `YE-HELPDESKTECH`
</details>

---

### 🚩 11. Bonus Matrix Activity by a New Remote Session Context

Objective: 
Identify another remote session device name that is associated with higher level related activities later in the chain.

What to Hunt: 
File events related to bonus payout related artifacts and extract the remote session device metadata.

```kql
DeviceNetworkEvents
| where TimeGenerated >=(datetime(2025-12-03))
| where DeviceName == "sys1-dept"
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| project TimeGenerated,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          RemoteIP, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated desc
```
<img width="920" height="125" alt="image" src="https://github.com/user-attachments/assets/b15d2789-acde-48c0-b542-e89a66d0c604" />

Question: Identify the other remote session department that attempted to access sensitive payout files 

<details>
<summary>Click to see answer</summary>
  
  Answer: `YE-HRPLANNER`
</details>

---

### 🚩 12. Performance Review Access Validation

Objective: 
Confirm access to employee performance review material through user-level tooling.

What to Hunt: 
Process telemetry showing access to the performance review directory and correlate repeated access behavior across departments/sessions.

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName == "5y51-d3p7"
| where TimeGenerated >= datetime(2025-12-01)
| where ProcessCommandLine contains "performancereview"
| where InitiatingProcessFileName has_any ("")
|project TimeGenerated, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, InitiatingProcessFileName, ProcessRemoteSessionIP, InitiatingProcessRemoteSessionIP
```
<img width="1207" height="104" alt="image" src="https://github.com/user-attachments/assets/3b8efdde-c6be-4f35-a265-32b4627906ca" />

Question: Identify the timestamp of a process that points to an access of a similar employee related file

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-12-03T07:25:15.6288106Z`
</details>

---

### 🚩 13. Approved/Final Bonus Artifact Access

Objective: 
Confirm access to a finalized year-end bonus artifact with sensitive-read classification.

What to Hunt: 
Events indicating sensitive reads tied to the remote session context responsible for the approved file access.

```kql
DeviceEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessAccountName == "5y51-d3p7"
| where TimeGenerated >=(datetime(2025-12-03))
| where FileName contains "bonus"
| where ActionType == "SensitiveFileRead"
```
<img width="758" height="34" alt="image" src="https://github.com/user-attachments/assets/973cf657-156a-46aa-b7d7-1316eabb084d" />

Question: Identify the timestamp pointing to unauthorized access of a sensitive file

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-12-03T07:25:39.1653621Z`
</details>

---

### 🚩 14. Candidate Archive Creation Location

Objective: 
Identify where a suspicious candidate-related archive was created.

What to Hunt: 
Locate the archive file creation event and extract its folder path.

<img width="572" height="17" alt="image" src="https://github.com/user-attachments/assets/378ff1ca-ebe2-48d6-894c-34aa9d644004" />

Question: Which directory was the .zip file dropped into? Insert the complete file path

<details>
<summary>Click to see answer</summary>
  
  Answer: `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip`
</details>
---

### 🚩 15. Outbound Transfer Attempt Timestamp

Objective: 
Confirm an outbound transfer attempt occurred after staging activity.

What to Hunt: 
Network events to a benign endpoint used for POST testing and extract the relevant timestamp.

```kql
    //Looking for "explanatory" file creation. 
DeviceFileEvents
    //Time should be immediately after creating the scheduler event
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
```
<img width="413" height="15" alt="image" src="https://github.com/user-attachments/assets/858b67b3-2738-4a8a-a973-4526a32d1c39" />

Question: Confirm whether an outbound connection was attempted and identify the timestamp

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-12-03T07:26:28.5959592Z`
</details>

---

### 🚩 16. Local Log Clearing Attempt Evidence

Objective: 
Identify command-line evidence of attempted local log clearing.

What to Hunt: 
Process creation for system utilities associated with clearing logs and capture the exact command line used.

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >=(datetime(2025-12-03))
| where FileName in ("wevtutil.exe","powershell.exe","cmd.exe")
| where ProcessCommandLine contains "cl"
   or ProcessCommandLine contains "clear"
| project TimeGenerated,
          FileName,
          ProcessCommandLine,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessRemoteSessionDeviceName,
          InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```
<img width="354" height="103" alt="image" src="https://github.com/user-attachments/assets/a8398f71-0257-44a2-9605-78c319488782" />

Question: Confirm whether an outbound connection was attempted and identify the timestamp

<details>
<summary>Click to see answer</summary>
  
  Answer: `"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational`
</details>

---

### 🚩 17. Second Endpoint Scope Confirmation

Objective: 
Identify the second endpoint involved in the chain based on similar telemetry patterns.

What to Hunt: 
Process telemetry on the second device and confirm its device name for scoping.

```kql
DeviceNetworkEvents
| where TimeGenerated >=(datetime(2025-12-03))
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessRemoteSessionIP == "192.168.0.110"
| summarize Connections=count(),
          RemoteSessionNames=make_set(InitiatingProcessRemoteSessionDeviceName, 10)
  by DeviceName
| where DeviceName != "sys1-dept"
| order by Connections desc
```
<img width="253" height="65" alt="image" src="https://github.com/user-attachments/assets/f349e72e-cdee-4d3c-8a67-4e67f4f1056b" />

Question: Identify the other compromised machine in question

<details>
<summary>Click to see answer</summary>
  
  Answer: `main1-srvr`
</details>

---

### 🚩 18. Approved Bonus Artifact Access on Second Endpoint

Objective: 
Confirm the approved bonus artifact is accessed again on the second endpoint.

What to Hunt: 
Process evidence of file access to the approved artifact on the second device and capture the access timestamp.

```kql
DeviceEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated >=(datetime(2025-12-03))
| where FileName contains "BonusMatrix_Q4_Approved.xlsx"
| take 5
| project TimeGenerated, InitiatingProcessCreationTime, ActionType, AdditionalFields, DeviceName, FileName, FolderPath
```
<img width="681" height="56" alt="image" src="https://github.com/user-attachments/assets/4e6ba309-db3a-4e13-8485-e4a85f5020b5" />

Question: Identify the creation time of the initiating process tied to this particular activity

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-12-04T03:11:58.6027696Z`
</details>

---

### 🚩 19. Employee Scorecard Access on Second Endpoint

Objective: 
Confirm employee-related scorecard access occurs again on the second endpoint and identify the remote session device context.

What to Hunt: 
Process activity showing access to the scorecard file and extract remote session device metadata.

```kql
DeviceEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated >=(datetime(2025-12-01))
| summarize Hits=count() by InitiatingProcessRemoteSessionDeviceName
| order by Hits desc
```
<img width="269" height="92" alt="image" src="https://github.com/user-attachments/assets/0528767f-ced7-45e1-9624-072be2c1350e" />

Question: Provide the requested device name responsible for this activity

<details>
<summary>Click to see answer</summary>
  
  Answer: `YE-FINANCEREVIE`
</details>

---

### 🚩 20. Staging Directory Identification on Second Endpoint

Objective: 
Identify the directory used for consolidation of internal reference materials and archived content.

What to Hunt: 
File events under the internal reference directory tree and determine the full directory structure involved.

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated >=(datetime(2025-12-03))
| where FileName != "VMAgentLogs.zip"
| where FolderPath contains "Internal"
| where FileName endswith ".zip"
   or FileName endswith ".7z"
   or FileName endswith ".rar"
   or FileName endswith ".tar"
   or FileName endswith ".gz"
| project TimeGenerated, ActionType, FileName, FolderPath,
          InitiatingProcessFileName,
          InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated asc
```
<img width="515" height="133" alt="image" src="https://github.com/user-attachments/assets/ae3f1cbe-19f0-44ec-85fa-576e959d7b09" />

Question: Provide the whole path containing the archived file

<details>
<summary>Click to see answer</summary>
  
  Answer: `C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip`
</details>

---

### 🚩 21. Staging Activity Timing on Second Endpoint

Objective: 
Determine when staging activity occurred during the final phase on the second endpoint.

What to Hunt: 
Timestamp of file events within the staging/internal reference directory scope.

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated >=(datetime(2025-12-03))
| where FileName != "VMAgentLogs.zip"
| where FolderPath contains "Internal"
| where FileName endswith ".zip"
   or FileName endswith ".7z"
   or FileName endswith ".rar"
   or FileName endswith ".tar"
   or FileName endswith ".gz"
| project TimeGenerated, ActionType, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="425" height="82" alt="image" src="https://github.com/user-attachments/assets/9676c1f1-ccc8-48e1-a9c7-e64e752032a0" />

Question: Now provide the timestamp when the staging activity occurred

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-12-04T03:15:29.2597235Z`
</details>

---

### 🚩 22. Outbound Connection Remote IP (Final Phase)

Objective: 
Identify the remote IP associated with the final outbound connection attempt.

What to Hunt: 
Network telemetry for the relevant outbound destination and extract the remote IP field.

```kql
DeviceNetworkEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated >= datetime(2025-12-03)
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| where InitiatingProcessFileName == "powershell.exe"
| where isnotempty(RemoteIP)
| where RemoteIP !startswith "10."
| where RemoteIP !startswith "192.168."
| where RemoteIP !startswith "172."
// remove common benign tooling / platform noise
| where InitiatingProcessCommandLine !contains "raw.githubusercontent.com"
| where InitiatingProcessCommandLine !contains "github.com"
| where InitiatingProcessCommandLine !contains "Windows Defender Advanced Threat Protection"
| where InitiatingProcessCommandLine !contains @"\Microsoft\Windows Defender Advanced Threat Protection\"
| where InitiatingProcessCommandLine !contains "exfiltratedata.ps1"
| project TimeGenerated, RemoteIP, RemotePort, ActionType, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="491" height="35" alt="image" src="https://github.com/user-attachments/assets/7e1e87c7-ff1d-4a4b-adaf-6b1c57071dc4" />

Question: Provide the IP of the outbound connection attempt

<details>
<summary>Click to see answer</summary>
  
  Answer: `54.83.21.156`
</details>

---
## Summary Table

| Flag | Description                        | Value |
|------|------------------------------------|-------|
| 1    | Initial Endpoint Association         | sys1-dept |
| 2    | Remote Session Source Attribution            | 192.168.0.110 |
| 3    | Support Script Execution Confirmation            | "powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1 |
| 4    | System Reconnaissance Initiation                 | "whoami.exe" /all |
| 5    | Sensitive Bonus-Related File Exposure                | BonusMatrix_Draft_v3.xlsx |
| 6    | Data Staging Activity Confirmation                     | 2533274790396713 |
| 7    | Outbound Connectivity Test             | 2025-12-03T06:27:31.1857946Z |
| 8    | Registry-Based Persistence                    | HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| 9    | Scheduled Task Persistence      | BonusReviewAssist |
| 10   | Secondary Access to Employee Scorecard Artifact          | YE-HELPDESKTECH |
| 11   | Bonus Matrix Activity by a New Remote Session Context            | YE-HRPLANNER |
| 12   |  Performance Review Access Validation          | 2025-12-03T07:25:15.6288106Z |
| 13   |  Approved/Final Bonus Artifact Access               | 2025-12-03T07:25:39.1653621Z |
| 14   | Candidate Archive Creation Location                     | C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip |
| 15   | Outbound Transfer Attempt Timestamp               | 2025-12-03T07:26:28.5959592Z |
| 16   |Local Log Clearing Attempt Evidence               | "wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational |
| 17   | Second Endpoint Scope Confirmation               | main1-srvr |
| 18   | Approved Bonus Artifact Access on Second Endpoint               | 2025-12-04T03:11:58.6027696Z |
| 19   | Employee Scorecard Access on Second Endpoint               | YE-FINANCEREVIE |
| 20   | Staging Directory Identification on Second Endpoint               | C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip |
| 21   |  Staging Activity Timing on Second Endpoint               |2025-12-04T03:15:29.2597235Z |
| 22   |Outbound Connection Remote IP (Final Phase)               | 54.83.21.156 |

---

**Report Completed By:** Alex Trinh
**Status:** ✅ All 22 flags investigated and confirmed
