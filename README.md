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

### 🚩 11. Bundling / Staging Artifacts

We have now established that the actor has contacted an outbound destination. Now we need to look for any sort of consolidation of artifacts/data to a single location, as that indicates transfer and exfiltration. By using `DeviceFileEvents`, we can find zip files and others similar to it while we also keep the field of `InitiatingProcessParentFileName`.

```kql
   //Looking for File system events. Looking for consolidation of artifacts
DeviceFileEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-16))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Executable file responsible for launching the current process
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
    //hint offered
| where FileName has_any ("zip")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1834" height="461" alt="image" src="https://github.com/user-attachments/assets/57d42d93-cca5-4752-a7df-e8f51f1af917" />

Question: Provide the full folder path value where the artifact was first dropped into.

<details>
<summary>Click to see answer</summary>
  
  Answer: `C:\Users\Public\ReconArtifacts.zip`
</details>

---

### 🚩 12. Outbound Transfer Attempt (Simulated)

Since the artifacts have been consolidated, we can assume the actor will attempt to move the data off host. We need to check for any network events that would suggest that. We will look for any unusual outbound connections.

```kql
   //Looking for network event indicating outbound transfers
DeviceNetworkEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-16))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Executable file responsible for launching the current process
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessParentFileName
| order by TimeGenerated desc
```
<img width="1842" height="510" alt="image" src="https://github.com/user-attachments/assets/e5849d93-159a-43ff-a22e-760c2ee1ee49" />

Question: Provide the IP of the last unusual outbound connection.

<details>
<summary>Click to see answer</summary>
  
  Answer: `100.29.147.161`
</details>

---

### 🚩 13. Scheduled Re-Execution Persistence

We need to also detect any creation of persistence. Did the actor create anything that may run again on a schedule or a signin. Any sort of re-execution mechanism is an actors way of surviving past a single session.

```kql
   //looking for creation of scheduler-related events
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Executable file responsible for launching the current process
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="1834" height="511" alt="image" src="https://github.com/user-attachments/assets/0f03dd2d-dd50-45dd-8877-228aa83f297a" />

Question: Provide the value of the task name down below.

<details>
<summary>Click to see answer</summary>
  
  Answer: `SupportToolUpdater`
</details>

---

### 🚩 14. Autorun Fallback Persistence

We also need to investigate any autorun entries placed as backup persistence. Anything that may resemble an autorun stemming from the `InitiatingProcessParentFileName` is an example of redundant persistence. That increases their resilience. We need to check the registry for any modifications.

<img width="1788" height="478" alt="image" src="https://github.com/user-attachments/assets/29af1c49-1268-4db2-b0b7-cc729f126ea0" />


Question: What was the name of the registry value?

<details>
<summary>Click to see answer</summary>
  
  Answer: `RemoteAssistUpdater`
</details>
---

### 🚩 15. Planted Narrative / Cover Artifact

This all started out as a routine support ticket. The actor wouldnt just leave without justifying the activity. We need to look for any creation of explanatory files around the time of the suspicious operations, as this file would be used as a classic misdirection.

```kql
    //Looking for "explanatory" file creation. 
DeviceFileEvents
    //Time should be immediately after creating the scheduler event
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
```
<img width="1831" height="607" alt="image" src="https://github.com/user-attachments/assets/718cf402-0b2f-43ca-a85a-ce5c69dc9dfb" />

Question: Identify the file name of the artifact left behind.

<details>
<summary>Click to see answer</summary>
  
  Answer: `SupportChat_log.lnk`
</details>

---
## Summary Table

| Flag | Description                        | Value |
|------|------------------------------------|-------|
|Start | Suspicious Machine                 | gab-intern-vm |
| 1    | 1st CLI parameter used in execution            | -ExecutionPolicy |
| 2    | File related to Exploit            | DefenderTamperArtifact.lnk |
| 3    | Exploit Command Value              | "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" |
| 4    | Last Recon Attempt                 | 2025-10-09T12:51:44.3425653Z |
| 5    | 2nd Command tied to Mapping                | "cmd.exe" /c wmic logicaldisk get name,freespace,size |
| 6    | Initiating Parent Process File Name                     | RuntimeBroker.exe |
| 7    | Initiating Process Unique ID              | 2533274790397065 |
| 8    | Process Inventory                     | tasklist.exe |
| 9    | 1st attempt timestamp      | 2025-10-09T12:52:14.3135459Z |
| 10   | 1st Outbound Destination          | www.msftconnecttest.com |
| 11   | Artifact 1st full folder path            | C:\Users\Public\ReconArtifacts.zip |
| 12   | Unusual outbound IP          | 100.29.147.161 |
| 13   | Task Name Value               | SupportToolUpdater |
| 14   | Registry Value Name                      | RemoteAssistUpdater |
| 15   | Artifact left behind               | SupportChat_log.lnk |

---

**Report Completed By:** William Olega
**Status:** ✅ All 15 flags investigated and confirmed
