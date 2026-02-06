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

To establish a reliable starting point, we first need to identify where anomalous behavior begins. Based on the scenario context, suspicious activity is expected to occur during early December, coinciding with year-end compensation and performance review workflows.

To anchor the investigation, we begin by examining process execution telemetry on employee-facing systems. By reviewing DeviceProcessEvents, we can identify abnormal script execution activity that may indicate unauthorized access or tooling usage.

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

### 🚩 2. Defense Disabling

With a suspicious program running on a compromised machine, we'll also need to check if our security posture has changed. Was anything tampered with? Even if failed or simply just an intent, any sort of indicator of activity there still can be a threat. Let's investigate. Again we use `matches regex @"(?i)"` along with the string `tamper` to find any regular, non-case-sensitive expression with the word tamper in it.

```kql
//search for artifact creation
DeviceFileEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //search for tamper
| where FileName matches regex @"(?i)(tamper)"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="1828" height="423" alt="image" src="https://github.com/user-attachments/assets/71e3a830-df5c-4511-a56c-a07ecd9470da" />

Question: What was the name of the file related to this exploit?

<details>
<summary>Click to see answer</summary>
  
  Answer: `DefenderTamperArtifact.lnk`
</details>

---

### 🚩 3. Quick Data Probe

Okay, at this point, the actor would still be probing for information, most likely something quick to acquire that would also hold sensitive information. Perhaps where copying and pasting is made possible, the clip board. Let's discover if the actor ran any command to access the clipboard. We will search, including the values of `powershell` and `clip` for any sort of event.

```kql
//looking for checks, actions that read data
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //action
| where FileName contains "powershell"
    //hint offered
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1826" height="480" alt="image" src="https://github.com/user-attachments/assets/9a4278b8-c675-441a-9df8-00617f3583d7" />

Question: Provide the command value tied to this particular exploit.

<details>
<summary>Click to see answer</summary>
  
  Answer: `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
</details>

---

### 🚩 4. Host Context Recon

After low-effort wins, we can expect the actor to continue to prob and collect information of the environment or account details. At this point, we don't expect them to modify anything yet, so we're just looking for any context-gathering decisions. This is where we expect them to use `qwinsta` command to discover any active user sessions on a system.

```kql
   //looking for activity/actions
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //hint offered
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1835" height="518" alt="image" src="https://github.com/user-attachments/assets/ad98c9f7-ff8c-49a2-b464-2dde764f3afb" />

Question: Point out when the last recon attempt was.

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-10-09T12:51:44.3425653Z`
</details>

---

### 🚩 5. Storage Surface Mapping

After using `qwinsta`, let's check if the actor discovered any storage locations. After recon, we can expect lightweight checks of available storage and even enumeration of filesystems or share surfaces.

```kql
   //looking for discovery of storage, looking for chekcs of available storage
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //look for filesystem/share surface enumeration, lightweight storage checks
| where tolower(ProcessCommandLine) has_any ("net share", "net view", "dir /s", "Get-Volume", "Get-SmbShare", "wmic", "fsutil fsinfo drives", "Get-CimInstance -ClassName Win32_LogicalDisk")
| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1835" height="481" alt="image" src="https://github.com/user-attachments/assets/0a3f932a-f744-48f2-9205-40851e317dad" />

Question: Provide the 2nd command tied to this activity.

<details>
<summary>Click to see answer</summary>
  
  Answer: `"cmd.exe" /c wmic logicaldisk get name,freespace,size`
</details>

---

### 🚩 6. Connectivity & Name Resolution Check

Since we confirmed that the actor discovered storage locations, we need to identify checks that validate network reachability. Are there network events or process events that indicate outward connectivity probes? We need to confirm egress before attempting to move data off host. We will use `DeviceProcessEvents` to look for any actions that resemble network probing.

```kql
   //looking for checks on the network and name resolution
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping", "nslookup", "curl", "Test-NetConnection", "tracert")
    //action taken for checks
| where FileName contains "powershell" or FileName contains "cmd"
    //validate Network reachability
| where ProcessCommandLine has_any ("ping", "tracert", "nslookup")
    //hint offered
| where IsProcessRemoteSession == "true"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessParentFileName, IsProcessRemoteSession
| order by TimeGenerated asc
```
<img width="1829" height="562" alt="image" src="https://github.com/user-attachments/assets/f7541770-2420-4a03-9280-536f5a41667a" />

Question: Provide the File Name of the initiating parent process.

<details>
<summary>Click to see answer</summary>
  
  Answer: `RuntimeBroker.exe`
</details>

---

### 🚩 7. Interactive Session Discovery

Did the actor detect user sessions on the host? Let's look for reveal attempts and signals that enumerate current session state without taking over the host. The reason the actor may do this is because knowing which sessions are active helps them decide whether to act immediately or wait. Let's search for `qwi` to see if any query sessions have been processed.

```kql
    //looking for actions to detect sessions
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //qwinsta command displays info on active user session
| where ProcessCommandLine contains ("qwi")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessUniqueId
```
<img width="1834" height="532" alt="image" src="https://github.com/user-attachments/assets/d67deef9-645f-461f-b894-4eea2ced8d25" />

Question: What is the unique ID of the initiating process?

<details>
<summary>Click to see answer</summary>
  
  Answer: `2533274790397065`
</details>

---

### 🚩 8. Runtime Application Inventory

Once the actor knows the current session state, they can look for running applications and services to inform them of any risks or opportunities. We need to look for any events that queries running services.

Question: Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host.

<details>
<summary>Click to see answer</summary>
  
  Answer: `tasklist.exe`
</details>

---

### 🚩 9. Privilege Surface Check

Now the actor can discover what permissions and priviledges are available to them. We need to look for any telemetry that indicates queries of priviledge. We can search `DeviceProcessEvents` for anything like a `whoami`.

```kql
   //looking for attempts to understand priviledges available
DeviceProcessEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "whoami"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
| take 1
```
<img width="1835" height="510" alt="image" src="https://github.com/user-attachments/assets/22c8ce83-1fef-474e-b1b7-30bc6852f86f" />

Question: Identify the timestamp of the very first attempt.

<details>
<summary>Click to see answer</summary>
  
  Answer: `2025-10-09T12:52:14.3135459Z`
</details>

---

### 🚩 10. Proof-of-Access & Egress Validation

We also need to find evidence of outbound network checks, activity, and artifacts create as proof the actor can view or collect host data. We can look for any Network Events that stemmed from the `InitiatingProcessParentFileName`. That way we can trace if and when the actor contacts an outbound destination.

```kql
   //looking for actions that validate outbound reachability and attempt to capture host state
DeviceNetworkEvents
    //search the first half of October 2025
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
    //suspicious machine
| where DeviceName == "gab-intern-vm"
    //Initiating Parent File Name related to network events/outward connectivity probes
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessFileName, RemoteUrl
| order by TimeGenerated asc
```
<img width="1834" height="515" alt="image" src="https://github.com/user-attachments/assets/4b2a4f3b-d678-4ba1-b97d-97e02e1bd950" />

Question: Which outbound destination was contacted first?

<details>
<summary>Click to see answer</summary>
  
  Answer: `www.msftconnecttest.com`
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
