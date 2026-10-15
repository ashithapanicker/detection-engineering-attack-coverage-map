# ATT&CK Coverage Map

| Technique ID & Name | Tactic | Data Source | Event ID |
|---|---|---|---|
| T1003.001 – LSASS Memory Dump | Credential Access | Sysmon | Event ID 10 (ProcessAccess, TargetImage=lsass.exe, SourceImage=rundll32.exe) |
| T1059.001 – PowerShell | Execution | Sysmon | Event ID 1 (process=powershell.exe, encoded command flags) |
| T1021.002 – SMB/Admin Shares | Lateral Movement | Windows Security | EventCode 5140 (network share accessed; C$, ADMIN$, IPC$) |
| T1547.001 – Registry Run Keys | Persistence | Sysmon | Event ID 13 (RegistryValueSet, ...\Run\...) |
| T1055 – Process Injection | Defense Evasion | Sysmon | Event ID 1 (process launch of the simulation's injection tool — see detections.md for this detection's scope limitation) |
| T1110 – Brute Force | Credential Access | Windows Security | EventCode 4625 (failed logon, 5+ within 5 minutes) |
| T1105 – Ingress Tool Transfer | Command and Control | Sysmon | Event ID 1 (process=powershell.exe, command contains 'iwr') |
| T1112 – Registry Modification | Defense Evasion | Sysmon | Event ID 13 (RegistryValueSet, ...\Policies\System\...) |
| T1135 – Network Share Discovery | Discovery | Sysmon | Event ID 1 (process=net.exe, command contains 'view' or 'share') |
| T1569.002 – Service Execution (PsExec) | Execution | Windows System log | EventCode 7045 (new service installed; Service_File_Name = cmd/powershell/rundll32) |
| T1070.001 – Clear Windows Event Logs | Defense Evasion | Windows Security + Sysmon | EventCode 1102, and Sysmon Event ID 1 (process=wevtutil.exe) |

Note: in ATT&CK v19, T1070.001 (Clear Windows Event Logs) appears as T1685.005 under Defense Impairment. This project uses T1070.001 in the docs and T1685.005 in the heatmap, and both are the same detection.

Heatmap uses MITRE ATT&CK v19.
