# Detection Write-Ups — MITRE ATT&CK Coverage Map

Eleven Splunk detections, each built from a real simulated attack (Atomic Red Team or a manual equivalent) on a Windows 11 VM running Sysmon.

**How they were validated**
1. Each detection was proven against its matching simulated attack.
2. Each was then run over the VM's **entire log history (All time)**, not just a short baseline, to look for false positives. This found real false positives in three detections (T1547.001, T1070.001, T1110), which were tuned. See each entry and the tuning table at the end.

**Tactic names:** the ATT&CK Navigator version used for the heatmap splits the older "Defense Evasion" tactic into "Stealth" and "Defense Impairment". Where that applies, the older name is shown with a note.

**Alerting:** Splunk Free does not support scheduled alerts. See `alert-configuration.md` for the intended alert settings; the detections here were validated by running the saved searches manually after each simulated attack.

---

## T1059.001 — PowerShell (Encoded Command)

**Tactic:** Execution
**Data source:** Sysmon EventCode 1 (Process Create)

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*powershell.exe" Image!="*splunk-powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="* -e *")
| table _time, host, Image, CommandLine, ParentImage
```

**What it catches:** PowerShell started with an encoded command. Attackers use base64 encoding to hide what a script does. The Splunk forwarder's own helper (`splunk-powershell.exe`) is excluded.

**Validation:** Atomic Red Team T1059.001 test #17 (PowerShell Command Execution). Test #1 (Mimikatz) was quarantined by Windows Defender, so a plain encoded-command test was used instead.

**False positives:** All-time check returns 1 hit, the test itself.

**Screenshot:** `t1059-001-powershell-atomictest.png`

---

## T1021.002 — SMB / Windows Admin Shares

**Tactic:** Lateral Movement
**Data source:** Windows Security EventCode 5140 (Network Share Accessed)

```spl
index=* sourcetype="WinEventLog:Security" EventCode=5140 (Share_Name="*C$*" OR Share_Name="*ADMIN$*" OR Share_Name="*IPC$*")
| table _time, host, Account_Name, Share_Name, Source_Address
```

**What it catches:** Access to the administrative shares (`C$`, `ADMIN$`, `IPC$`) that attackers use to move between machines.

**Validation:** Atomic Red Team T1021.002 test #1 (map admin share). The real data source is Windows Security 5140, not Sysmon EventCode 3 as often assumed. It required enabling File Share auditing with `auditpol` and setting `LocalAccountTokenFilterPolicy=1`, since neither is on by default on a non-domain machine.

**False positives:** All-time check returns 4 hits, all from test activity. Running `net view \\localhost` (T1135 test) also touches `IPC$`, so those two detections can fire together.

**Screenshot:** `t1021-002-smb-admin-share.png`

---

## T1003.001 — LSASS Credential Dumping

**Tactic:** Credential Access
**Data source:** Sysmon EventCode 10 (Process Access)

```spl
index=* sourcetype=*Sysmon* EventCode=10 TargetImage="*lsass.exe" SourceImage="*rundll32.exe" CallTrace="*comsvcs.dll*"
| table _time, host, SourceImage, TargetImage, CallTrace, User
```

**What it catches:** `rundll32.exe` using `comsvcs.dll` to dump LSASS memory, a well-known credential-theft method that uses only built-in Windows files.

**Validation:** Atomic Red Team T1003.001 test #2. The Mimikatz-based test #1 was avoided because Defender quarantines it. The default SwiftOnSecurity Sysmon config logs nothing for ProcessAccess, so a rule for `lsass.exe` was added to the active config. Real-time Protection and Tamper Protection were turned off temporarily for the test.

**False positives:** All-time check returns 1 hit, the test itself.

**Screenshot:** `t1003-001-lsass-comsvcs.png`

---

## T1070.001 — Clear Windows Event Logs

**Tactic:** Defense Evasion (Defense Impairment in the latest ATT&CK version)
**Data source:** Windows Security EventCode 1102 and Sysmon EventCode 1

```spl
index=* ((sourcetype="WinEventLog:Security" EventCode=1102) OR (sourcetype=*Sysmon* EventCode=1 Image="*wevtutil.exe" (CommandLine="* cl *" OR CommandLine="*clear-log*")))
| table _time, host, EventCode, Image, CommandLine
```

**What it catches:** The log-cleared event Windows records (1102), and the `wevtutil cl` command that caused it.

**Validation:** Ran `wevtutil cl Security` and confirmed both events.

**False positive found and tuned:** The first version matched `CommandLine="*cl*"`, which also matches the letters "cl" inside `MpClient.dll`. This produced **27 false positives** from Windows Defender's own `wevtutil install-manifest` runs after platform updates. Tuned to match `cl` and `clear-log` as whole words. The all-time check now returns 2 hits, both from the real test.

**Screenshot:** `t1070-001-clear-logs.png`

---

## T1547.001 — Registry Run Key Persistence

**Tactic:** Persistence
**Data source:** Sysmon EventCode 13 (Registry Value Set)

```spl
index=* sourcetype=*Sysmon* EventCode=13
| regex TargetObject="CurrentVersion[[:punct:]]Run[[:punct:]]"
| search NOT (Image="*msedge.exe" TargetObject="*MicrosoftEdgeAutoLaunch_*")
| table _time, host, Image, TargetObject, Details
```

**What it catches:** Values written under the `...\CurrentVersion\Run` registry key, the most common way malware survives a reboot.

**Validation:** Added `TestPersistence` and `TestPersistence2` with `reg add` and confirmed both events.

**False positive found and tuned:** Microsoft Edge rewrites its own `MicrosoftEdgeAutoLaunch_...` Run-key value each time it starts or a user signs in. This produced about **30 false positives** across the VM's history, and it was missed in the first short baseline because Edge had not restarted in that window. Tuned by excluding writes that come from `msedge.exe` **and** target Edge's autolaunch value. Requiring both conditions means an attacker cannot hide just by renaming a program. The all-time check now returns 2 hits, both the `reg.exe` test writes.

**Screenshot:** `t1547-001-registry-runkey-live.png`

---

## T1112 — Registry Modification (Policies)

**Tactic:** Defense Evasion (Stealth / Defense Impairment in the latest ATT&CK version)
**Data source:** Sysmon EventCode 13 (Registry Value Set)

```spl
index=* sourcetype=*Sysmon* EventCode=13
| regex TargetObject="Policies[[:punct:]]System[[:punct:]]"
| table _time, host, Image, TargetObject, Details
```

**What it catches:** Changes under `...\Policies\System`, a common place for attackers to switch off security features, such as blocking Registry Editor.

**Validation:** Set `DisableRegistryTools` and confirmed the event. Note: this setting blocked both `regedit.exe` and `reg.exe`, so it had to be removed with PowerShell's `Remove-ItemProperty`.

**False positives:** All-time check returns 4 hits, all from setting and removing that test value.

**Screenshot:** `t1112-registry-modification.png`

---

## T1135 — Network Share Discovery

**Tactic:** Discovery
**Data source:** Sysmon EventCode 1 (Process Create)

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*net.exe" (CommandLine="*view*" OR CommandLine="*share*")
| table _time, host, Image, CommandLine, ParentImage
```

**What it catches:** `net view` and `net share`, built-in commands attackers use to list available shares before moving sideways.

**Validation:** Ran both commands and confirmed matching Sysmon events.

**False positives:** All-time check returns 7 hits, all from test activity.

**Screenshot:** `t1135-network-share-discovery-live.png`

---

## T1569.002 — Service Execution (PsExec-style)

**Tactic:** Execution
**Data source:** Windows **System** log EventCode 7045 (Service Installed)

```spl
index=* sourcetype="WinEventLog:System" EventCode=7045 (Service_File_Name="*cmd.exe*" OR Service_File_Name="*powershell.exe*" OR Service_File_Name="*rundll32.exe*")
| table _time, host, Service_Name, Service_File_Name, Account_Name
```

**What it catches:** A new Windows service whose program is `cmd.exe`, `powershell.exe` or `rundll32.exe`, the signature of PsExec-style remote execution.

**Validation:** Created a test service pointed at `cmd.exe` with `sc create`.

**False positive tested and tuned:** The first version matched any new service. A test service named `UpdaterHelperService` pointing at `notepad.exe` (simulating a normal software installer) falsely matched it. Restricting the program to the three binaries above cleared it, while the real cmd.exe test still matched. The all-time check returns 2 hits, both real test services.

**Screenshot:** `t1569-002-service-execution-live.png`

---

## T1110 — Brute Force

**Tactic:** Credential Access
**Data source:** Windows Security EventCode 4625 (Failed Logon)

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| eval target=mvindex(Account_Name,-1)
| where NOT like(target,"%$") AND target!="-"
| bin _time span=5m
| stats count as failures, latest(host) as host by _time, target
| where failures>=5
| table _time, host, target, failures
```

**What it catches:** 5 or more failed logons for the same account within 5 minutes, which is the pattern of password guessing.

**Validation:** Entered wrong passwords repeatedly at the sign-in screen. Caught on 2026-09-22 and 2026-10-12 (5 failures each).

**False positives found and tuned:** The first version counted failures per account over all time, so almost any account was flagged. It also double-counted, because event 4625 lists both the computer account and the account being logged into. Tuned to use only the real account, ignore computer accounts, and require 5 failures inside 5 minutes. A first test of only 2 failures about 6 minutes apart correctly did **not** trigger it. The all-time check returns 4 hits: the 2 real tests plus 2 failed-logon bursts that predate the project (2026-06-14 and 2026-07-29).

**Screenshot:** `t1110-bruteforce.png`

---

## T1105 — Ingress Tool Transfer

**Tactic:** Command and Control
**Data source:** Sysmon EventCode 1 (Process Create)

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*powershell.exe" Image!="*splunk-powershell.exe" CommandLine="*iwr*"
| table _time, host, Image, CommandLine, ParentImage
```

**What it catches:** PowerShell's `iwr` (Invoke-WebRequest) shortcut downloading a file, a common way attackers bring extra tools onto a machine. The Splunk forwarder's own helper process is excluded.

**Validation:** Atomic Red Team T1105 test #29 (`iwr` / Invoke-WebRequest download).

**False positives:** All-time check returns 2 hits, both from test runs.

**Screenshot:** `t1105-ingress-tool-transfer.png`

---

## T1055 — Process Injection

**Tactic:** Defense Evasion / Privilege Escalation (Stealth in the latest ATT&CK version)
**Data source:** Sysmon EventCode 1 (Process Create)

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*uuid_injection.exe"
| table _time, host, Image, CommandLine, ParentImage
```

**What it catches:** Execution of the injection tool used in the simulated attack.

**Validation:** Atomic Red Team T1055 test #13 (UUID custom process injection). The Mimikatz test (#2) and the CreateRemoteThread test (#9) were blocked by Windows Defender, so a different injection implementation was used.

**Limitation (honest note):** this detection matches the simulation's own file name, so it proves the pipeline catches that test, but it is not a general injection detector. A broader version would need Sysmon EventCode 8 (CreateRemoteThread) rules.

**False positives:** All-time check returns 1 hit, the test itself.

**Screenshot:** `t1055-process-injection.png`

---

## Tuning Summary

| Technique | False positives before | Tuning applied | After |
|---|---|---|---|
| T1059.001 | 0 | Excluded the Splunk forwarder's own PowerShell helper | 0 |
| T1021.002 | 0 | None | 0 |
| T1003.001 | 0 | None | 0 |
| T1070.001 | 27 (Defender log-manifest installs) | Match `cl` / `clear-log` as whole words | 0 |
| T1547.001 | about 30 (Edge autolaunch Run key) | Excluded Edge's own autolaunch write (program and value name) | 0 |
| T1112 | 0 | None | 0 |
| T1135 | 0 | None | 0 |
| T1569.002 | 1 (simulated software installer) | Only match cmd.exe / powershell.exe / rundll32.exe services | 0 |
| T1110 | 5 flagged accounts, double counting | Real account only, 5 failures within 5 minutes | 0 on benign activity |
| T1105 | 0 | Excluded the Splunk forwarder's own PowerShell helper | 0 |
| T1055 | 0 | None | 0 |

## Dashboard

The "Blue Team Detection Overview" dashboard shows detection hits over time, hits by ATT&CK technique, and the 10 most recent hits. Because Splunk Free has no triggered alerts, it is built from the saved detection searches. Screenshot: `splunk-detection-dashboard.png`
