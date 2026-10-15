# Alert Configuration

This file documents the alert settings I would use for each of the 11 detections.

## Important limitation

I ran this lab on the **Splunk Free license**. Splunk Free does not support alerts or scheduled searches, so these alerts were **not created in Splunk**. This file records the settings I would apply on a licensed Splunk Enterprise or Splunk Cloud instance.

What I did instead:
- Saved every detection as a report named `DE - <technique> - <name>`.
- Re-ran the detections manually after each simulated attack and saved screenshots of the fresh results.
- Built the "Blue Team Detection Overview" dashboard from the saved searches.

## How to create these alerts (on a licensed Splunk)

1. Open the saved report and choose **Save As > Alert**.
2. Set **Alert type** to *Scheduled* and choose the run frequency below.
3. Set the **Trigger condition** below.
4. Set the **Throttle** as listed, to avoid alert floods.
5. Add the trigger actions: add to Triggered Alerts, and send an email to the SOC mailbox for High and Critical alerts.

## Summary

| Technique | Detection | Severity | Schedule | Trigger | Throttle |
|---|---|---|---|---|---|
| T1059.001 | PowerShell Encoded Command | High | Every 5 minutes | Number of results > 0 | Alert on every hit |
| T1021.002 | SMB Admin Share Access | Medium | Every 5 minutes | Number of results > 0 | Once per account per hour |
| T1003.001 | LSASS Dump via comsvcs.dll | Critical | Every 1 minute | Number of results > 0 | Alert on every hit |
| T1070.001 | Clear Windows Event Logs | High | Every 5 minutes | Number of results > 0 | Alert on every hit |
| T1547.001 | Registry Run Key Persistence | Medium | Every 10 minutes | Number of results > 0 | Once per host per hour |
| T1112 | Registry Modification (Policies) | Medium | Every 10 minutes | Number of results > 0 | Once per host per hour |
| T1135 | Network Share Discovery | Low | Every 15 minutes | Number of results > 0 | Once per host per hour |
| T1569.002 | Service Execution (PsExec-style) | High | Every 5 minutes | Number of results > 0 | Alert on every hit |
| T1110 | Brute Force (Multiple Failed Logons) | High | Every 5 minutes | Number of results > 0 | Once per account per 15 minutes |
| T1105 | Ingress Tool Transfer | Medium | Every 10 minutes | Number of results > 0 | Once per host per hour |
| T1055 | Process Injection (UUID injection tool) | High | Every 5 minutes | Number of results > 0 | Alert on every hit |


Time range for every alert: the last 15 minutes (the last 30 minutes for T1110, since it counts failures in 5-minute windows).

## Detection details

### T1059.001: PowerShell Encoded Command

- **Severity:** High
- **Schedule:** Every 5 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Alert on every hit

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*powershell.exe" Image!="*splunk-powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="* -e *")
| table _time, host, Image, CommandLine, ParentImage
```

### T1021.002: SMB Admin Share Access

- **Severity:** Medium
- **Schedule:** Every 5 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Once per account per hour

```spl
index=* sourcetype="WinEventLog:Security" EventCode=5140 (Share_Name="*C$*" OR Share_Name="*ADMIN$*" OR Share_Name="*IPC$*")
| table _time, host, Account_Name, Share_Name, Source_Address
```

### T1003.001: LSASS Dump via comsvcs.dll

- **Severity:** Critical
- **Schedule:** Every 1 minute
- **Trigger condition:** Number of results > 0
- **Throttle:** Alert on every hit

```spl
index=* sourcetype=*Sysmon* EventCode=10 TargetImage="*lsass.exe" SourceImage="*rundll32.exe" CallTrace="*comsvcs.dll*"
| table _time, host, SourceImage, TargetImage, CallTrace, User
```

### T1070.001: Clear Windows Event Logs

- **Severity:** High
- **Schedule:** Every 5 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Alert on every hit

```spl
index=* ((sourcetype="WinEventLog:Security" EventCode=1102) OR (sourcetype=*Sysmon* EventCode=1 Image="*wevtutil.exe" (CommandLine="* cl *" OR CommandLine="*clear-log*")))
| table _time, host, EventCode, Image, CommandLine
```

### T1547.001: Registry Run Key Persistence

- **Severity:** Medium
- **Schedule:** Every 10 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Once per host per hour

```spl
index=* sourcetype=*Sysmon* EventCode=13
| regex TargetObject="CurrentVersion[[:punct:]]Run[[:punct:]]"
| search NOT (Image="*msedge.exe" TargetObject="*MicrosoftEdgeAutoLaunch_*")
| table _time, host, Image, TargetObject, Details
```

### T1112: Registry Modification (Policies)

- **Severity:** Medium
- **Schedule:** Every 10 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Once per host per hour

```spl
index=* sourcetype=*Sysmon* EventCode=13
| regex TargetObject="Policies[[:punct:]]System[[:punct:]]"
| table _time, host, Image, TargetObject, Details
```

### T1135: Network Share Discovery

- **Severity:** Low
- **Schedule:** Every 15 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Once per host per hour

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*net.exe" (CommandLine="*view*" OR CommandLine="*share*")
| table _time, host, Image, CommandLine, ParentImage
```

### T1569.002: Service Execution (PsExec-style)

- **Severity:** High
- **Schedule:** Every 5 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Alert on every hit

```spl
index=* sourcetype="WinEventLog:System" EventCode=7045 (Service_File_Name="*cmd.exe*" OR Service_File_Name="*powershell.exe*" OR Service_File_Name="*rundll32.exe*")
| table _time, host, Service_Name, Service_File_Name, Account_Name
```

### T1110: Brute Force (Multiple Failed Logons)

- **Severity:** High
- **Schedule:** Every 5 minutes
- **Trigger condition:** Number of results > 0 (the query already requires 5+ failures in 5 minutes)
- **Throttle:** Once per account per 15 minutes

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| eval target=mvindex(Account_Name,-1)
| where NOT like(target,"%$") AND target!="-"
| bin _time span=5m
| stats count as failures, latest(host) as host by _time, target
| where failures>=5
| table _time, host, target, failures
```

### T1105: Ingress Tool Transfer

- **Severity:** Medium
- **Schedule:** Every 10 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Once per host per hour

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*powershell.exe" Image!="*splunk-powershell.exe" CommandLine="*iwr*"
| table _time, host, Image, CommandLine, ParentImage
```

### T1055: Process Injection (UUID injection tool)

- **Severity:** High
- **Schedule:** Every 5 minutes
- **Trigger condition:** Number of results > 0
- **Throttle:** Alert on every hit

```spl
index=* sourcetype=*Sysmon* EventCode=1 Image="*uuid_injection.exe"
| table _time, host, Image, CommandLine, ParentImage
```

## Tuning notes that affect the alerts

- T1070.001: the old pattern matched about 27 harmless Windows Defender runs. The query now matches ` cl ` or `clear-log` as whole words, plus Security EventCode 1102.
- T1547.001: about 30 harmless Microsoft Edge autolaunch writes were excluded.
- T1110: failed logons are counted in 5-minute windows, computer accounts are ignored, and 5 or more failures are required.
- T1569.002: only services launched by `cmd.exe`, `powershell.exe` or `rundll32.exe` are matched, and the event is in the Windows **System** log, not Security.
- T1055: the detection matches the test tool's file name (`uuid_injection.exe`). This is a documented limitation, and a production rule would need behaviour-based detection.
