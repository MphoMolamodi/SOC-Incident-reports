SOC Analyst Labs- Mpho Molamodi


Incident: 1001- Suspicious Parent-Child Relationship

\\Evidence:
Host:win-3459
Process:C:\windows\servicing\TrustedInstaller.exe
Parent: services.exe (PID 3506)
Event: Sysmon 1 
Verdict: False Positive
Reason for verdict: TrustedInstaller.exe spawned by services.exe, legit windows update process.
Path: C:\windows\servicing\TrustedInstaller.exe is Microsoft signed. 

\\Analysis:
-Binary is Microsoft signed windows Module Installer.
-Path legitimate, not masquerading.
-Parent-Child services.exe is expected for windows update.

\\Action taken:
Alert closed, no escalation required.
