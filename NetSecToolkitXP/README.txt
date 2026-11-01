NetSecToolkitXP 0.5.0
=====================
Windows XP SP3 / PowerShell 2.0 build of NetSecToolkit, with a security
assistant. Everything is read-only except Set-XPHardening, which applies
the hardening baseline (use -WhatIf first to preview it), and
Set-XPAssistantConfig, which only saves the assistant's settings.

Easiest: double-click NetSecToolkitXP.exe (keep it next to this
NetSecToolkitXP folder). It opens a numbered menu: 1 = full check,
V = virus and threat check,
H = harden (preview first, applies only after you type YES),
A = assistant, Q = quit. No Set-ExecutionPolicy or Import-Module needed.
If an antivirus blocks the .exe, double-click NetSecToolkitXP.cmd instead.

Quick start from PowerShell instead (Administrator window):
  Import-Module NetSecToolkitXP
  Invoke-XPSecurityCheck         # check everything, save a report
  xpai                           # ask the assistant; type plan

Requirements
------------
- Windows XP SP3
- .NET Framework 2.0 SP1 or later
- Windows PowerShell 2.0 (KB968930)

Install
-------
1. Copy the NetSecToolkitXP folder to the XP machine, e.g.
   C:\Documents and Settings\<you>\My Documents\WindowsPowerShell\Modules\NetSecToolkitXP
   (create the WindowsPowerShell\Modules folders if they don't exist).
2. If you downloaded the zip in a browser on XP, right-click each file,
   choose Properties, and click Unblock (PS 2.0 has no Unblock-File).
3. Allow local scripts (once):
     Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   or just for one session:
     powershell -ExecutionPolicy Bypass
4. Import:
     Import-Module NetSecToolkitXP
   or by path, from anywhere:
     Import-Module C:\path\to\NetSecToolkitXP\NetSecToolkitXP.psd1

Commands
--------
Get-NetAdapterHealthXP   Adapters from WMI: IP, mask, gateway, DNS, DHCP
                         lease, NetBIOS over TCP/IP. Flags APIPA, missing
                         gateway/DNS, NetBIOS on. Pings gateway and 8.8.8.8,
                         tests DNS.

Get-FirewallAuditXP      Windows Firewall via the HNetCfg.FwMgr COM API:
                         SharedAccess service, Domain and Standard profiles,
                         File and Printer Sharing / UPnP / Remote Desktop /
                         Remote Admin exceptions, ICMP, program exceptions
                         (flags ones pointing to deleted files), open ports
                         (flags risky ones), logging (from netsh firewall
                         show logging).
                         -ExportPath file.csv   save the exception list

Find-NetworkDeviceXP     Ping sweep of the local subnet, then reads arp -a.
                         Shows IP, MAC, gateway/this PC, ping response,
                         randomized MACs.
                         -TimeoutMs 200         per-host ping timeout
                         -NoSweep               only read the ARP cache
                         -ResolveNames          look up hostnames (slower)
                         -ExportPath file.csv   save the device list

Set-XPHardening          Applies the XP hardening baseline in one run:
                         - Firewall on, exceptions disabled (all profiles)
                         - Firewall logging on (dropped packets and
                           connections, %windir%\pfirewall.log)
                         - Closes File and Printer Sharing, Remote Desktop,
                           Remote Admin and UPnP firewall exceptions
                         - Remote Assistance off (fAllowToGetHelp = 0)
                           and its sessmgr.exe firewall exception off
                         - Stops and disables MSMQ, UPnP Device Host, SSDP,
                           Simple TCP/IP Services, Server + Computer Browser,
                           Remote Registry, Messenger, Telnet
                         - SMBDeviceEnabled = 0 (closes 445 after reboot)
                         - NetBIOS over TCP/IP off on every network
                           interface, incl. disabled/unplugged adapters
                         - Built-in Guest account disabled (found by
                           SID, so a renamed Guest is covered)
                         - No anonymous (null session) listing of shares
                           and accounts (RestrictAnonymous = 1, needs reboot)
                         - No LM password hashes (NoLMHash = 1)
                         - NTLMv2 only (LmCompatibilityLevel = 3)
                         - Passwords 8+ characters, lockout for 30 min
                           after 10 bad tries (net accounts)
                         - AutoRun off (NoDriveTypeAutoRun = 0xFF)
                         Needs an Administrator PowerShell window.
                         Only applies on 32-bit XP (5.1); elsewhere it
                         stops unless you add -Force.
                         -WhatIf                preview, change nothing
                         -Confirm               ask before each step
                         -Force                 apply on non-XP Windows
                         -Skip Name,Name        leave steps alone. Names:
                           Firewall Logging FileAndPrint RemoteDesktop
                           RemoteAdmin UPnPException RemoteAssistance MSMQ
                           UPnP SimpleTcp Server SmbDevice NetBIOS
                           RemoteRegistry Messenger Telnet Guest
                           RestrictAnonymous NoLMHash NTLMv2 PasswordPolicy
                           AutoRun
                         Keep file sharing working:
                             -Skip Server,SmbDevice,NetBIOS,FileAndPrint
                         Needs to reach Windows 9x / very old NAS shares:
                           -Skip NTLMv2

Get-XPHardeningStatus    Read-only check of everything above (and DEP), plus the
                         wormable-flaw fixes, checked by file version so
                         later superseding updates count:
                           Conficker  netapi32.dll >= 5.1.2600.5694
                           WannaCry   srv.sys      >= 5.1.2600.7208
                           BlueKeep   termdd.sys   >= 5.1.2600.7701
                         the AutoRun fix KB967715, and which TCP ports are
                         listening on the network. Ends with a risk/warning
                         count.

Get-AccountAuditXP       Local accounts and Administrators members. Flags
                         accounts allowed a blank password, enabled
                         HelpAssistant/SUPPORT accounts, blank-password
                         network logons, auto logon (and a plain-text
                         Winlogon DefaultPassword), no screen saver lock.

Get-FirewallLogXP        Summarizes pfirewall.log: blocked packets by
                         source, likely port scans (10+ ports), blocked
                         traffic from the internet or outside the subnet.
                         -Hours 24              how far back to read

Test-RouterExposureXP    Tries 16 common TCP ports on the router and checks
                         whether it answers UPnP (SSDP). Inside view only;
                         use GRC ShieldsUP from a modern PC for the outside.
                         -Router 192.168.1.1    default: the gateway

Get-USBHistoryXP         Every USB storage device ever connected (USBSTOR),
                         with serial numbers.

Invoke-XPSecurityCheck   Runs all of the checks, flags devices and USB drives
                         that are new since the last run, prints a fix
                         order, and saves Check_*.txt, Report_*.html and
                         Snapshot_*.xml to My Documents\SecurityChecks.
                         -ActiveScan            ping-sweep the subnet too
                         -NoRouter / -NoReport  skip the router / save nothing

Invoke-XPAssistant       Security assistant (alias: xpai). Uses the findings
                         from the checks you ran this session.
                           xpai                 interactive XP-AI> prompt
                           xpai -Scan           run the status checks first
                           xpai "what is netbios"
                         At the prompt: summary, plan, list, explain <n>,
                         scan, topics, help, exit, or any question.
                         Offline by default: built-in notes, nothing leaves
                         this PC. Claude mode: see below.

Get-ThreatExposureXP     Rates this PC Protected / Partly / Exposed against
                         WannaCry, Conficker, BlueKeep, USB worms, password
                         guessing and theft, and web/email ransomware, from
                         its real patches and settings.

Find-MalwareIndicatorXP  Not an antivirus: looks for signs of infection where
                         XP malware hides (Run keys, Startup, Winlogon,
                         AppInit_DLLs, IFEO, Temp/RECYCLER programs, hosts
                         file, autorun.inf, scheduled tasks), checks the
                         antivirus, and saves SHA-256 hashes with VirusTotal
                         links to check from a modern PC.
                         -ExportPath file.csv   save the hashes

Start-NetSecToolkitXP    The numbered menu NetSecToolkitXP.exe opens.

Set-XPAssistantConfig    Saves the relay address/token for Claude mode.
                           -RelayUrl http://<host>:8787 -RelayToken <token>
                           -DefaultMode Claude  -Test  -Clear

The checks accept -PassThru to return objects as well as the report.
Get-Help <command> -Full shows the built-in help.

Hardening a fresh XP machine
----------------------------
  Import-Module C:\path\to\NetSecToolkitXP\NetSecToolkitXP.psd1
  Get-XPHardeningStatus          # before
  Set-XPHardening -WhatIf        # preview
  Set-XPHardening
  Restart-Computer
  Get-XPHardeningStatus          # after: target is only 135 listening
Then run Legacy Update and re-check the patches. The BlueKeep fix
(KB4500331) is only on the Microsoft Update Catalog, not Windows Update.

What this does NOT cover: patches (use Legacy Update / the Update Catalog),
the Administrator password, a non-admin daily account, and phishing.
Side effects: this PC can no longer share files/printers, open other PCs'
shares (\\PC\share), accept Remote Desktop, or host LAN games. Browsing,
downloads and Windows Update are unaffected (outbound traffic).

Claude mode (optional)
----------------------
XP cannot make the TLS 1.2 connections the Claude API needs, so a relay
runs on a modern PC (for a VM: the host) and makes the call for it.
On the host, in PowerShell 7 (needs an Anthropic API key; usage is billed):
  $env:ANTHROPIC_API_KEY = 'sk-ant-...'
  .\relay\Start-ClaudeRelay.ps1 -AllowedClient <XP VM address>
It prints a token and the command to run on XP:
  Set-XPAssistantConfig -RelayUrl http://<host>:8787 -RelayToken <token> -DefaultMode Claude -Test
The API key never leaves the host. MAC addresses, the PC name and your
user name are masked before sending (-NoRedact turns that off). The XP-to-
relay hop is plain HTTP: keep it on a host-only or NAT VM network. If the
relay is down, the assistant answers from its offline notes.

Examples
--------
  Get-NetAdapterHealthXP
  Get-FirewallAuditXP -ExportPath C:\fw-exceptions.csv
  Find-NetworkDeviceXP -ResolveNames -ExportPath C:\devices.csv

Differences from NetSecToolkit (PowerShell 7)
---------------------------------------------
- WMI and COM instead of the Net* cmdlets (Windows 8+ only).
- netsh firewall instead of advfirewall; the XP firewall has no
  per-rule inbound/outbound model, only exceptions.
- Sweep runs one host at a time (no -Parallel in PS 2.0); a /24 takes
  under a minute at the default timeout. Subnets larger than /22 are
  capped to the local /24.
- No speed test or Wi-Fi commands yet. Set-XPHardening covers what
  Set-FirewallBaseline does on the PS7 module, and more.
  Invoke-XPSecurityCheck is the XP version of Invoke-DailySecurityCheck.
- Settings on the Domain profile are reported as Info unless the PC is
  actually on a domain network.

Testing and known limits
------------------------
- Verified on a real XP Pro SP3 VM (VMware Workstation, PowerShell 2.0)
  with 0.2.2: all five commands ran without errors. Set-XPHardening
  applied 16 steps with 0 failures (2 N/A), and after a reboot
  Get-XPHardeningStatus went from 12 warnings to 0 risks, 0 warnings,
  with only port 135 listening. Also checked in PowerShell 7 with mocked
  data and a scan for PS 3.0+ syntax. Not yet run on the physical XP
  laptop (Dell Inspiron 1521), where the same steps were first done by
  hand.
- 0.2.3 came from a code review. Each fix was checked against mocks that
  reproduce the bug on 0.2.2 first; the fixes have not had an XP VM run
  yet.
- 0.3.0 (new checks, hardening steps and the assistant) was tested with
  mocked data in PowerShell 7, including Claude mode end to end through
  the relay to a fake API, plus an independent PS 2.0 compatibility
  review. 0.3.0 then ran on the hardened XP VM without errors; its three
  false findings (VMware NAT as "router", ASPNET account, unnamed removed
  adapters) are fixed in 0.3.1.
- XP x64 / Server 2003 (5.2) are not supported. Get-XPHardeningStatus
  skips the wormable-flaw checks there, because their 5.2.3790.x file
  versions would always look newer than the XP fixes.
- Remote Desktop / Remote Admin exceptions don't exist on XP Home; those
  steps report Failed there. Re-run with -Skip RemoteDesktop,RemoteAdmin.
- Firewall logging is one setting for all profiles on XP, read from
  netsh firewall show logging.
- netsh, arp -a, net accounts and net localgroup parsing expects
  English-language XP output.
- DHCP lease time uses System.Management; if it shows blank, ipconfig /all
  has it.

Changes
-------
0.5.0  Threat check (menu option V, and part of Invoke-XPSecurityCheck):
       Get-ThreatExposureXP and Find-MalwareIndicatorXP, with SHA-256 /
       VirusTotal export (Hashes_<time>.csv). Assistant topics: threats,
       malware, VirusTotal, antivirus.
0.4.0  NetSecToolkitXP.exe: double-click launcher that opens the new
       Start-NetSecToolkitXP menu (or runs one command given after it),
       plus NetSecToolkitXP.cmd as a fallback. Reports fall back to
       %USERPROFILE%\My Documents if the shell folder is not set.
0.3.1  Fixes from the first XP run: a VMware/VirtualBox/Hyper-V NAT
       gateway is recognized and its ports reported as Info; ASPNET,
       IUSR_ and IWAM_ service accounts are Info, not "blank password";
       the firewall log always reports its blocked-packet count; removed
       adapters are named in the NetBIOS finding.
0.3.0  Security assistant: Invoke-XPAssistant (xpai), offline notes, fix
       order and finding explanations, optional Claude mode through
       relay\Start-ClaudeRelay.ps1; Set-XPAssistantConfig. New checks:
       Get-AccountAuditXP, Get-FirewallLogXP, Test-RouterExposureXP,
       Get-USBHistoryXP, and the all-in-one Invoke-XPSecurityCheck with
       HTML report and new-device/new-USB alerts. New hardening steps:
       RestrictAnonymous, NoLMHash, NTLMv2, PasswordPolicy; status checks
       them and DEP.
0.2.3  Code review fixes. XP x64 / Server 2003 were reported as patched
       against Conficker, WannaCry and BlueKeep even when they weren't;
       the patch check now only runs on 32-bit XP, and Set-XPHardening
       refuses other versions without -Force. The NetBIOS step no longer
       reports Failed on "done, reboot required" (WMI code 1) and now
       covers disabled/unplugged adapters. A renamed Guest account is
       found by SID. The Remote Assistance firewall exception is turned
       off too. Status also checks the Computer Browser service.
0.2.2  Set-XPHardening also turns on firewall logging and turns off
       Remote Assistance. Firewall logging is now read from netsh (the
       registry check was wrong). Tables fit the console window.
       Find-NetworkDeviceXP re-pings hosts whose ARP entry expired during
       the sweep, so the gateway MAC is no longer blank.
0.2.1  Wormable-flaw patch checks compare file versions instead of KB
       numbers, so superseding updates count.
0.2.0  Added Set-XPHardening and Get-XPHardeningStatus.
0.1.0  Get-NetAdapterHealthXP, Get-FirewallAuditXP, Find-NetworkDeviceXP.
