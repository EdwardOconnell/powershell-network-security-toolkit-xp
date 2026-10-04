NetSecToolkitXP 0.2.0
=====================
Windows XP SP3 / PowerShell 2.0 test build of NetSecToolkit.
Everything is read-only except Set-XPHardening, which applies the
hardening baseline (use -WhatIf first to preview it).

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
                         (flags risky ones), logging.
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
                         - Closes File and Printer Sharing, Remote Desktop,
                           Remote Admin and UPnP firewall exceptions
                         - Stops and disables MSMQ, UPnP Device Host, SSDP,
                           Simple TCP/IP Services, Server + Computer Browser,
                           Remote Registry, Messenger, Telnet
                         - SMBDeviceEnabled = 0 (closes 445 after reboot)
                         - NetBIOS over TCP/IP off on all IP adapters
                         - Guest account disabled
                         - AutoRun off (NoDriveTypeAutoRun = 0xFF)
                         Needs an Administrator PowerShell window.
                         -WhatIf                preview, change nothing
                         -Confirm               ask before each step
                         -Skip Name,Name        leave steps alone. Names:
                           Firewall FileAndPrint RemoteDesktop RemoteAdmin
                           UPnPException MSMQ UPnP SimpleTcp Server SmbDevice
                           NetBIOS RemoteRegistry Messenger Telnet Guest AutoRun
                         Keep file sharing working:
                           -Skip Server,SmbDevice,NetBIOS,FileAndPrint

Get-XPHardeningStatus    Read-only check of everything above, plus the
                         wormable-flaw patches (KB958644 Conficker,
                         KB4012598 WannaCry, KB4500331 BlueKeep), the AutoRun
                         fix KB967715, and which TCP ports are listening on
                         the network. Ends with a risk/warning count.

All commands accept -PassThru to return objects as well as the report.
Get-Help <command> -Full shows the built-in help.

Hardening a fresh XP machine
----------------------------
  Import-Module C:\path\to\NetSecToolkitXP\NetSecToolkitXP.psd1
  Get-XPHardeningStatus          # before
  Set-XPHardening -WhatIf        # preview
  Set-XPHardening
  Restart-Computer
  Get-XPHardeningStatus          # after: target is only 135 listening
Then run Legacy Update and re-check the patches.

What this does NOT cover: patches (use Legacy Update / the Update Catalog),
the Administrator password, a non-admin daily account, and phishing.
Side effects: this PC can no longer share files/printers, open other PCs'
shares (\\PC\share), accept Remote Desktop, or host LAN games. Browsing,
downloads and Windows Update are unaffected (outbound traffic).

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
- No router exposure, speed test or Wi-Fi commands yet. Set-XPHardening
  covers what Set-FirewallBaseline does on the PS7 module, and more.
- Settings on the Domain profile are reported as Info unless the PC is
  actually on a domain network.

Known limits / not yet verified on real XP
------------------------------------------
- Built and checked in PowerShell 7 with mocked WMI/COM/ARP/netsh data
  and a scan for PS 3.0+ syntax. The hardening steps match commands run
  by hand on a real XP SP3 laptop (Dell Inspiron 1521); the module itself
  still needs its first real run there.
- Remote Desktop / Remote Admin exceptions don't exist on XP Home; those
  steps report Failed there. Re-run with -Skip RemoteDesktop,RemoteAdmin.
- Firewall logging is read from
  HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\
  FirewallPolicy\<Profile>\Logging. Cross-check with:
    netsh firewall show logging
- arp -a parsing expects English-language XP output.
- DHCP lease time uses System.Management; if it shows blank, ipconfig /all
  has it.
