# NetSecToolkitXP

![PowerShell 2.0](https://img.shields.io/badge/PowerShell-2.0-blue) ![Windows XP SP3](https://img.shields.io/badge/Windows-XP%20SP3-green) ![Version 0.2.2](https://img.shields.io/badge/version-0.2.2-lightgrey)

The Windows XP SP3 / PowerShell 2.0 edition of my [PowerShell Network Security Toolkit](https://github.com/EdwardOconnell/powershell-network-security-toolkit).

The main toolkit targets PowerShell 7 and relies on the `Net*` cmdlets (`Get-NetAdapter`, `Get-NetFirewallRule`), which only exist on Windows 8 and later. This edition rebuilds the core checks with WMI, COM and `netsh firewall` so they run on XP. It also adds a one-command hardening baseline based on locking down a real XP laptop.

Everything is read-only except `Set-XPHardening`, which supports `-WhatIf`.

## Commands

| Command | What it does |
|---|---|
| `Get-NetAdapterHealthXP` | Adapters from WMI: IP, mask, gateway, DNS, DHCP lease, NetBIOS. Flags APIPA addresses, missing gateway/DNS and NetBIOS. Pings the gateway and 8.8.8.8 and tests DNS. |
| `Get-FirewallAuditXP` | Audits Windows Firewall through the `HNetCfg.FwMgr` COM API: service state, Domain and Standard profiles, service/program/port exceptions and ICMP, plus logging from `netsh firewall show logging`. Prints `netsh` fixes. |
| `Find-NetworkDeviceXP` | Ping sweep of the local subnet plus `arp -a`, so devices that block ping still show up. Marks the gateway, this PC and randomized MACs. |
| `Set-XPHardening` | Applies the hardening baseline in one run (details below). Supports `-WhatIf`, `-Confirm` and `-Skip`. |
| `Get-XPHardeningStatus` | Read-only check of the baseline, the wormable-flaw patches, and which TCP ports are listening on the network. Ends with a risk/warning count. |

All commands accept `-PassThru` to return objects, and `Get-Help <command> -Full` shows the built-in help.

## Requirements

- Windows XP SP3 (Professional recommended; see [Known limits](#known-limits))
- .NET Framework 2.0 SP1 or later (3.5 SP1 covers it)
- Windows PowerShell 2.0, from the Windows Management Framework Core package (KB968930)

## Install

1. Download the repo and copy the `NetSecToolkitXP` folder to the XP machine, for example:
   `C:\Documents and Settings\<you>\My Documents\WindowsPowerShell\Modules\NetSecToolkitXP`
2. If you downloaded it with a browser on XP, right-click each file, choose **Properties**, and click **Unblock**. PS 2.0 has no `Unblock-File`.
3. Allow local scripts, once:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
   Or for one session only: `powershell -ExecutionPolicy Bypass`
4. Import the module:
   ```powershell
   Import-Module NetSecToolkitXP
   ```
   Or by path, from anywhere: `Import-Module C:\path\to\NetSecToolkitXP\NetSecToolkitXP.psd1`

### Load it in every new window (optional)

PowerShell 2.0 doesn't load modules automatically, so each new window needs `Import-Module` first. To have it load every time, add the import to your profile once:

```powershell
New-Item -ItemType File -Path $PROFILE -Force
Add-Content -Path $PROFILE -Value "Import-Module 'C:\path\to\NetSecToolkitXP\NetSecToolkitXP.psd1'"
```

## Usage

### `Get-NetAdapterHealthXP`

Shows each IP-enabled adapter's status, MAC, IPv4 address and mask, gateway, DNS servers, DHCP lease and NetBIOS setting, then tests connectivity: it pings the gateway and 8.8.8.8 and resolves `www.microsoft.com`.

```powershell
Get-NetAdapterHealthXP
```

It flags APIPA addresses (169.254.x.x, meaning DHCP failed), missing gateway or DNS, and NetBIOS over TCP/IP being on.

### `Get-FirewallAuditXP`

Read-only audit of Windows Firewall. It checks the firewall service, both profiles (Domain and Standard), service/program/port exceptions, ICMP and logging, and prints the `netsh` command to fix anything it flags.

```powershell
Get-FirewallAuditXP
Get-FirewallAuditXP -ExportPath C:\fw-exceptions.csv   # also save the exception list
```

Findings on the Domain profile are reported as Info unless the PC is actually on a domain network.

### `Find-NetworkDeviceXP`

Finds devices on the local subnet. It pings every address (one at a time; a /24 takes under a minute), then reads the ARP table, so devices that block ping still show up.

```powershell
Find-NetworkDeviceXP                                    # default sweep
Find-NetworkDeviceXP -ResolveNames                      # add hostnames (slower)
Find-NetworkDeviceXP -NoSweep                           # only read the current ARP table
Find-NetworkDeviceXP -TimeoutMs 500                     # longer ping timeout for slow networks
Find-NetworkDeviceXP -ExportPath C:\devices.csv         # also save the list
```

Output columns: IP, MAC, role (gateway / this PC), whether it answered ping, latency, and whether the MAC is randomized (common on phones). Subnets larger than /22 are capped to the local /24.

### `Get-XPHardeningStatus`

Read-only check of the full baseline: firewall and logging, services, SMB/NetBIOS, Guest account, Remote Assistance, AutoRun, the three wormable-flaw fixes (checked by file version) and network-facing TCP ports. Ends with a risk/warning count.

```powershell
Get-XPHardeningStatus
```

### `Set-XPHardening`

Applies the baseline. Run it in an Administrator window, preview with `-WhatIf` first, and reboot afterward. See [Hardening a machine](#hardening-a-machine) for the full walkthrough and the list of steps.

```powershell
Set-XPHardening -WhatIf                                  # preview, changes nothing
Set-XPHardening                                          # apply
Set-XPHardening -Confirm                                 # ask before each step
Set-XPHardening -Skip Server,SmbDevice,NetBIOS,FileAndPrint   # keep file sharing
```

## Hardening a machine

Run these in an **Administrator** PowerShell window:

```powershell
Get-XPHardeningStatus     # before
Set-XPHardening -WhatIf   # preview, changes nothing
Set-XPHardening
Restart-Computer
Get-XPHardeningStatus     # after
```

Then run Legacy Update and check the patches again with `Get-XPHardeningStatus`.

### What `Set-XPHardening` changes

| Step | Change | Closes |
|---|---|---|
| `Firewall` | Firewall on, exceptions disabled, all profiles | All inbound exceptions |
| `Logging` | Logs dropped packets and connections to `%windir%\pfirewall.log` | |
| `FileAndPrint`, `RemoteDesktop`, `RemoteAdmin`, `UPnPException` | Firewall service exceptions closed | 139, 445, 3389, 135, 2869, 1900 |
| `MSMQ` | Message Queuing stopped and disabled | 1801, 2103, 2105, 2107, 3527 |
| `UPnP` | UPnP Device Host and SSDP Discovery stopped and disabled | 2869, 1900 |
| `SimpleTcp` | Simple TCP/IP Services stopped and disabled | 7, 9, 13, 17, 19 |
| `Server` | Server and Computer Browser stopped and disabled | File sharing |
| `SmbDevice` | `SMBDeviceEnabled = 0` (applies after a reboot) | 445 |
| `NetBIOS` | NetBIOS over TCP/IP off on every IP adapter | 137-139 |
| `RemoteAssistance` | Remote Assistance off (`fAllowToGetHelp = 0`) | |
| `RemoteRegistry`, `Messenger`, `Telnet` | Stopped and disabled | |
| `Guest` | Guest account disabled | |
| `AutoRun` | `NoDriveTypeAutoRun = 0xFF` | |

Each step reports **Applied**, **N/A** (not installed), **Skipped** or **Failed**, and a failed step doesn't stop the rest.

To keep file sharing working, skip those steps:

```powershell
Set-XPHardening -Skip Server,SmbDevice,NetBIOS,FileAndPrint
```

### Side effects

The PC can no longer share files or printers, open other PCs' shares (`\\PC\share`), accept Remote Desktop, or host LAN games. Browsing, downloads and Windows Update are outbound, so they keep working.

### What it does not cover

- **Patches.** Use Legacy Update or the Microsoft Update Catalog. `Get-XPHardeningStatus` checks the three wormable flaws by the **file version** each fix installed, not by KB number, because later updates (including POSReady 2009 updates) supersede the original KBs:

  | Flaw | File | Fixed in | Original KB |
  |---|---|---|---|
  | MS08-067 (Conficker) | `netapi32.dll` | 5.1.2600.5694 | KB958644 |
  | MS17-010 (WannaCry) | `drivers\srv.sys` | 5.1.2600.7208 | KB4012598 |
  | CVE-2019-0708 (BlueKeep) | `drivers\termdd.sys` | 5.1.2600.7701 | KB4500331 (Update Catalog only) |
- The Administrator password and a non-admin account for daily use.
- **Phishing.** Closing inbound ports doesn't stop a user from clicking a malicious link. XP's browsers are long unsupported, so keep browsing to a minimum.

## Case study: Dell Inspiron 1521

These steps were first done by hand on an XP SP3 laptop, then collected into `Set-XPHardening`.

**Before:** the firewall was on but allowed exceptions. `netsh firewall show state` listed open ports for MSMQ (135, 1801, 2103, 2105, 2107, 1026, 1027, 3527), UPnP (2869, 1900), Windows peer-to-peer networking (3540, 3587) and Teredo (3544). `netstat` also showed Simple TCP/IP Services on 7, 9, 13, 17 and 19, plus SMB on 445 and NetBIOS on 139. Only 8 updates were installed, and all three wormable-flaw patches were missing.

**After:** the firewall reported *"No ports are currently open on all network interfaces."* `netstat` listening ports went from 15+ down to RPC on 135 (which can't be closed on XP, and the firewall blocks it) and localhost-only listeners. At the time of writing, 445 was waiting on its reboot.

<!-- Add before/after photos or screenshots of netsh firewall show state and netstat here -->

## Verified on an XP VM

Tested with 0.2.2 on Windows XP Professional SP3 in VMware Workstation (PowerShell 2.0, fully updated through Legacy Update plus KB4500331), starting from a pre-hardening snapshot:

| | Before | After `Set-XPHardening` + reboot |
|---|---|---|
| `Get-XPHardeningStatus` | 0 risks, 12 warnings | **0 risks, 0 warnings** |
| Firewall | On, exceptions allowed, logging off | On, exceptions disabled, logging on |
| Remote Assistance | On | Off |
| Network-facing TCP ports | 135, 139, 445 | **135 only** (RPC, blocked by the firewall) |

`Set-XPHardening` reported 16 steps Applied, 2 N/A (MSMQ and Simple TCP/IP Services weren't installed on the VM) and 0 Failed. All five commands ran without errors, including the 0.2.2 fixes: the firewall audit reads logging correctly and its tables fit the console, and `Find-NetworkDeviceXP` reports the gateway's MAC.

<!-- Add before/after screenshots of Get-XPHardeningStatus here -->

## External verification

`Get-XPHardeningStatus` checks the VM from the inside. To confirm the firewall actually blocks traffic, the hardened VM was also probed from the Windows 11 host over VMware's NAT network (host `192.168.107.1`, VM `192.168.107.128`), using PowerShell 7:

```powershell
$xp = '192.168.107.128'
135,139,445,3389,2869,5985,80 | ForEach-Object {
    [pscustomobject]@{ Port = $_; Open = (Test-Connection $xp -TcpPort $_ -TimeoutSeconds 2) }
}
ping $xp
```

| Port | Service | Reachable from the host |
|---|---|---|
| 135 | RPC (still listening on the VM) | No |
| 139 | NetBIOS session | No |
| 445 | SMB | No |
| 3389 | Remote Desktop | No |
| 2869 | UPnP | No |
| 5985, 80 | Windows Remote Management | No |
| ICMP | Ping | No (100% loss) |

Port 135 is the key result: XP is still listening on it, so the block comes from the firewall, not from the service being off.

An all-blocked result would look the same if the VM were simply unreachable, so the XP firewall log (`C:\WINDOWS\pfirewall.log`, enabled by the `Logging` step) was checked to confirm the probes arrived and were dropped:

```
2026-10-04 17:47:03 DROP TCP 192.168.107.1 192.168.107.128 54130 135 52 S 2738703890 0 65535 - - - RECEIVE
2026-10-04 17:47:05 DROP TCP 192.168.107.1 192.168.107.128 54133 139 52 S 1925047705 0 65535 - - - RECEIVE
2026-10-04 17:47:07 DROP TCP 192.168.107.1 192.168.107.128 54137 445 52 S 2457819011 0 65535 - - - RECEIVE
2026-10-04 17:47:09 DROP TCP 192.168.107.1 192.168.107.128 55191 3389 52 S 3013061225 0 65535 - - - RECEIVE
2026-10-04 17:47:17 DROP ICMP 192.168.107.1 192.168.107.128 - - 60 - - - - 8 0 - RECEIVE
2026-10-04 17:47:38 CLOSE UDP 192.168.107.128 192.168.107.2 64133 53 - - - - - - - - -
```

- `DROP TCP ... S`: a dropped connection attempt (`S` is the TCP SYN flag). Each port appears twice in the full log because the host retried once.
- `DROP ICMP ... 8 0`: a dropped ping (ICMP type 8, code 0 is an echo request).
- `CLOSE UDP ... 53`: the VM's own outbound DNS lookup completing normally, showing outbound traffic still works and is logged.

<!-- Control test: revert to the pre-hardening snapshot and run the same probe; add the before/after results here -->

## Testing

- Parsed with the PowerShell language parser, plus a scan for PowerShell 3.0+ syntax: `[pscustomobject]`, `[ordered]`, `-in`, simplified `Where-Object`, `-Parallel`, PS3+ parameters.
- Every command exercised in PowerShell 7 against mocked WMI, COM, `netsh`, ARP and registry data, including the `-WhatIf`, `-Skip`, failed-step and already-applied paths.
- Real runs on an XP Professional SP3 VM: see [Verified on an XP VM](#verified-on-an-xp-vm) and [External verification](#external-verification). Each round of VM testing found real bugs that mocks missed: a false positive in the original KB-number patch check (fixed in 0.2.1), and a wrong logging check, a missing gateway MAC and wrapped tables (fixed in 0.2.2).
- Files are pure ASCII with CRLF line endings, so PS 2.0 reads them correctly and they open cleanly in XP's Notepad.
- Recommended: test in an XP SP3 VM using **NAT or Host-only networking** (never Bridged), with a snapshot taken before running `Set-XPHardening`.

## Known limits

- Built for **XP SP3**. Remote Desktop and Remote Admin exceptions don't exist on XP Home, so those steps report Failed there. Use `-Skip RemoteDesktop,RemoteAdmin`.
- **Vista and 7 are not supported yet.** They use Windows Firewall with Advanced Security (`MpsSvc` and `netsh advfirewall`), different patch KB numbers, and a different SMB stack.
- `netsh` and `arp -a` parsing expects English-language XP output.
- Firewall logging is a single setting for all profiles on XP, read from `netsh firewall show logging`.
- DHCP lease times use `System.Management`; if one shows blank, `ipconfig /all` has it.

## Roadmap

- `Set-XPHardening` run on the physical XP laptop, with results added above
- Vista / 7 support: OS detection, `advfirewall` commands, per-OS patch IDs
- Router exposure check, as in the main toolkit

## Changelog

- **0.2.2:** `Set-XPHardening` also turns on firewall logging and turns off Remote Assistance. Logging is now read from `netsh` (the old registry check reported logging off when it was on). Tables fit the console window. `Find-NetworkDeviceXP` re-pings hosts whose ARP entry expired during the sweep, so the gateway's MAC is no longer blank.
- **0.2.1:** Wormable-flaw checks compare file versions instead of KB numbers, so superseding updates count.
- **0.2.0:** Added `Set-XPHardening` and `Get-XPHardeningStatus`.
- **0.1.0:** `Get-NetAdapterHealthXP`, `Get-FirewallAuditXP`, `Find-NetworkDeviceXP`.

## Disclaimer

Use this only on systems you own or are authorized to manage. Windows XP has been unsupported since 2014. Hardening reduces the network attack surface, but it doesn't make XP safe for everyday internet use. Keep XP machines off untrusted networks.
