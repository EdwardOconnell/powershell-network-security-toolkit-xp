# NetSecToolkit

![CI](https://github.com/EdwardOconnell/powershell-network-security-toolkit/actions/workflows/ci.yml/badge.svg)

A PowerShell 7 module for auditing a Windows PC and the network it's connected to: firewall configuration, network adapters, devices on the local network, router exposure, and connection speed. Every audit command is **read-only**. The one command that changes settings, `Set-FirewallBaseline`, applies the audit's recommended firewall fixes and supports `-WhatIf` to preview first.

Built and tested on real home and small-office networks (ASUS routers, mixed Wi-Fi 5/6/7 clients, Windows 11).

## Commands

| Command | What it does | Admin? |
|---|---|---|
| `Invoke-DailySecurityCheck` | All-in-one daily check: adapters, firewall, firewall log, network devices, printers, USB devices. Saves a report and flags **new devices and USB drives** since the last run. | Yes |
| `Get-FirewallAudit` | Audits Windows Defender Firewall: profiles, default actions, logging, inbound rules exposing risky ports (RDP, SMB, WinRM, etc.), and allowed programs in user-writable folders. | Yes |
| `Set-FirewallBaseline` | Applies the fixes `Get-FirewallAudit` recommends: turns on logging of blocked connections for every profile and disables the Remote Assistance rules. Changes only what isn't already compliant. Supports `-WhatIf` and `-Confirm`. | Yes |
| `Get-NetAdapterHealth` | Checks every adapter: link state, IP, APIPA detection, gateway reachability, driver health, packet errors, internet and DNS. | Yes |
| `Find-NetworkDevice` | Lists devices on the local subnet using a parallel ping sweep plus the ARP table, with hostnames and randomized-MAC detection. `-Passive` sends no traffic. | No |
| `Test-RouterExposure` | Checks which services the router exposes on the LAN, shows your public IP for an outside test, and can dump the router's iptables rules over SSH. | No |
| `Test-NetworkSpeed` | Speed test (latency, jitter, download, upload) that also shows the network you're on: SSID, band, channel, Wi-Fi standard, signal, security (WPA2/WPA3), router, and ISP. Supports Wi-Fi 7 multi-link (MLO). Keeps a history for comparing networks. | No |

Every command has built-in help, for example `Get-Help Test-NetworkSpeed -Full`. Add `-PassThru` to any command to get its results as objects for further scripting.

## Install

Requires Windows 10 or 11 and [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows) or later.

```powershell
git clone https://github.com/EdwardOconnell/powershell-network-security-toolkit.git
cd powershell-network-security-toolkit
Get-ChildItem -Recurse -Filter *.ps* | Unblock-File     # only needed for downloaded ZIPs
Import-Module ./NetSecToolkit
```

To load it automatically in every session, copy the `NetSecToolkit` folder to `$HOME\Documents\PowerShell\Modules\`.

## Usage

```powershell
Invoke-DailySecurityCheck                      # run in an elevated window
Invoke-DailySecurityCheck -ActiveScan -LogHours 72
Get-FirewallAudit -ExportPath C:\fw-rules.csv
Set-FirewallBaseline -WhatIf                   # preview the firewall fixes
Set-FirewallBaseline                           # apply them, then rerun Get-FirewallAudit
Find-NetworkDevice -Passive
Test-RouterExposure -Router 192.168.1.1
Test-NetworkSpeed -Seconds 15

# Results as objects
$warnings = Invoke-DailySecurityCheck -PassThru
Find-NetworkDevice -PassThru | Where-Object { -not $_.Hostname }
```

## Project structure

```
NetSecToolkit/
  NetSecToolkit.psd1      Module manifest
  NetSecToolkit.psm1      Loads Private/ then Public/, exports Public/ only
  Public/                 One file per exported command
  Private/                Shared helpers and pure parsing functions
tests/                    Pester tests (run in CI on every push)
.github/workflows/ci.yml  PSScriptAnalyzer lint + Pester tests on Windows
```

Parsing logic (netsh Wi-Fi output including Wi-Fi 7 MLO, firewall log lines, subnet math, risky-port matching, speed test math) lives in pure functions under `Private/`, so it's unit tested without touching the system.

## Development

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./NetSecToolkit -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

## Output and privacy

Reports, snapshots, and speed test history are saved to `Documents\SecurityChecks`. They contain IP addresses, MAC addresses, and device names, so the included `.gitignore` keeps them out of the repository.

## Notes

- **Only scan networks you own or are authorized to test.** On a work or shared network, use `Find-NetworkDevice -Passive` or get permission first.
- `Test-NetworkSpeed` uses Cloudflare's public speed test endpoints, so results can differ slightly from other speed test sites.
- `Test-RouterExposure -Ssh` requires SSH to be enabled on the router (LAN only). Turn it back off when you're done.

## Coming from the standalone scripts?

| Old script | New command |
|---|---|
| `Workday-SecurityCheck.ps1` | `Invoke-DailySecurityCheck` |
| `Check-Firewall.ps1` | `Get-FirewallAudit` |
| `Check-NetAdapters.ps1` | `Get-NetAdapterHealth` |
| `Scan-LocalNetwork.ps1` | `Find-NetworkDevice` |
| `Check-RouterFirewall.ps1` | `Test-RouterExposure` |
| `Test-NetworkSpeed.ps1` | `Test-NetworkSpeed` |

Parameters are the same, and reports keep saving to the same folder, so existing history and snapshots carry over.

## License

[MIT](LICENSE)
