<p align="center">
  <img src="assets/eds-logo.png" alt="Edward O'Connell, Cyber Security Professional" width="560">
</p>

# NetSecToolkitXP

![PowerShell 2.0](https://img.shields.io/badge/PowerShell-2.0-blue) ![Windows XP SP3](https://img.shields.io/badge/Windows-XP%20SP3-green) ![Version 0.5.2](https://img.shields.io/badge/version-0.5.2-lightgrey)

The Windows XP SP3 / PowerShell 2.0 edition of my [PowerShell Network Security Toolkit](https://github.com/EdwardOconnell/powershell-network-security-toolkit).

The main toolkit targets PowerShell 7 and relies on the `Net*` cmdlets (`Get-NetAdapter`, `Get-NetFirewallRule`), which only exist on Windows 8 and later. This edition rebuilds the core checks with WMI, COM and `netsh firewall` so they run on XP. It also adds a one-command hardening baseline based on locking down a real XP laptop, an all-in-one daily check, a threat check that shows which current attacks the PC is exposed to and looks for signs of malware, a root certificate update that cuts down HTTPS certificate errors, and a security assistant that explains the findings and says what to fix first.

**Easiest way to run it:** download the release zip, copy it to the XP machine, extract it and double-click **`NetSecToolkitXP.exe`**. A numbered menu opens, with no execution policy changes, `Import-Module` or typing needed. See [Run it with NetSecToolkitXP.exe](#run-it-with-netsectoolkitxpexe).

Everything is read-only except `Set-XPHardening` and `Update-XPRootCertificate` (both support `-WhatIf`), and `Set-XPAssistantConfig` (which only saves the assistant's settings).

## Commands

| Command | What it does |
|---|---|
| `Get-NetAdapterHealthXP` | Adapters from WMI: IP, mask, gateway, DNS, DHCP lease, NetBIOS. Flags APIPA addresses, missing gateway/DNS and NetBIOS. Pings the gateway and 8.8.8.8 and tests DNS. |
| `Get-FirewallAuditXP` | Audits Windows Firewall through the `HNetCfg.FwMgr` COM API: service state, Domain and Standard profiles, service/program/port exceptions and ICMP, plus logging from `netsh firewall show logging`. Prints `netsh` fixes. |
| `Find-NetworkDeviceXP` | Ping sweep of the local subnet plus `arp -a`, so devices that block ping still show up. Marks the gateway, this PC and randomized MACs. |
| `Set-XPHardening` | Applies the hardening baseline in one run (details below). Supports `-WhatIf`, `-Confirm` and `-Skip`. |
| `Get-XPHardeningStatus` | Read-only check of the baseline, logon security (anonymous access, LM hashes, NTLMv2, password and lockout policy, DEP), the wormable-flaw patches, and which TCP ports are listening on the network. Ends with a risk/warning count. |
| `Get-AccountAuditXP` | Local accounts and who is in Administrators. Flags accounts allowed a blank password, enabled support accounts, blank-password network logons, automatic logon (and a plain-text `DefaultPassword` in the registry) and a screen saver with no password. |
| `Get-FirewallLogXP` | Summarizes `pfirewall.log`: how much was blocked, which addresses tried to reach this PC, likely port scans, and blocked traffic from the internet or from outside the subnet. |
| `Test-RouterExposureXP` | Checks 16 common TCP ports on the router from inside the network and whether it answers UPnP discovery. |
| `Get-USBHistoryXP` | Every USB storage device ever connected (model and serial, from `USBSTOR`), and whether USB storage is blocked. |
| `Get-ThreatExposureXP` | Rates the PC **Protected / Partly / Exposed** against the attacks that still hit XP (WannaCry, Conficker, BlueKeep, USB worms, password guessing and theft, web/email ransomware), from its real patches and settings. |
| `Find-MalwareIndicatorXP` | Looks for signs of infection where XP malware hides (startup entries, Winlogon and IFEO hijacks, AppInit_DLLs, Temp/RECYCLER programs, hosts file, autorun.inf, scheduled tasks), checks the antivirus, and exports a SHA-256 + VirusTotal link for every program it looked at. |
| `Get-RootCertStatusXP` | Compares XP's Trusted Root store with today's root certificates (the RSA roots on Mozilla's CA list) and checks for TLS 1.2 support (KB4019276). |
| `Update-XPRootCertificate` | Adds the missing root certificates, so Internet Explorer, Windows Update and PowerShell trust the authorities that sign today's HTTPS sites. Supports `-WhatIf` and `-Remove`. |
| `Invoke-XPSecurityCheck` | Runs all of the checks above in one go, flags devices and USB drives that are new since the last run, and saves a transcript, an HTML report and a snapshot. |
| `Invoke-XPAssistant` (alias `xpai`) | Security assistant: explains findings, answers questions and builds a fix order. Works offline; can also ask Claude through a relay on a modern PC. See [Security assistant](#security-assistant). |
| `Set-XPAssistantConfig` | Saves the relay address and token for the assistant's Claude mode. |
| `Start-NetSecToolkitXP` | The numbered menu that `NetSecToolkitXP.exe` opens. |

The checks accept `-PassThru` to return objects, and `Get-Help <command> -Full` shows the built-in help.

The repo also has `relay\Start-ClaudeRelay.ps1`, which runs on the modern host PC (PowerShell 7), not on XP. It is only needed for the assistant's Claude mode.

## Requirements

- Windows XP SP3 (Professional recommended; see [Known limits](#known-limits))
- .NET Framework 2.0 SP1 or later (3.5 SP1 covers it)
- Windows PowerShell 2.0, from the Windows Management Framework Core package (KB968930)

## Run it with NetSecToolkitXP.exe

1. Download `NetSecToolkitXP-0.5.2.zip` from the [Releases](../../releases) page (or the repo zip), and copy it to the XP machine.
2. Extract it. Keep `NetSecToolkitXP.exe` and the `NetSecToolkitXP` folder together.
3. Double-click **`NetSecToolkitXP.exe`**. Log on as an administrator for options H and C.

![NetSecToolkitXP.exe 0.5.1 menu running on Windows XP SP3](docs/images/exe-menu-0.5.1.png)

**Option H** always shows the `-WhatIf` preview first and changes nothing until you type `YES`. You can type `S` to name steps to leave alone; unknown step names cancel the run. Then it offers to restart.

**Option C** shows which root certificates are missing (the same check as option **T**), then adds them only after you type `YES`. See [Root certificates](#root-certificates-get-rootcertstatusxp-and-update-xprootcertificate).

How the .exe works:

- **It's a small launcher** (13 KB, plain Win32 C, no C runtime; source in [`launcher/`](launcher/)). It starts `powershell.exe -ExecutionPolicy Bypass` for that one window and loads the module from the folder next to it, so the system's execution policy is never changed.
- **It explains what's missing.** If PowerShell 2.0 isn't installed, or the `NetSecToolkitXP` folder isn't next to it, it shows a message saying exactly that.
- **It can run one command.** From a command prompt, `NetSecToolkitXP.exe Invoke-XPSecurityCheck -ActiveScan` runs that command instead of the menu. Double quotes inside the command aren't supported; use single quotes.
- **There's a fallback.** If an antivirus blocks unsigned programs, `NetSecToolkitXP.cmd` does the same thing.

To rebuild the .exe: `launcher/build.sh` with mingw-w64 (`gcc-mingw-w64-i686` on Debian/Ubuntu, or MSYS2 on Windows).

## Install (PowerShell)

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

![Get-FirewallAuditXP on the hardened XP VM](docs/images/firewall-audit.png)

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

![Find-NetworkDeviceXP on VMware's NAT network: gateway, host adapter and DHCP server found](docs/images/device-scan.png)

### `Get-XPHardeningStatus`

Read-only check of the full baseline: firewall and logging, services, SMB/NetBIOS, Guest account, Remote Assistance, AutoRun, logon security (RestrictAnonymous, NoLMHash, LmCompatibilityLevel, password length, lockout, DEP), the three wormable-flaw fixes (checked by file version) and network-facing TCP ports. Ends with a risk/warning count.

```powershell
Get-XPHardeningStatus
```

### `Get-AccountAuditXP`

Lists the local accounts (enabled, admin, password required, locked out, built-in) and flags:

- enabled accounts allowed a blank password (`PasswordRequired = False`)
- enabled `HelpAssistant` / `SUPPORT_388945a0` accounts
- `LimitBlankPasswordUse = 0` (blank-password accounts can log on over the network)
- automatic logon, and a **plain-text password** in `Winlogon\DefaultPassword` (it never prints the password)
- a screen saver that doesn't ask for a password

```powershell
Get-AccountAuditXP
```

### `Get-FirewallLogXP`

Reads `pfirewall.log` (and `pfirewall.log.old` after a rollover) and summarizes blocked traffic by source. It flags one source trying 10+ ports (a likely scan), and blocked traffic from a public internet address that reached this PC directly, which usually means a router port forward or DMZ. Needs the `Logging` step; run it as an administrator if the log can't be read.

```powershell
Get-FirewallLogXP              # last 24 hours
Get-FirewallLogXP -Hours 72
```

Large logs are filtered with plain string checks before any parsing, because PS 2.0 on XP is slow at creating objects.

### `Test-RouterExposureXP`

Connects to 16 common TCP ports on the router (FTP, Telnet, HTTP/HTTPS admin, SMB, PPTP, TR-069 and others), one at a time with a timeout, and sends an SSDP search to see whether the router has UPnP on. Telnet, FTP, PPTP and TR-069 open on the LAN are Risks; an HTTP-only admin page and UPnP are warnings.

```powershell
Test-RouterExposureXP                    # the default gateway
Test-RouterExposureXP -Router 192.168.1.1
```

This is the inside view. For the internet's view, run GRC ShieldsUP from a modern PC or phone on the same network.

### `Get-USBHistoryXP`

Lists every USB disk and CD drive ever connected, from `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, with serial numbers (and marks devices that have none), and reports whether USB storage is blocked (`USBSTOR Start = 4`).

### `Invoke-XPSecurityCheck`

The all-in-one check, modeled on `Invoke-DailySecurityCheck` in the main toolkit. It runs every check above (device discovery reads the ARP cache only unless you add `-ActiveScan`), then:

- flags **devices that are new** since the last check on the same network (identified by the router's MAC). The saved device list keeps every device seen so far, so a phone that dropped out of the ARP cache isn't reported as new when it comes back.
- flags **USB storage devices** connected since the last check
- prints a summary and the assistant's fix order
- saves `Check_<time>.txt` (transcript), `Report_<time>.html` (opens in IE on XP) and `Snapshot_<time>.xml` to `My Documents\SecurityChecks`

```powershell
Invoke-XPSecurityCheck
Invoke-XPSecurityCheck -ActiveScan -LogHours 72
Invoke-XPSecurityCheck -NoRouter -NoReport
```

It changes no settings.

### Threat check: `Get-ThreatExposureXP` and `Find-MalwareIndicatorXP`

Menu option **V** runs both, and `Invoke-XPSecurityCheck` (option 1) includes them.

**It is not an antivirus.** Real virus scanning needs millions of signatures updated daily, and XP can't download them (it has no TLS 1.2). Instead, it answers two questions honestly.

**1. What is this PC exposed to?** `Get-ThreatExposureXP` reads the patches and settings each attack depends on:

| Threat | Protected when |
|---|---|
| WannaCry / EternalBlue (SMB ransomware worms) | MS17-010 patched (`srv.sys`) and SMB not reachable |
| Conficker (network + USB) | MS08-067 patched (`netapi32.dll`), SMB not reachable, AutoRun off |
| BlueKeep (Remote Desktop) | Remote Desktop off, or patched (`termdd.sys`) and blocked by the firewall |
| USB worms | AutoRun off for all drive types |
| Password guessing (botnets) | Firewall on, Guest off, account lockout on, anonymous listing blocked |
| Password theft (hashes) | No LM hashes, NTLMv2 only. XP can't stop pass-the-hash, so the best rating is Partly. |
| Web and email (ransomware, phishing) | Not possible while XP is online: its browsers and mail programs get no fixes |

Exposed threats that a patch or setting can fix count as **Risks**. The two that XP itself can't fix are **Info**, so they don't bury the fixable items.

**2. Are there signs of infection?** `Find-MalwareIndicatorXP` checks the places XP malware uses to start and hide:

- Run/RunOnce keys and Startup folders
- Winlogon `Shell`/`Userinit`, `AppInit_DLLs`, and Image File Execution Options `Debugger` hijacks (used to block Task Manager or antivirus)
- services, running programs and scheduled tasks started from Temp, the Recycle Bin (`RECYCLER`) or straight from Application Data
- a hosts file that redirects update or antivirus sites
- `autorun.inf` on fixed and removable drives
- program files in Temp, and ones hidden in `RECYCLER` (XP renames real deleted files to `Dc<n>.ext`, so those are left alone)
- whether an antivirus is registered with Security Center, on, and up to date

It knows XP's own defaults, like the sample IFEO key that runs `ntsd -d` and Process Explorer replacing Task Manager.

**Check the files with VirusTotal:** every program it looks at gets a SHA-256 hash. `-ExportPath` (and options V and 1, as `My Documents\SecurityChecks\Hashes_<time>.csv`) saves them with a VirusTotal link. Open the CSV on a modern PC and click a link to see what 70+ antivirus engines say about that exact file, without copying it off the VM.

```powershell
Get-ThreatExposureXP
Find-MalwareIndicatorXP -ExportPath C:\hashes.csv
```

### Root certificates: `Get-RootCertStatusXP` and `Update-XPRootCertificate`

Menu option **T** runs the check, option **C** runs the update, and `Invoke-XPSecurityCheck` (option 1) includes the check.

XP's list of trusted certificate authorities stopped updating years ago, so Internet Explorer says *"There is a problem with this website's security certificate"* on sites signed by newer authorities such as Let's Encrypt. The toolkit ships the current roots in `NetSecToolkitXP\RootCerts`:

- **Where they come from:** Mozilla's CA list (certifi 2026.10.23), the same list Firefox and most Linux systems trust.
- **79 of its 118 roots:** only the RSA ones. The other 39 use ECC keys, which XP can't read, so leaving them out changes nothing.
- **Also in the folder:** `RootCerts.csv` lists every root's SHA-1 thumbprint and expiry, and `XP-RootCerts.p7b` is the same set for a manual import with `mmc`.

`Update-XPRootCertificate` adds the missing roots to the Local Computer **Trusted Root Certification Authorities** store:

- **Adds only:** roots that are already there or expired are skipped, and nothing is replaced.
- **Logs what changed:** the list is saved to `My Documents\SecurityChecks\RootCerts_<time>.txt`.
- **Can be undone:** `-Remove` takes the listed roots back out.

**Root certificates are only half of the problem.** Most sites also require TLS 1.2, which XP SP3 doesn't have out of the box:

- **What the check reports:** `Get-RootCertStatusXP` says whether the POSReady update **KB4019276** (TLS 1.1/1.2 for XP) is installed. [Legacy Update](https://legacyupdate.net) installs it.
- **What still won't work:** even with KB4019276, XP lacks the newer ciphers, so some sites still won't load in IE.
- **What works best:** a browser with its own TLS and certificates, such as Supermium.

```powershell
Get-RootCertStatusXP
Update-XPRootCertificate -WhatIf
Update-XPRootCertificate
Update-XPRootCertificate -Remove
```

### `Set-XPHardening`

Applies the baseline. Run it in an Administrator window, preview with `-WhatIf` first, and reboot afterward. See [Hardening a machine](#hardening-a-machine) for the full walkthrough and the list of steps.

```powershell
Set-XPHardening -WhatIf                                  # preview, changes nothing
Set-XPHardening                                          # apply
Set-XPHardening -Confirm                                 # ask before each step
Set-XPHardening -Skip Server,SmbDevice,NetBIOS,FileAndPrint   # keep file sharing
```

It only applies changes on 32-bit Windows XP (version 5.1). On anything else, including XP x64 and Server 2003, it stops with a message; `-WhatIf` still previews, and `-Force` applies anyway at your own risk.

## Security assistant

`Invoke-XPAssistant` (or just `xpai`) explains what the checks found and what to do about it. It picks up the findings from every check you ran in the session, or you can pipe them in or use `-Scan`.

```powershell
Get-XPHardeningStatus
xpai                                        # interactive prompt
xpai -Scan                                  # run the status and account checks first
xpai "what is netbios"                      # one question
Get-XPHardeningStatus -PassThru | Invoke-XPAssistant -Question plan
```

At the `XP-AI>` prompt:

| Type | Gets you |
|---|---|
| `summary` | Risk/warning counts and the top risks |
| `plan` | What to fix first, in order, with the commands. Risks that need their own fix come first, then one `Set-XPHardening` run for everything it covers, then the rest. |
| `list` / `explain <n>` | Numbered issues / what issue *n* means and how to fix it |
| `scan` | Runs `Get-XPHardeningStatus` and `Get-AccountAuditXP` and reloads |
| `topics` | Everything the offline notes cover (42 topics) |
| any question | "why turn off smb", "what is 445", "how do I undo the hardening", "is xp safe online" |

### Offline mode (default)

Answers come from notes built into the module, covering every finding the toolkit can produce, XP's wormable flaws, NTLM and LM hashes, DEP, the router, USB, undoing a step, and more. Each answer also lists the matching findings on this PC. Nothing leaves the machine, and it needs no internet.

### Claude mode (optional)

Claude mode sends your question and the loaded findings to Claude for open-ended answers. XP can't make the TLS 1.2 connections the Claude API requires, so a small relay runs on a modern PC (for a VM, the host) and makes the HTTPS call for it:

```
XP VM  --plain HTTP, VM network, relay token-->  Start-ClaudeRelay.ps1 (Windows 11, PowerShell 7)  --HTTPS-->  Claude API
```

**On the host** (PowerShell 7). This needs an Anthropic API key from console.anthropic.com, and usage is billed to that account:

```powershell
$env:ANTHROPIC_API_KEY = 'sk-ant-...'
.\relay\Start-ClaudeRelay.ps1 -AllowedClient 192.168.107.128    # the XP VM's address
```

It listens on the VMware VMnet1/VMnet8 host adapter (or `-ListenAddress`), and prints a token and the exact command to run on XP. If XP can't connect, the relay also prints a Windows Firewall rule scoped to that adapter.

**On XP:**

```powershell
Set-XPAssistantConfig -RelayUrl http://192.168.107.1:8787 -RelayToken <token> -DefaultMode Claude -Test
xpai
```

Type `mode offline` / `mode claude` to switch at the prompt. If the relay can't be reached, the assistant says so and answers from the offline notes.

How the relay is locked down:

- **The API key stays on the host.** XP only stores the relay token, in `%APPDATA%\NetSecToolkitXP`.
- **It only accepts the assistant's request format.** Every request needs the token, and the relay sets its own system prompt (XP-safe commands only, plain ASCII for the XP console), caps the reply length and limits requests to 64 KB, so it isn't an open Claude proxy.
- **It is restricted.** It refuses `0.0.0.0` unless `-AllowAnyAddress` is given, can be limited to the VM's address (`-AllowedClient`), and has a rate limit (`-MaxAsksPer10Min`, default 30).
- **Less personal data goes out.** MAC addresses, the PC name and your user name are masked before anything is sent; `-NoRedact` turns that off.
- **The XP-to-relay hop is plain HTTP.** Keep it on a host-only or NAT VM network.

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
| `NetBIOS` | NetBIOS over TCP/IP off on every network interface, including disabled or unplugged adapters | 137-139 |
| `RemoteAssistance` | Remote Assistance off (`fAllowToGetHelp = 0`) and its `sessmgr.exe` firewall exception disabled | |
| `RemoteRegistry`, `Messenger`, `Telnet` | Stopped and disabled | |
| `Guest` | Built-in Guest account disabled, found by its SID so a renamed Guest is covered | |
| `RestrictAnonymous` | `RestrictAnonymous = 1`, `RestrictAnonymousSAM = 1`: no anonymous (null session) listing of shares and accounts (applies after a reboot) | |
| `NoLMHash` | `NoLMHash = 1`: stop storing crackable LM password hashes (old ones clear at each next password change) | |
| `NTLMv2` | `LmCompatibilityLevel = 3`: send NTLMv2 only (XP default is 0) | |
| `PasswordPolicy` | `net accounts`: minimum 8 characters, lock out for 30 minutes after 10 bad tries | |
| `AutoRun` | `NoDriveTypeAutoRun = 0xFF` | |

Each step reports **Applied**, **N/A** (not installed), **Skipped** or **Failed**, and a failed step doesn't stop the rest.

To keep file sharing working, skip those steps:

```powershell
Set-XPHardening -Skip Server,SmbDevice,NetBIOS,FileAndPrint
```

### Side effects

The PC can no longer share files or printers, open other PCs' shares (`\\PC\share`), accept Remote Desktop, or host LAN games. Browsing, downloads and Windows Update are outbound, so they keep working.

- **NTLMv2 step:** connections to Windows 9x or very old NAS shares stop working. Use `-Skip NTLMv2` if you need them.
- **PasswordPolicy step:** the 8-character minimum applies at each account's next password change. Ten wrong passwords lock an account for 30 minutes; the built-in Administrator is never locked out.

### What it does not cover

- **Patches.** Use Legacy Update or the Microsoft Update Catalog. `Get-XPHardeningStatus` checks the three wormable flaws by the **file version** each fix installed, not by KB number, because later updates (including POSReady 2009 updates) supersede the original KBs:

  | Flaw | File | Fixed in | Original KB |
  |---|---|---|---|
  | MS08-067 (Conficker) | `netapi32.dll` | 5.1.2600.5694 | KB958644 |
  | MS17-010 (WannaCry) | `drivers\srv.sys` | 5.1.2600.7208 | KB4012598 |
  | CVE-2019-0708 (BlueKeep) | `drivers\termdd.sys` | 5.1.2600.7701 | KB4500331 (Update Catalog only) |
- The Administrator password and a non-admin account for daily use. `Get-AccountAuditXP` points these out but changes nothing.
- **Phishing.** Closing inbound ports doesn't stop a user from clicking a malicious link. XP's browsers are long unsupported, so keep browsing to a minimum.

## Case study: Dell Inspiron 1521

These steps were first done by hand on an XP SP3 laptop, then collected into `Set-XPHardening`.

**Before:** the firewall was on but allowed exceptions. `netsh firewall show state` listed open ports for MSMQ (135, 1801, 2103, 2105, 2107, 1026, 1027, 3527), UPnP (2869, 1900), Windows peer-to-peer networking (3540, 3587) and Teredo (3544). `netstat` also showed Simple TCP/IP Services on 7, 9, 13, 17 and 19, plus SMB on 445 and NetBIOS on 139. Only 8 updates were installed, and all three wormable-flaw patches were missing.

**After:** the firewall reported *"No ports are currently open on all network interfaces."* `netstat` listening ports went from 15+ down to RPC on 135 (which can't be closed on XP, and the firewall blocks it) and localhost-only listeners. At the time of writing, 445 was waiting on its reboot.

<!-- Add before/after photos or screenshots of netsh firewall show state and netstat here -->

## Verified on an XP VM

All real-machine testing so far has been on one VM:

| | |
|---|---|
| OS | Windows XP Professional SP3, 32-bit (5.1.2600), in VMware Workstation on Windows 11 |
| PowerShell | 2.0 (Windows Management Framework Core, KB968930) |
| Updates | Fully updated through Legacy Update, plus KB4500331 (BlueKeep) from the Update Catalog |
| Network | VMware NAT (VMnet8): VM `192.168.107.128`, gateway `192.168.107.2`, host `192.168.107.1` |
| Snapshots | "Pre-hardening - toolkit 0.2.2" and "Post-hardening" |

![Test environment: Windows XP Professional SP3 (5.1.2600), PowerShell 2.0, NetSecToolkitXP 0.2.2](docs/images/environment.png)

### Results by version

| Version | Run on the VM | Result |
|---|---|---|
| 0.2.0 | First real run | Three false "not patched" risks on a fully patched VM, so the patch check now compares file versions (fixed in 0.2.1) |
| 0.2.2 | Full hardening, from the pre-hardening snapshot | 0 risks, 0 warnings after reboot; all five commands ran without errors |
| 0.3.0 | `Invoke-XPSecurityCheck`, on the hardened VM | Ran end to end and saved its transcript, HTML report and snapshot; three false findings, fixed in 0.3.1. Also the first VM run of the 0.2.3 fixes (NetBIOS checked on every interface, Guest found by its SID) |
| 0.4.0 | `NetSecToolkitXP.exe`, double-clicked on the VM | Opened the menu (window title, version, administrator detected) and option H ran the hardening |
| 0.3.1 | Not yet on its own | Its changes are included in 0.4.0 |
| 0.5.0 | `NetSecToolkitXP.exe` 0.5.0, double-clicked on the VM | Opened the 0.5.0 menu with the new option V; the threat check itself is tested on mocks (clean, hardened, infected), VM run pending |
| 0.5.1 | `NetSecToolkitXP.exe` 0.5.1 on the VM | Menu shows version 0.5.1 and the copyright line |
| 0.5.2 | Not yet | Root certificate options T and C tested on mocks; VM run pending |

### 0.2.2: hardening run

Starting from the pre-hardening snapshot:

| | Before | After `Set-XPHardening` + reboot |
|---|---|---|
| `Get-XPHardeningStatus` | 0 risks, 12 warnings | **0 risks, 0 warnings** |
| Firewall | On, exceptions allowed, logging off | On, exceptions disabled, logging on |
| Remote Assistance | On | Off |
| Network-facing TCP ports | 135, 139, 445 | **135 only** (RPC, blocked by the firewall) |

`Set-XPHardening` reported 16 steps Applied, 2 N/A (MSMQ and Simple TCP/IP Services weren't installed on the VM) and 0 Failed. All five commands ran without errors, including the 0.2.2 fixes: the firewall audit reads logging correctly, its tables fit the console, and `Find-NetworkDeviceXP` reports the gateway's MAC.

**Before:** `Get-XPHardeningStatus` on the unhardened VM, 0 risks and 12 warnings.

![Get-XPHardeningStatus before hardening: 0 risks, 12 warnings](docs/images/status-before.png)

**Hardening:** `Set-XPHardening`, 16 steps Applied, 2 N/A, 0 Failed.

![Set-XPHardening step report](docs/images/hardening-run.png)

**After the reboot:** 0 risks, 0 warnings, only port 135 listening.

![Get-XPHardeningStatus after hardening: 0 risks, 0 warnings](docs/images/status-after.png)

### 0.3.0: first full security check

`Invoke-XPSecurityCheck` ran on the VM that 0.2.2 had already hardened. It finished without errors, saved `Check_*.txt`, `Report_*.html` and `Snapshot_*.xml` to `My Documents\SecurityChecks`, and reported **1 risk, 7 warnings, 43 findings**.

**Already in place from the 0.2.2 hardening:**

| Area | Result |
|---|---|
| Firewall | On, exceptions disabled, dropped-packet logging on |
| Services | Server, Computer Browser, UPnP Device Host, SSDP, Remote Registry, Messenger and Telnet stopped and disabled; MSMQ and Simple TCP/IP not installed |
| SMB / ports | `SMBDeviceEnabled = 0`; only 135 (RPC) listening, blocked by the firewall |
| Accounts | Guest disabled; automatic logon off; `LimitBlankPasswordUse = 1` |
| Remote Assistance, AutoRun | Remote Assistance off; AutoRun off for all drive types |
| Patches | Conficker `netapi32.dll` 5.1.2600.6260, WannaCry `srv.sys` 5.1.2600.7651 and BlueKeep `termdd.sys` 5.1.2600.7701: all patched |
| Connectivity | Gateway 0 ms, 8.8.8.8 23 ms, DNS lookup OK |
| Router | No UPnP answer |

**Real warnings (5)**, all from checks added in 0.3.0, which the 0.2.2 hardening run didn't have yet. A `Set-XPHardening` run with 0.3.0 or later covers all of them:

- `RestrictAnonymous` is 0.
- LM password hashes are still stored.
- NTLMv1 is still allowed (`LmCompatibilityLevel` below 3).
- No minimum password length.
- No account lockout.

**False findings, fixed in 0.3.1:**

| Finding | Why it was wrong | Fix |
|---|---|---|
| Risk: "Router port 21 (FTP) is open" | The gateway is VMware's NAT service (MAC `00-50-56-...`), not a real router | Virtual NAT gateways are recognized; their ports are reported as Info |
| Warn: "ASPNET is allowed a blank password" | `ASPNET` is the .NET Framework's service account, with a random password | ASPNET, IUSR_ and IWAM_ are reported as service accounts (Info) |
| Warn: NetBIOS on two adapters named only by GUID | They are removed adapters with leftover settings | Named "removed adapter {GUID}" (still a real warning, since Windows can reuse them) |
| (missing) Firewall log section | Nothing blocked was aimed at this PC, so it reported nothing | Always reports the blocked-packet count |

Also reported, as Info:

- **Accounts:** two enabled administrator accounts, and the screen saver doesn't lock the PC.
- **DEP:** set to OptIn, the XP default.
- **USB:** no USB storage devices have been connected.
- **Network:** this run saved the device list as the baseline.

### 0.4.0 to 0.5.1: `NetSecToolkitXP.exe` on XP

Double-clicked from the extracted release zip on the VM. With no execution policy change and no `Import-Module`:

- **The menu opened:** the window title shows the version, and it detected the computer, the user and administrator rights.
- **0.4.0:** option H previewed the hardening with `-WhatIf`, then applied it after `YES`.
- **0.5.0:** the menu includes the new option V (virus and threat check).
- **0.5.1:** the menu shows the version and **Copyright Edward O'Connell III 2026** under the title.

![NetSecToolkitXP.exe 0.5.1 menu on the XP VM](docs/images/exe-menu-0.5.1.png)

### Still to run on the VM

- [x] 0.4.0: double-click `NetSecToolkitXP.exe` on XP: the menu opens, and option H (hardening) ran.
- [ ] 0.4.0: after option H and a reboot, run option 1 (full check). Expected result: 0 risks, 0 warnings.
- [ ] 0.4.0: option A (assistant) from the menu.
- [ ] 0.5.0: option V (threat check), and open `Hashes_<time>.csv` on the host to try the VirusTotal links.
- [ ] 0.5.2: option T, then option C, then option T again (expected: all 79 roots installed), and an HTTPS site in Internet Explorer before and after.
- [ ] Claude mode against the live API, through `relay/Start-ClaudeRelay.ps1`.

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

![Port probe and ping from the Windows 11 host: every port False, 100% ping loss](docs/images/probe-from-host.png)

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

![pfirewall.log showing the dropped probes](docs/images/firewall-log.png)

<!-- Control test: revert to the pre-hardening snapshot and run the same probe; add the before/after results here -->

## Testing

- Parsed with the PowerShell language parser, plus a scan for PowerShell 3.0+ syntax: `[pscustomobject]`, `[ordered]`, `-in`, simplified `Where-Object`, `-Parallel`, PS3+ parameters.
- Every command exercised in PowerShell 7 against mocked WMI, COM, `netsh`, ARP and registry data, including the `-WhatIf`, `-Skip`, failed-step and already-applied paths.
- Real runs on an XP Professional SP3 VM: see [Verified on an XP VM](#verified-on-an-xp-vm) and [External verification](#external-verification). Each round of VM testing found real bugs that mocks missed: a false positive in the original KB-number patch check (fixed in 0.2.1), and a wrong logging check, a missing gateway MAC and wrapped tables (fixed in 0.2.2).
- **0.2.3 came from a code review**, and each fix was checked against mocks that reproduce the bug on 0.2.2 first. They first ran on the VM as part of 0.3.0.

  The very first real run (0.2.0) reported three wormable-flaw patches as missing on a fully patched VM. Later POSReady updates had replaced the original KBs, so the check now compares file versions instead:

  ![First real run of 0.2.0: three false-positive patch risks](docs/images/first-run-false-positives.png)
- **0.3.0** was tested the same way, against mocked data on PowerShell 7:
  - **Every new command:** account audit, firewall log, router, USB, two runs of `Invoke-XPSecurityCheck` (new device and new USB drive flagged on the second), and the assistant's offline answers and interactive prompt.
  - **Claude mode, end to end:** the XP client through `Start-ClaudeRelay.ps1` to a fake Messages API. That covered multi-turn history, masking, and the wrong-token (401), oversized (413), rate-limit (429), blocked-client (403) and relay-down paths.
  - **An independent code review** focused on PS 2.0 / .NET 2.0 compatibility, which found no runtime breakers and 15 smaller fixes, all applied.
  - **First real run (0.3.0, hardened XP VM):** finished without errors; its false findings are fixed in 0.3.1. See [0.3.0: first full security check](#030-first-full-security-check).
  - **Not yet:** Claude mode hasn't been run against the live API.
- **0.5.0 threat check**, tested on mocks with three setups:
  - **Clean but not hardened:** WannaCry and BlueKeep came out Protected; the rest were Partly or Exposed with the right fixes.
  - **Clean and hardened:** 0 risks and 0 warnings, with only the two XP limits as Info.
  - **Infected:** 8 planted signs, all caught:
    - a startup entry `photo.jpg.exe` in Temp
    - a `Userinit` hijack
    - `AppInit_DLLs`
    - an IFEO Debugger on `taskmgr.exe`
    - a service and a scheduled task in `RECYCLER`
    - a program running from Application Data
    - hosts redirects for VirusTotal and Microsoft Update
    - `autorun.inf` on a USB drive

    The real deleted file `Dc3.exe` in the Recycle Bin and XP's built-in sample IFEO key were not flagged. Not yet run on the XP VM.
- **0.4.0 launcher:**
  - **Under Wine:** run as 32-bit Windows, with a stand-in `powershell.exe` that records its command line. That confirmed the exact command and working folder, the exit code passed back, and escaping of a folder named `O'Connell Kit`.
  - **Error messages:** checked on screen for a missing module folder and for missing PowerShell 2.0.
  - **Imports:** its import table lists only functions that exist in XP's `kernel32.dll` and `user32.dll`, and its PE header targets Windows 5.1.
  - **Real PowerShell:** the same command line loads the module.
  - **Menu:** driven on mocks through every path: preview then cancel, `S` with a skip list then `YES`, an unknown step name, no report yet, the device sweep prompt, the assistant, and an invalid choice.
  - **On the XP VM:** the .exe opened the menu and option H ran. See [Results by version](#results-by-version).
- **0.5.2 root certificates**, tested on mocks against a real .NET certificate store:
  - **Install:** an empty store showed 79 missing; option C cancelled on Enter, added all 79 after `YES`, and then reported nothing to add.
  - **Re-run and undo:** a second update added 0 (79 already installed), `-WhatIf` changed nothing, and `-Remove` took all 79 back out.
  - **The full check:** it includes the new section, with KB4019276 tested both present and missing.
  - **The assistant:** it answers certificate and TLS 1.2 questions.
  - **A missing `RootCerts` folder:** reported, not crashed.
  - **The certificate files:** all parse, and the .p7b holds all 79.
- Files are pure ASCII with CRLF line endings, so PS 2.0 reads them correctly and they open cleanly in XP's Notepad.
- Recommended: test in an XP SP3 VM using **NAT or Host-only networking** (never Bridged), with a snapshot taken before running `Set-XPHardening`.

## Known limits

- Built for **32-bit XP SP3**. Remote Desktop and Remote Admin exceptions don't exist on XP Home, so those steps report Failed there. Use `-Skip RemoteDesktop,RemoteAdmin`.
- **XP x64 and Server 2003** (version 5.2) are not supported: `Set-XPHardening` refuses without `-Force`, and `Get-XPHardeningStatus` skips the wormable-flaw checks there, because their file versions (5.2.3790.x) would always look newer than the XP fixes.
- **Vista and 7 are not supported yet.** They use Windows Firewall with Advanced Security (`MpsSvc` and `netsh advfirewall`), different patch KB numbers, and a different SMB stack.
- `netsh`, `arp -a`, `net accounts` and `net localgroup` parsing expects English-language XP output.
- `Test-RouterExposureXP` checks one port at a time (PS 2.0 has no `-Parallel`), about 13 seconds worst case. A router that ignores SSDP from this PC shows UPnP as off.
- Claude mode needs a modern PC running the relay and an Anthropic API key; the offline assistant needs neither.
- `NetSecToolkitXP.exe` isn't code-signed, so downloading it on a modern PC may bring up a SmartScreen or antivirus warning. The source and build script are in `launcher/`, and `NetSecToolkitXP.cmd` is the fallback.
- The root certificate update fixes certificate errors only. Sites that require TLS 1.2 also need KB4019276, and some still fail in IE because XP lacks the newer ciphers. Firefox-based browsers and Supermium use their own certificate lists, so they don't need it.
- Firewall logging is a single setting for all profiles on XP, read from `netsh firewall show logging`.
- DHCP lease times use `System.Management`; if one shows blank, `ipconfig /all` has it.

## Roadmap

- `Set-XPHardening` run on the physical XP laptop, with results added above
- Vista / 7 support: OS detection, `advfirewall` commands, per-OS patch IDs
- 0.3.0 run on the XP VM, with screenshots of the new commands

## Changelog

- **0.5.2:**
  - **Root certificates:** `Get-RootCertStatusXP` (menu option **T**) checks the Trusted Root store and TLS 1.2 support, and `Update-XPRootCertificate` (menu option **C**) adds the 79 RSA roots from Mozilla's current CA list, shipped in `NetSecToolkitXP\RootCerts`.
  - **Where else it shows up:** the full check (option 1) includes the certificate check, and the assistant has a new topic on certificates, HTTPS errors and TLS 1.2.
- **0.5.1:** the copyright (`Copyright Edward O'Connell III 2026`) now shows in the menu, at the top of the full check, at the bottom of HTML reports, in the .exe's file properties and in the module manifest.
- **0.5.0:**
  - **Threat check:** `Get-ThreatExposureXP` rates exposure to current XP threats, and `Find-MalwareIndicatorXP` looks for signs of infection, checks the antivirus, and exports SHA-256 hashes with VirusTotal links.
  - **Where it shows up:** menu option **V**, part of `Invoke-XPSecurityCheck` (which now also saves `Hashes_<time>.csv`), and four new assistant topics (threats, malware, VirusTotal, antivirus).
- **0.4.0:**
  - **`NetSecToolkitXP.exe`:** a double-click launcher for XP that opens the new `Start-NetSecToolkitXP` menu, and can also run one command.
  - **`NetSecToolkitXP.cmd`:** a fallback that does the same.
  - **Report folder:** reports fall back to `%USERPROFILE%\My Documents` (then the temp folder) if the shell folder isn't set.
- **0.3.1** (fixes from the first real run of 0.3.0):
  - **Virtual gateways:** `Test-RouterExposureXP` recognizes a VMware, VirtualBox or Hyper-V NAT gateway by its MAC and reports its ports as Info, since they describe the VM software, not your router.
  - **Service accounts:** `ASPNET`, `IUSR_*` and `IWAM_*` are reported as Info service accounts instead of "allowed a blank password".
  - **Firewall log:** `Get-FirewallLogXP` always reports how many packets were blocked (it was silent when none were aimed at this PC).
  - **Removed adapters:** NetBIOS findings name them "removed adapter {GUID}".
- **0.3.0** (new features and the assistant):
  - **Security assistant:** `Invoke-XPAssistant` (alias `xpai`) with offline notes, finding explanations and a fix order, plus an optional Claude mode through `relay\Start-ClaudeRelay.ps1`. `Set-XPAssistantConfig` saves the relay settings.
  - **New checks:** `Get-AccountAuditXP`, `Get-FirewallLogXP`, `Test-RouterExposureXP` (ports and UPnP) and `Get-USBHistoryXP`.
  - **`Invoke-XPSecurityCheck`:** runs everything, flags new devices and USB drives since the last run, and saves a transcript, an HTML report and a snapshot.
  - **New `Set-XPHardening` steps:** `RestrictAnonymous`, `NoLMHash`, `NTLMv2` and `PasswordPolicy`. `Get-XPHardeningStatus` checks them, plus DEP.
  - **Small changes:** the step column in `Set-XPHardening` output is wider, and the status summary points to the assistant.
- **0.2.3** (code review fixes):
  - **XP x64 / Server 2003 reported as patched when they weren't.** Their 5.2.3790.x file versions always compared newer than the 32-bit XP fix versions, so an unpatched system showed all three wormable flaws as fixed. The patch check now only runs on 32-bit XP, and `Set-XPHardening` refuses other Windows versions unless `-Force` is given.
  - **NetBIOS step reported Failed when Windows said "done, reboot required"** (WMI return code 1), and it skipped adapters that were disabled or not IP-enabled, which turned NetBIOS back on when re-enabled. It now sets every NetBT interface in the registry, and `Get-XPHardeningStatus` checks every interface.
  - **A renamed Guest account was missed.** `Set-XPHardening` failed with "user name could not be found", and `Get-XPHardeningStatus` reported no Guest even while it was enabled. Both now find it by its SID (RID 501), which also works on non-English XP.
  - **Remote Assistance's firewall exception stayed enabled** after the `RemoteAssistance` step. It is now disabled in both profiles, and `Get-XPHardeningStatus` reports it.
  - `Get-XPHardeningStatus` also checks the Computer Browser service, which `Set-XPHardening` disables.
- **0.2.2:** `Set-XPHardening` also turns on firewall logging and turns off Remote Assistance. Logging is now read from `netsh` (the old registry check reported logging off when it was on). Tables fit the console window. `Find-NetworkDeviceXP` re-pings hosts whose ARP entry expired during the sweep, so the gateway's MAC is no longer blank.
- **0.2.1:** Wormable-flaw checks compare file versions instead of KB numbers, so superseding updates count.
- **0.2.0:** Added `Set-XPHardening` and `Get-XPHardeningStatus`.
- **0.1.0:** `Get-NetAdapterHealthXP`, `Get-FirewallAuditXP`, `Find-NetworkDeviceXP`.

## Disclaimer

Use this only on systems you own or are authorized to manage. Windows XP has been unsupported since 2014. Hardening reduces the network attack surface, but it doesn't make XP safe for everyday internet use. Keep XP machines off untrusted networks.

## About me

<p align="center">
  <img src="assets/footer-logo.png" alt="Edward O'Connell EO shield logo" width="180">
</p>

I'm Edward O'Connell III, an IT professional in Las Vegas focused on cybersecurity, networking and Windows systems. I build practical PowerShell security tools and test them in my own lab, including tools for legacy machines like Windows XP that people still rely on and that still need protecting.

**Qualifications**

- **Certifications:** CompTIA Security+ (2025), CompTIA A+ (2025), Cisco CCNA (2022)
- **Education:** A.A.S. in Computer & Information Technology, Cybersecurity, College of Southern Nevada (2025): 3.7 GPA, High Honors, Phi Theta Kappa
- **Now:** B.S. in Cloud Computing, Western Governors University (starting December 2026)
- **Training:** Cisco Networking Academy CCNAv7 (Introduction to Networks; Switching, Routing and Wireless Essentials; Enterprise Networking, Security and Automation) and NDG Linux I
- **Projects:** [PowerShell Network Security Toolkit](https://github.com/EdwardOconnell/powershell-network-security-toolkit) (PowerShell 7) and this XP edition

## Copyright

Copyright Edward O'Connell III 2026
