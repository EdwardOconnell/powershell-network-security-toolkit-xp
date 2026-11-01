# NetSecToolkitXP 0.4.0 - Windows XP SP3 / PowerShell 2.0 build of NetSecToolkit.
# Written for PS 2.0 only: no [pscustomobject], [ordered], -in, member
# enumeration, simplified Where-Object syntax, or Win8+ Net* cmdlets.
# Keep this file pure ASCII: PS 2.0 on XP reads BOM-less files as ANSI.

#region Shared data

$script:RiskyPorts = @{
    '21'   = 'FTP'
    '23'   = 'Telnet'
    '80'   = 'HTTP'
    '135'  = 'RPC endpoint mapper'
    '137'  = 'NetBIOS name'
    '138'  = 'NetBIOS datagram'
    '139'  = 'NetBIOS session'
    '445'  = 'SMB'
    '1900' = 'SSDP / UPnP'
    '2869' = 'UPnP'
    '3389' = 'Remote Desktop'
    '5900' = 'VNC'
}

$script:Ipv4Pattern = '^\d{1,3}(\.\d{1,3}){3}$'

$script:ToolkitVersion = '0.4.0'

# Findings from the last run of each audit command, keyed by command name.
# Invoke-XPAssistant reads these, so it can explain what was just run.
$script:LastRun = @{}

$script:LsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

#endregion

#region Private helpers

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor DarkCyan
    Write-Host (' ' + $Title) -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor DarkCyan
}

function Write-Finding {
    param(
        [ValidateSet('OK', 'Info', 'Warn', 'Risk')][string]$Level,
        [string]$Message,
        [string]$Fix
    )
    $colors = @{ 'OK' = 'Green'; 'Info' = 'Gray'; 'Warn' = 'Yellow'; 'Risk' = 'Red' }
    Write-Host ('  [{0,-4}] {1}' -f $Level, $Message) -ForegroundColor $colors[$Level]
    if ($Fix) { Write-Host ('         Fix: {0}' -f $Fix) -ForegroundColor DarkGray }
}

function New-Finding {
    param([string]$Area, [string]$Level, [string]$Message, [string]$Fix)
    Write-Finding -Level $Level -Message $Message -Fix $Fix
    New-Object PSObject -Property @{ Area = $Area; Level = $Level; Message = $Message; Fix = $Fix } |
        Select-Object Area, Level, Message, Fix
}

function Save-RunFindings {
    # Keeps the findings of an audit command for Invoke-XPAssistant.
    param([string]$Name, $Findings)
    $script:LastRun[$Name] = @($Findings | Where-Object { $_ })
}

function Get-ConsoleWidth {
    $width = 120
    try {
        $w = $Host.UI.RawUI.BufferSize.Width
        if ($w -gt 40) { $width = $w - 1 }
    } catch { }
    return $width
}

function Write-TableToHost {
    # Fits tables to the console width. With -Columns (Format-Table hashtables
    # with fixed Width), long text wraps inside its column instead of breaking
    # whole rows across lines.
    param($InputRows, [object[]]$Columns)
    if (@($InputRows).Length -eq 0) { return }
    $width = Get-ConsoleWidth
    if ($Columns) {
        $InputRows | Format-Table -Property $Columns -Wrap | Out-String -Width $width | Write-Host
    } else {
        $InputRows | Format-Table -AutoSize | Out-String -Width $width | Write-Host
    }
}

function Get-FirewallLogging {
    # Parses `netsh firewall show logging` (English XP output). XP keeps one
    # firewall log for all profiles. Returns $null if the output is unreadable.
    $info = @{}
    foreach ($line in @(& netsh.exe firewall show logging 2>&1)) {
        if ([string]$line -match '^\s*(File location|Max file size|Dropped packets|Connections)\s*=\s*(.+?)\s*$') {
            $info[$matches[1]] = $matches[2]
        }
    }
    if ($info.Count -eq 0) { return $null }
    New-Object PSObject -Property @{
        Path           = $info['File location']
        MaxSize        = $info['Max file size']
        DroppedPackets = ($info['Dropped packets'] -eq 'Enable')
        Connections    = ($info['Connections'] -eq 'Enable')
    }
}

function Limit-Level {
    # Findings on an inactive Domain profile only matter once the PC joins a
    # domain, so they are reported as Info instead of Warn/Risk.
    param([string]$Level, [bool]$Cap)
    if ($Cap -and ($Level -ne 'OK')) { return 'Info' }
    return $Level
}

function ConvertTo-IPv4Int64 {
    param([string]$Address)
    $b = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    return ([int64]$b[0] * 16777216) + ([int64]$b[1] * 65536) + ([int64]$b[2] * 256) + [int64]$b[3]
}

function ConvertFrom-IPv4Int64 {
    param([int64]$Value)
    $o1 = [int64][math]::Floor($Value / 16777216) % 256
    $o2 = [int64][math]::Floor($Value / 65536) % 256
    $o3 = [int64][math]::Floor($Value / 256) % 256
    $o4 = $Value % 256
    return ('{0}.{1}.{2}.{3}' -f $o1, $o2, $o3, $o4)
}

function Get-PrefixLength {
    param([string]$Mask)
    $bits = 0
    foreach ($byte in ([System.Net.IPAddress]::Parse($Mask)).GetAddressBytes()) {
        for ($i = 7; $i -ge 0; $i--) {
            if ($byte -band [int][math]::Pow(2, $i)) { $bits++ }
        }
    }
    return $bits
}

function Get-SubnetHostRange {
    # Returns the usable host range for Address/PrefixLength. Subnets larger
    # than /MinPrefix are capped to the /24 around Address so a sweep stays
    # reasonable on single-threaded PS 2.0.
    param([string]$Address, [int]$PrefixLength, [int]$MinPrefix = 22)
    $capped = $false
    if ($PrefixLength -lt $MinPrefix) { $PrefixLength = 24; $capped = $true }
    if ($PrefixLength -gt 30) { return $null }
    $block = [int64][math]::Pow(2, 32 - $PrefixLength)
    $ip = ConvertTo-IPv4Int64 $Address
    $network = $ip - ($ip % $block)
    New-Object PSObject -Property @{
        Network      = (ConvertFrom-IPv4Int64 $network)
        PrefixLength = $PrefixLength
        First        = $network + 1
        Last         = $network + $block - 2
        HostCount    = $block - 2
        Capped       = $capped
    }
}

function Test-LocallyAdministeredMac {
    # True when the "locally administered" bit is set, which is what
    # randomized/private MACs on phones and laptops use.
    param([string]$Mac)
    $clean = $Mac -replace '[^0-9A-Fa-f]', ''
    if ($clean.Length -ne 12) { return $false }
    $first = [Convert]::ToInt32($clean.Substring(0, 2), 16)
    return (($first -band 2) -ne 0)
}

function ConvertFrom-ArpTable {
    # Parses `arp -a` output (English XP format):
    #   Interface: 192.168.1.10 --- 0x2
    #     Internet Address      Physical Address      Type
    #     192.168.1.1           00-11-22-33-44-55     dynamic
    param([string[]]$Text)
    $iface = $null
    foreach ($line in $Text) {
        if ($line -match '^\s*Interface:\s+(\d{1,3}(?:\.\d{1,3}){3})') {
            $iface = $matches[1]
            continue
        }
        if ($line -match '^\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)') {
            New-Object PSObject -Property @{
                Interface = $iface
                IPAddress = $matches[1]
                MAC       = $matches[2].ToUpper()
                Type      = $matches[3].ToLower()
            } | Select-Object Interface, IPAddress, MAC, Type
        }
    }
}

function Test-Ping {
    # Returns round-trip ms on success, $null on failure. Uses the .NET 2.0
    # Ping class because PS 2.0 Test-Connection has no timeout parameter.
    param([string]$Address, [int]$TimeoutMs = 1000)
    try {
        $pinger = New-Object System.Net.NetworkInformation.Ping
        $reply = $pinger.Send($Address, $TimeoutMs)
        if ($reply.Status -eq 'Success') { return [int64]$reply.RoundtripTime }
    } catch { }
    return $null
}

function Test-DnsLookup {
    param([string]$Name)
    try {
        $answers = [System.Net.Dns]::GetHostAddresses($Name)
        return (@($answers).Length -gt 0)
    } catch {
        return $false
    }
}

function Get-FirstIPv4 {
    param($Values)
    foreach ($v in @($Values)) {
        if ($v -and ($v -match $script:Ipv4Pattern)) { return $v }
    }
    return $null
}

function Get-XPAdapterInfo {
    # One object per IP-enabled adapter, built from WMI (XP has no Get-NetAdapter).
    $statusNames = @{
        '0' = 'Disconnected'; '1' = 'Connecting'; '2' = 'Connected'; '3' = 'Disconnecting'
        '4' = 'Hardware not present'; '5' = 'Hardware disabled'; '6' = 'Hardware malfunction'
        '7' = 'Media disconnected'; '8' = 'Authenticating'; '9' = 'Authenticated'
        '10' = 'Authentication failed'; '11' = 'Invalid address'; '12' = 'Credentials required'
    }
    $netbiosNames = @{ '0' = 'Default (DHCP decides)'; '1' = 'Enabled'; '2' = 'Disabled' }

    $configs = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' -ErrorAction SilentlyContinue)
    foreach ($c in $configs) {
        $nic = Get-WmiObject -Class Win32_NetworkAdapter -Filter ('Index = {0}' -f $c.Index) -ErrorAction SilentlyContinue

        # IPAddress and IPSubnet are parallel arrays; take the first IPv4 pair.
        $ip = $null
        $mask = $null
        $addrs = @($c.IPAddress)
        $masks = @($c.IPSubnet)
        for ($i = 0; $i -lt $addrs.Length; $i++) {
            if ($addrs[$i] -match $script:Ipv4Pattern) {
                $ip = $addrs[$i]
                if ($masks.Length -gt $i) { $mask = $masks[$i] }
                break
            }
        }

        $prefix = $null
        if ($mask -and ($mask -match $script:Ipv4Pattern)) { $prefix = Get-PrefixLength $mask }

        $lease = $null
        if ($c.DHCPEnabled -and $c.DHCPLeaseExpires) {
            try { $lease = [System.Management.ManagementDateTimeConverter]::ToDateTime($c.DHCPLeaseExpires) } catch { }
        }

        $name = $null
        $status = 'Unknown'
        if ($nic) {
            $name = $nic.NetConnectionID
            if ($nic.NetConnectionStatus -ne $null) {
                $key = [string]$nic.NetConnectionStatus
                if ($statusNames.ContainsKey($key)) { $status = $statusNames[$key] }
            }
        }

        $netbios = 'Unknown'
        if ($c.TcpipNetbiosOptions -ne $null) {
            $nbKey = [string]$c.TcpipNetbiosOptions
            if ($netbiosNames.ContainsKey($nbKey)) { $netbios = $netbiosNames[$nbKey] }
        }

        New-Object PSObject -Property @{
            Index        = $c.Index
            Name         = $name
            Description  = $c.Description
            Status       = $status
            MAC          = $c.MACAddress
            IPv4         = $ip
            SubnetMask   = $mask
            PrefixLength = $prefix
            Gateway      = (Get-FirstIPv4 $c.DefaultIPGateway)
            DNSServers   = ((@($c.DNSServerSearchOrder) | Where-Object { $_ }) -join ', ')
            DHCPEnabled  = [bool]$c.DHCPEnabled
            DHCPServer   = $c.DHCPServer
            LeaseExpires = $lease
            NetBIOS      = $netbios
            NetBIOSCode  = $c.TcpipNetbiosOptions
        } | Select-Object Index, Name, Description, Status, MAC, IPv4, SubnetMask, PrefixLength,
                          Gateway, DNSServers, DHCPEnabled, DHCPServer, LeaseExpires, NetBIOS, NetBIOSCode
    }
}

function Get-PrimaryAdapter {
    # Prefer an adapter with an IPv4 address and a gateway.
    $all = @(Get-XPAdapterInfo | Where-Object { $_.IPv4 })
    $withGw = @($all | Where-Object { $_.Gateway })
    if ($withGw.Length -gt 0) { return $withGw[0] }
    if ($all.Length -gt 0) { return $all[0] }
    return $null
}

#endregion

#region Public commands

function Get-NetAdapterHealthXP {
<#
.SYNOPSIS
    Checks network adapters and basic connectivity on Windows XP.
.DESCRIPTION
    Reads IP-enabled adapters from WMI, flags APIPA addresses, missing
    gateway/DNS and NetBIOS over TCP/IP, then pings the gateway and 8.8.8.8
    and tests a DNS lookup.
.PARAMETER PassThru
    Also return the adapters, test results and findings as an object.
.EXAMPLE
    Get-NetAdapterHealthXP
#>
    [CmdletBinding()]
    param([switch]$PassThru)

    $findings = @()
    Write-Section 'Network adapters'

    $adapters = @(Get-XPAdapterInfo)
    if ($adapters.Length -eq 0) {
        $findings += New-Finding -Area 'Adapter' -Level 'Risk' -Message 'No IP-enabled adapters found.' -Fix 'Check Device Manager and ncpa.cpl'
    }

    foreach ($a in $adapters) {
        Write-Host ''
        Write-Host ('  {0}  ({1})' -f $a.Name, $a.Description) -ForegroundColor White
        Write-Host ('    Status : {0}' -f $a.Status)
        Write-Host ('    MAC    : {0}' -f $a.MAC)
        Write-Host ('    IPv4   : {0} / {1}' -f $a.IPv4, $a.SubnetMask)
        Write-Host ('    Gateway: {0}' -f $a.Gateway)
        Write-Host ('    DNS    : {0}' -f $a.DNSServers)
        if ($a.DHCPEnabled) {
            $dhcpLine = '    DHCP   : on'
            if ($a.DHCPServer) { $dhcpLine += ', server ' + $a.DHCPServer }
            if ($a.LeaseExpires) { $dhcpLine += ', lease expires ' + $a.LeaseExpires }
            Write-Host $dhcpLine
        } else {
            Write-Host '    DHCP   : off (static)'
        }
        Write-Host ('    NetBIOS: {0}' -f $a.NetBIOS)

        $label = $a.Name
        if (-not $label) { $label = $a.Description }

        if ($a.IPv4 -like '169.254.*') {
            $findings += New-Finding -Area 'Adapter' -Level 'Risk' -Message ("{0}: APIPA address, DHCP failed." -f $label) -Fix 'ipconfig /release then ipconfig /renew; check the router/DHCP server'
        } elseif (-not $a.IPv4) {
            $findings += New-Finding -Area 'Adapter' -Level 'Warn' -Message ("{0}: no IPv4 address." -f $label)
        }
        if ($a.IPv4 -and -not $a.Gateway) {
            $findings += New-Finding -Area 'Adapter' -Level 'Warn' -Message ("{0}: no default gateway." -f $label)
        }
        if ($a.IPv4 -and -not $a.DNSServers) {
            $findings += New-Finding -Area 'Adapter' -Level 'Warn' -Message ("{0}: no DNS servers." -f $label)
        }
        if (($a.NetBIOSCode -eq 0) -or ($a.NetBIOSCode -eq 1)) {
            $fix = '(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "Index={0}").SetTcpipNetbios(2)' -f $a.Index
            $findings += New-Finding -Area 'Adapter' -Level 'Warn' -Message ("{0}: NetBIOS over TCP/IP is {1}; it broadcasts the PC name and opens 137-139." -f $label, $a.NetBIOS.ToLower()) -Fix $fix
        }
    }

    Write-Section 'Connectivity'
    $tests = @()
    $primary = Get-PrimaryAdapter

    if ($primary -and $primary.Gateway) {
        $gwMs = Test-Ping -Address $primary.Gateway -TimeoutMs 2000
        $tests += New-Object PSObject -Property @{ Test = ('Ping gateway ' + $primary.Gateway); Passed = ($gwMs -ne $null); LatencyMs = $gwMs }
    }
    $netMs = Test-Ping -Address '8.8.8.8' -TimeoutMs 2000
    $tests += New-Object PSObject -Property @{ Test = 'Ping 8.8.8.8'; Passed = ($netMs -ne $null); LatencyMs = $netMs }
    $dnsOk = Test-DnsLookup -Name 'www.microsoft.com'
    $tests += New-Object PSObject -Property @{ Test = 'DNS lookup www.microsoft.com'; Passed = $dnsOk; LatencyMs = $null }

    foreach ($t in $tests) {
        if ($t.Passed) {
            $msg = $t.Test
            if ($t.LatencyMs -ne $null) { $msg = '{0} ({1} ms)' -f $t.Test, $t.LatencyMs }
            $findings += New-Finding -Area 'Connectivity' -Level 'OK' -Message $msg
        } else {
            $findings += New-Finding -Area 'Connectivity' -Level 'Risk' -Message ($t.Test + ' failed')
        }
    }

    Save-RunFindings -Name 'Get-NetAdapterHealthXP' -Findings $findings
    if ($PassThru) {
        New-Object PSObject -Property @{
            Adapters = $adapters
            Tests    = ($tests | Select-Object Test, Passed, LatencyMs)
            Findings = $findings
        }
    }
}

function Get-FirewallAuditXP {
<#
.SYNOPSIS
    Audits Windows Firewall (XP SP2/SP3) through its COM API.
.DESCRIPTION
    Checks the SharedAccess service, both firewall profiles, service
    exceptions (File and Printer Sharing, UPnP, Remote Desktop), Remote
    Administration, ICMP, program exceptions, open ports and logging.
    Read-only: it prints netsh commands as fixes but changes nothing.
.PARAMETER ExportPath
    Optional CSV path for the exception list.
.PARAMETER PassThru
    Also return the exceptions and findings as an object.
.EXAMPLE
    Get-FirewallAuditXP -ExportPath C:\fw-exceptions.csv
#>
    [CmdletBinding()]
    param([string]$ExportPath, [switch]$PassThru)

    $findings = @()
    $exceptions = @()
    $scopeNames = @{ '0' = 'Any'; '1' = 'Local subnet'; '2' = 'Custom' }
    $protoNames = @{ '6' = 'TCP'; '17' = 'UDP' }

    Write-Section 'Firewall service'
    $svc = Get-Service -Name SharedAccess -ErrorAction SilentlyContinue
    if (-not $svc) {
        $findings += New-Finding -Area 'Service' -Level 'Risk' -Message 'Windows Firewall/ICS service (SharedAccess) not found. Is SP2 or later installed?'
    } elseif ($svc.Status -ne 'Running') {
        $findings += New-Finding -Area 'Service' -Level 'Risk' -Message ('SharedAccess service is ' + $svc.Status + '.') -Fix 'Set-Service SharedAccess -StartupType Automatic; Start-Service SharedAccess'
    } else {
        $findings += New-Finding -Area 'Service' -Level 'OK' -Message 'SharedAccess service is running.'
    }

    try {
        $mgr = New-Object -ComObject HNetCfg.FwMgr
        $policy = $mgr.LocalPolicy
    } catch {
        $findings += New-Finding -Area 'Service' -Level 'Risk' -Message ('Could not read firewall policy: ' + $_.Exception.Message)
        if ($PassThru) { New-Object PSObject -Property @{ Exceptions = @(); Findings = $findings } }
        return
    }

    $currentType = $mgr.CurrentProfileType
    $profiles = @(
        @{ Type = 0; Name = 'Domain';   RegKey = 'DomainProfile' },
        @{ Type = 1; Name = 'Standard'; RegKey = 'StandardProfile' }
    )

    foreach ($p in $profiles) {
        try { $prof = $policy.GetProfileByType($p.Type) } catch { continue }
        $pname = $p.Name
        if ($p.Type -eq $currentType) { $pname = $p.Name + ' (active)' }
        Write-Section ('Profile: ' + $pname)
        $inactiveDomain = (($p.Type -eq 0) -and ($currentType -ne 0))
        if ($inactiveDomain) {
            Write-Host '  Not active: these settings apply only when the PC is on a domain network.' -ForegroundColor DarkGray
        }

        if ($prof.FirewallEnabled) {
            $findings += New-Finding -Area $p.Name -Level (Limit-Level 'OK' $inactiveDomain) -Message 'Firewall is on.'
        } else {
            $level = 'Warn'
            if ($p.Type -eq $currentType) { $level = 'Risk' }
            $findings += New-Finding -Area $p.Name -Level (Limit-Level $level $inactiveDomain) -Message 'Firewall is OFF.' -Fix ('netsh firewall set opmode mode=ENABLE profile=' + $p.Name.ToUpper())
        }
        if ($prof.ExceptionsNotAllowed) {
            $findings += New-Finding -Area $p.Name -Level (Limit-Level 'OK' $inactiveDomain) -Message '"Don''t allow exceptions" is on; all exceptions below are ignored.'
        }

        # Built-in service exceptions
        foreach ($s in $prof.Services) {
            $scope = $scopeNames[[string]$s.Scope]
            $exceptions += New-Object PSObject -Property @{
                Profile = $p.Name; Kind = 'Service'; Name = $s.Name; Detail = ''; Enabled = [bool]$s.Enabled; Scope = $scope
            }
            if ($s.Enabled) {
                $level = 'Warn'
                if (($s.Type -ne 1) -and ($s.Scope -eq 0)) { $level = 'Risk' }
                $typeArg = @{ '0' = 'FILEANDPRINT'; '1' = 'UPNP'; '2' = 'REMOTEDESKTOP' }[[string]$s.Type]
                $fix = $null
                if ($typeArg) { $fix = 'netsh firewall set service type={0} mode=DISABLE profile={1}' -f $typeArg, $p.Name.ToUpper() }
                $findings += New-Finding -Area $p.Name -Level (Limit-Level $level $inactiveDomain) -Message ('{0} exception is enabled (scope: {1}).' -f $s.Name, $scope) -Fix $fix
            }
        }

        try {
            if ($prof.RemoteAdminSettings.Enabled) {
                $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Risk' $inactiveDomain) -Message 'Remote Administration exception is enabled (opens RPC/DCOM, 135 and 445).' -Fix ('netsh firewall set service type=REMOTEADMIN mode=DISABLE profile=' + $p.Name.ToUpper())
            }
        } catch { }

        try {
            if ($prof.IcmpSettings.AllowInboundEchoRequest) {
                $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Info' $inactiveDomain) -Message 'Inbound ping (ICMP echo) is allowed.'
            }
        } catch { }

        # Program exceptions
        foreach ($app in $prof.AuthorizedApplications) {
            $scope = $scopeNames[[string]$app.Scope]
            $exceptions += New-Object PSObject -Property @{
                Profile = $p.Name; Kind = 'Program'; Name = $app.Name; Detail = $app.ProcessImageFileName; Enabled = [bool]$app.Enabled; Scope = $scope
            }
            if ($app.Enabled) {
                $exe = [Environment]::ExpandEnvironmentVariables([string]$app.ProcessImageFileName)
                if ($exe -and -not (Test-Path -LiteralPath $exe)) {
                    $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Warn' $inactiveDomain) -Message ('Program exception "{0}" points to a file that no longer exists.' -f $app.Name) -Fix ('netsh firewall delete allowedprogram program="{0}" profile={1}' -f $exe, $p.Name.ToUpper())
                } elseif ($app.Scope -eq 0) {
                    $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Info' $inactiveDomain) -Message ('Program exception "{0}" accepts connections from any address.' -f $app.Name)
                }
            }
        }

        # Port exceptions
        foreach ($port in $prof.GloballyOpenPorts) {
            $scope = $scopeNames[[string]$port.Scope]
            $proto = $protoNames[[string]$port.Protocol]
            if (-not $proto) { $proto = [string]$port.Protocol }
            $exceptions += New-Object PSObject -Property @{
                Profile = $p.Name; Kind = 'Port'; Name = $port.Name; Detail = ('{0}/{1}' -f $proto, $port.Port); Enabled = [bool]$port.Enabled; Scope = $scope
            }
            if ($port.Enabled) {
                $fix = 'netsh firewall delete portopening protocol={0} port={1} profile={2}' -f $proto, $port.Port, $p.Name.ToUpper()
                $key = [string]$port.Port
                if ($script:RiskyPorts.ContainsKey($key)) {
                    $level = 'Warn'
                    if ($port.Scope -eq 0) { $level = 'Risk' }
                    $findings += New-Finding -Area $p.Name -Level (Limit-Level $level $inactiveDomain) -Message ('Open port {0}/{1} ({2}), scope: {3}.' -f $proto, $port.Port, $script:RiskyPorts[$key], $scope) -Fix $fix
                } else {
                    $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Warn' $inactiveDomain) -Message ('Open port {0}/{1} "{2}", scope: {3}. Confirm you still need it.' -f $proto, $port.Port, $port.Name, $scope) -Fix $fix
                }
            }
        }
    }

    Write-Section 'Logging (all profiles)'
    $fwLog = Get-FirewallLogging
    if (-not $fwLog) {
        $findings += New-Finding -Area 'Logging' -Level 'Info' -Message 'Could not read netsh firewall show logging.'
    } elseif ($fwLog.DroppedPackets) {
        $findings += New-Finding -Area 'Logging' -Level 'OK' -Message ('Dropped-packet logging is on ({0}, max {1}).' -f $fwLog.Path, $fwLog.MaxSize)
        if (-not $fwLog.Connections) {
            $findings += New-Finding -Area 'Logging' -Level 'Info' -Message 'Successful-connection logging is off.'
        }
    } else {
        $findings += New-Finding -Area 'Logging' -Level 'Warn' -Message 'Dropped-packet logging is off.' -Fix 'netsh firewall set logging droppedpackets=ENABLE connections=ENABLE'
    }

    $exceptions = @($exceptions | Select-Object Profile, Kind, Name, Detail, Enabled, Scope)
    Write-Section 'Exception list'
    if ($exceptions.Length -eq 0) {
        Write-Host '  (none)'
    } else {
        $cols = @(
            @{ Label = 'Profile'; Expression = { $_.Profile }; Width = 8 },
            @{ Label = 'Kind';    Expression = { $_.Kind };    Width = 7 },
            @{ Label = 'Enabled'; Expression = { $_.Enabled }; Width = 7 },
            @{ Label = 'Scope';   Expression = { $_.Scope };   Width = 12 },
            @{ Label = 'Name';    Expression = { $_.Name };    Width = 36 },
            @{ Label = 'Detail';  Expression = { $_.Detail } }
        )
        Write-TableToHost -InputRows $exceptions -Columns $cols
    }

    if ($ExportPath) {
        $exceptions | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host ('  Exceptions exported to ' + $ExportPath) -ForegroundColor DarkGray
    }

    Save-RunFindings -Name 'Get-FirewallAuditXP' -Findings $findings
    if ($PassThru) {
        New-Object PSObject -Property @{ Exceptions = $exceptions; Findings = $findings }
    }
}

function Find-NetworkDeviceXP {
<#
.SYNOPSIS
    Finds devices on the local subnet with a ping sweep plus the ARP cache.
.DESCRIPTION
    Pings every host on the primary adapter's subnet (one at a time, since
    PS 2.0 has no -Parallel), then reads `arp -a`. Devices that block ping
    still show up if they answered ARP. Subnets larger than /22 are capped
    to the local /24.
.PARAMETER TimeoutMs
    Ping timeout per host. 200 ms sweeps a /24 in under a minute.
.PARAMETER NoSweep
    Skip the ping sweep and only read the current ARP cache.
.PARAMETER ResolveNames
    Look up hostnames (DNS, then NetBIOS). Can add several seconds per device.
.PARAMETER ExportPath
    Optional CSV path for the device list.
.PARAMETER PassThru
    Also return the device list.
.EXAMPLE
    Find-NetworkDeviceXP -ResolveNames -ExportPath C:\devices.csv
#>
    [CmdletBinding()]
    param(
        [ValidateRange(50, 5000)][int]$TimeoutMs = 200,
        [switch]$NoSweep,
        [switch]$ResolveNames,
        [string]$ExportPath,
        [switch]$PassThru
    )

    Write-Section 'Device discovery'
    $primary = Get-PrimaryAdapter
    if (-not $primary -or -not $primary.PrefixLength) {
        Write-Finding -Level 'Risk' -Message 'No adapter with an IPv4 address and subnet mask found.'
        return
    }

    $range = Get-SubnetHostRange -Address $primary.IPv4 -PrefixLength $primary.PrefixLength
    if (-not $range) {
        Write-Finding -Level 'Warn' -Message ('Subnet /{0} is too small to sweep.' -f $primary.PrefixLength)
        return
    }
    Write-Host ('  Adapter : {0} ({1})' -f $primary.Name, $primary.IPv4)
    Write-Host ('  Subnet  : {0}/{1}, {2} hosts' -f $range.Network, $range.PrefixLength, $range.HostCount)
    if ($range.Capped) {
        Write-Finding -Level 'Info' -Message ('Subnet is /{0}; scanning only the local /24.' -f $primary.PrefixLength)
    }

    $responders = @{}
    if (-not $NoSweep) {
        $seconds = [math]::Ceiling($range.HostCount * $TimeoutMs / 1000)
        Write-Host ('  Sweeping (worst case about {0} s)...' -f $seconds)
        $done = 0
        for ($n = $range.First; $n -le $range.Last; $n++) {
            $target = ConvertFrom-IPv4Int64 $n
            $done++
            if (($done % 8) -eq 0) {
                $pct = [int](($done / $range.HostCount) * 100)
                Write-Progress -Activity 'Ping sweep' -Status $target -PercentComplete $pct
            }
            if ($target -eq $primary.IPv4) { continue }
            $ms = Test-Ping -Address $target -TimeoutMs $TimeoutMs
            if ($ms -ne $null) { $responders[$target] = $ms }
        }
        Write-Progress -Activity 'Ping sweep' -Completed -Status 'Done'
    }

    # Merge ARP cache entries for this interface and subnet
    $first = $range.First
    $last = $range.Last
    $arp = @(ConvertFrom-ArpTable -Text (arp -a) | Where-Object {
        ($_.Interface -eq $primary.IPv4) -and
        ($_.MAC -ne 'FF-FF-FF-FF-FF-FF') -and
        ($_.MAC -ne '00-00-00-00-00-00') -and
        ($_.MAC -notlike '01-00-5E-*')
    } | Where-Object {
        $v = ConvertTo-IPv4Int64 $_.IPAddress
        ($v -ge $first) -and ($v -le $last)
    })

    $byIp = @{}
    foreach ($entry in $arp) { $byIp[$entry.IPAddress] = $entry.MAC }

    # XP can age ARP entries out within a minute, so hosts pinged early in the
    # sweep may be gone from the cache by the end. Ping those again and re-read.
    $missing = @($responders.Keys | Where-Object { -not $byIp.ContainsKey($_) })
    if ($missing.Length -gt 0) {
        foreach ($ip in $missing) { $null = Test-Ping -Address $ip -TimeoutMs 1000 }
        foreach ($entry in @(ConvertFrom-ArpTable -Text (arp -a))) {
            if (($entry.Interface -eq $primary.IPv4) -and ($missing -contains $entry.IPAddress)) {
                $byIp[$entry.IPAddress] = $entry.MAC
            }
        }
    }
    foreach ($ip in $responders.Keys) { if (-not $byIp.ContainsKey($ip)) { $byIp[$ip] = '' } }

    $selfMac = ''
    if ($primary.MAC) { $selfMac = ($primary.MAC -replace ':', '-').ToUpper() }
    $byIp[$primary.IPv4] = $selfMac

    $devices = @()
    foreach ($ip in $byIp.Keys) {
        $role = ''
        if ($ip -eq $primary.IPv4) { $role = 'This PC' }
        elseif ($ip -eq $primary.Gateway) { $role = 'Gateway' }

        $latency = $null
        $answered = $false
        if ($responders.ContainsKey($ip)) { $answered = $true; $latency = $responders[$ip] }
        if ($ip -eq $primary.IPv4) { $answered = $true }

        $hostName = ''
        if ($ResolveNames) {
            try { $hostName = ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { }
            if ($hostName -eq $ip) { $hostName = '' }
        }

        $mac = $byIp[$ip]
        $devices += New-Object PSObject -Property @{
            IPAddress   = $ip
            MAC         = $mac
            Role        = $role
            AnsweredPing = $answered
            LatencyMs   = $latency
            RandomMAC   = ($mac -and (Test-LocallyAdministeredMac $mac))
            HostName    = $hostName
            SortKey     = (ConvertTo-IPv4Int64 $ip)
        }
    }

    $devices = @($devices | Sort-Object SortKey |
        Select-Object IPAddress, MAC, Role, AnsweredPing, LatencyMs, RandomMAC, HostName)

    Write-TableToHost $devices

    $quiet = @($devices | Where-Object { -not $_.AnsweredPing })
    $random = @($devices | Where-Object { $_.RandomMAC })
    Write-Finding -Level 'Info' -Message ('{0} device(s) found.' -f $devices.Length)
    if ((-not $NoSweep) -and ($quiet.Length -gt 0)) {
        Write-Finding -Level 'Info' -Message ('{0} device(s) answered ARP but blocked ping (firewalled hosts).' -f $quiet.Length)
    }
    if ($random.Length -gt 0) {
        Write-Finding -Level 'Info' -Message ('{0} device(s) use a randomized MAC (usually phones/laptops with private Wi-Fi addresses).' -f $random.Length)
    }

    if ($ExportPath) {
        $devices | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host ('  Devices exported to ' + $ExportPath) -ForegroundColor DarkGray
    }

    if ($PassThru) { $devices }
}

#endregion

#region Hardening

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $id
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-NetshFirewall {
    # Runs `netsh firewall <args>` and throws unless netsh answers "Ok."
    param([string[]]$Arguments)
    $out = & netsh.exe firewall $Arguments 2>&1
    $text = (($out | Out-String) -replace '\s+', ' ').Trim()
    if ($text -notmatch '^Ok\.?$') {
        throw ('netsh firewall {0}: {1}' -f ($Arguments -join ' '), $text)
    }
}

function Disable-XPService {
    # Sets each service to Disabled first (so nothing restarts it), then stops it.
    param([string[]]$Name)
    $done = @()
    foreach ($n in $Name) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $svc) {
            $done += ($n + ': not installed')
            continue
        }
        Set-Service -Name $n -StartupType Disabled -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $n -Force -ErrorAction Stop }
        $done += ($n + ': stopped, disabled')
    }
    return ($done -join '; ')
}

function Set-RegistryDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path -Path $Path)) { New-Item -Path $Path | Out-Null }
    $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
    } else {
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value | Out-Null
    }
}

function Get-NetbtInterface {
    # One object per NetBT interface key (Tcpip_{GUID}), named from WMI where
    # the adapter still exists. Covers disabled and unplugged adapters too,
    # which Win32_NetworkAdapterConfiguration's IPEnabled filter leaves out.
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $names = @{}
    foreach ($c in @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue)) {
        if ($c.SettingID) { $names[[string]$c.SettingID.ToUpper()] = $c.Description }
    }
    foreach ($k in @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
        $leaf = [string]$k.PSChildName
        if ($leaf -notlike 'Tcpip_*') { continue }
        $guid = $leaf.Substring(6).ToUpper()
        $desc = $names[$guid]
        if (-not $desc) { $desc = 'removed adapter ' + $guid }
        $opt = (Get-ItemProperty -Path ($root + '\' + $leaf) -ErrorAction SilentlyContinue).NetbiosOptions
        New-Object PSObject -Property @{ Path = ($root + '\' + $leaf); Description = $desc; NetbiosOptions = $opt }
    }
}

function Get-GuestAccount {
    # The built-in Guest account, found by its well-known RID (500 + 1) rather
    # than by name, so it is found even when renamed or on non-English XP.
    @(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount = TRUE' -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.SID -like 'S-1-5-21-*-501' }) | Select-Object -First 1
}

function Get-OSVersionInfo {
    # Wrapped so the tests can stand in for XP.
    return [Environment]::OSVersion.Version
}

function Test-IsXP32 {
    # 32-bit Windows XP reports 5.1. XP x64 and Server 2003 report 5.2.
    $v = Get-OSVersionInfo
    return (($v.Major -eq 5) -and ($v.Minor -eq 1))
}

function Set-RemoteAssistanceException {
    # Disables the Remote Assistance (sessmgr.exe) program exception in the
    # Domain and Standard firewall profiles. Returns how many were changed.
    $mgr = New-Object -ComObject HNetCfg.FwMgr
    $changed = 0
    foreach ($type in 0, 1) {
        try { $prof = $mgr.LocalPolicy.GetProfileByType($type) } catch { continue }
        foreach ($app in $prof.AuthorizedApplications) {
            if (([string]$app.ProcessImageFileName -like '*\sessmgr.exe') -and $app.Enabled) {
                $app.Enabled = $false
                $changed++
            }
        }
    }
    return $changed
}

function Get-FileVersionObject {
    # Returns a [Version] built from a file's numeric version fields, or $null.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    if (-not $vi) { return $null }
    return (New-Object System.Version -ArgumentList $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart)
}

function Set-XPHardening {
<#
.SYNOPSIS
    Applies the XP hardening baseline in one run.
.DESCRIPTION
    Turns on Windows Firewall with no exceptions and logging, closes the File
    and Printer Sharing / Remote Desktop / Remote Admin / UPnP exceptions,
    turns off Remote Assistance, disables
    MSMQ, UPnP, Simple TCP/IP Services, the Server service, Remote Registry,
    Messenger and Telnet, turns off SMB over port 445 and NetBIOS over
    TCP/IP, disables the Guest account, blocks anonymous (null session)
    enumeration, stops storing LM password hashes, sends NTLMv2 only, sets a
    password policy (8+ characters, lockout after 10 bad tries) and turns
    off AutoRun.
    Each step reports Applied, N/A (not installed), Skipped or Failed.
    Run with -WhatIf first to see what it will do.
.PARAMETER Skip
    Step names to leave alone, e.g. -Skip Server,SmbDevice,NetBIOS,FileAndPrint
    to keep file sharing working. Skip NTLMv2 if this PC must connect to
    Windows 9x or very old NAS shares.
.PARAMETER Force
    Apply even when the system is not 32-bit Windows XP (5.1). The steps are
    only tested on XP SP3; on XP x64 or Server 2003 use at your own risk.
.PARAMETER PassThru
    Also return the step results as objects.
.EXAMPLE
    Set-XPHardening -WhatIf
.EXAMPLE
    Set-XPHardening
.EXAMPLE
    Set-XPHardening -Skip RemoteDesktop
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Firewall', 'Logging', 'FileAndPrint', 'RemoteDesktop', 'RemoteAdmin', 'UPnPException', 'RemoteAssistance',
                     'MSMQ', 'UPnP', 'SimpleTcp', 'Server', 'SmbDevice', 'NetBIOS',
                     'RemoteRegistry', 'Messenger', 'Telnet', 'Guest', 'RestrictAnonymous', 'NoLMHash',
                     'NTLMv2', 'PasswordPolicy', 'AutoRun')]
        [string[]]$Skip = @(),
        [switch]$Force,
        [switch]$PassThru
    )

    if ((-not $WhatIfPreference) -and (-not $Force) -and (-not (Test-IsXP32))) {
        throw ('Set-XPHardening is built and tested for 32-bit Windows XP SP3 (version 5.1). This system reports {0}. Use -WhatIf to preview, or -Force to apply anyway.' -f (Get-OSVersionInfo))
    }
    if ((-not $WhatIfPreference) -and (-not (Test-IsAdmin))) {
        throw 'Set-XPHardening must run in an Administrator PowerShell window.'
    }

    $steps = @(
        @{ Name = 'Firewall'; Reboot = $false
           Action = 'Turn on Windows Firewall with exceptions disabled (all profiles)'
           Run = { Invoke-NetshFirewall @('set', 'opmode', 'mode=ENABLE', 'exceptions=DISABLE', 'profile=ALL'); 'On, no exceptions' } },
        @{ Name = 'Logging'; Reboot = $false
           Action = 'Log dropped packets and successful connections to pfirewall.log'
           Run = { Invoke-NetshFirewall @('set', 'logging', 'droppedpackets=ENABLE', 'connections=ENABLE'); 'Logging to pfirewall.log' } },
        @{ Name = 'FileAndPrint'; Reboot = $false
           Action = 'Close the File and Printer Sharing firewall exception'
           Run = { Invoke-NetshFirewall @('set', 'service', 'type=FILEANDPRINT', 'mode=DISABLE', 'profile=ALL'); 'Exception closed' } },
        @{ Name = 'RemoteDesktop'; Reboot = $false
           Action = 'Close the Remote Desktop firewall exception'
           Run = { Invoke-NetshFirewall @('set', 'service', 'type=REMOTEDESKTOP', 'mode=DISABLE', 'profile=ALL'); 'Exception closed' } },
        @{ Name = 'RemoteAdmin'; Reboot = $false
           Action = 'Close the Remote Administration firewall exception'
           Run = { Invoke-NetshFirewall @('set', 'service', 'type=REMOTEADMIN', 'mode=DISABLE', 'profile=ALL'); 'Exception closed' } },
        @{ Name = 'UPnPException'; Reboot = $false
           Action = 'Close the UPnP Framework firewall exception'
           Run = { Invoke-NetshFirewall @('set', 'service', 'type=UPNP', 'mode=DISABLE', 'profile=ALL'); 'Exception closed' } },
        @{ Name = 'RemoteAssistance'; Reboot = $false
           Action = 'Turn off Remote Assistance (fAllowToGetHelp = 0) and its sessmgr.exe firewall exception'
           Run = {
               Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fAllowToGetHelp' -Value 0
               $n = Set-RemoteAssistanceException
               'Remote Assistance off, {0} firewall exception(s) disabled' -f $n
           } },
        @{ Name = 'MSMQ'; Reboot = $false
           Action = 'Stop and disable Message Queuing (ports 1801, 2103-2107, 3527)'
           Run = { Disable-XPService @('MSMQ') } },
        @{ Name = 'UPnP'; Reboot = $false
           Action = 'Stop and disable UPnP Device Host and SSDP Discovery (2869, 1900)'
           Run = { Disable-XPService @('upnphost', 'SSDPSRV') } },
        @{ Name = 'SimpleTcp'; Reboot = $false
           Action = 'Stop and disable Simple TCP/IP Services (7, 9, 13, 17, 19)'
           Run = { Disable-XPService @('SimpTcp') } },
        @{ Name = 'Server'; Reboot = $false
           Action = 'Stop and disable the Server and Computer Browser services (file sharing)'
           Run = { Disable-XPService @('Browser', 'lanmanserver') } },
        @{ Name = 'SmbDevice'; Reboot = $true
           Action = 'Turn off SMB over TCP port 445 (SMBDeviceEnabled = 0, needs reboot)'
           Run = { Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'SMBDeviceEnabled' -Value 0; 'Set to 0, reboot to apply' } },
        @{ Name = 'NetBIOS'; Reboot = $false
           Action = 'Turn off NetBIOS over TCP/IP on every network interface, including disabled ones (137-139)'
           Run = {
               # 1. Registry: every NetBT interface, so adapters that are
               #    disabled or unplugged right now stay off when they come back.
               $ifaces = @(Get-NetbtInterface)
               foreach ($i in $ifaces) { Set-RegistryDword -Path $i.Path -Name 'NetbiosOptions' -Value 2 }
               # 2. WMI: IP-enabled adapters, so the change applies right away.
               #    ReturnValue 0 = done, 1 = done but needs a reboot.
               $bad = @()
               $live = 0
               $rebootNeeded = $false
               foreach ($c in @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE')) {
                   $r = $c.SetTcpipNetbios(2)
                   if ($r.ReturnValue -eq 0) { $live++ }
                   elseif ($r.ReturnValue -eq 1) { $live++; $rebootNeeded = $true }
                   else { $bad += ('{0} (code {1})' -f $c.Description, $r.ReturnValue) }
               }
               if ($bad.Length -gt 0) { throw ('Failed on: ' + ($bad -join '; ')) }
               $msg = '{0} interface(s) set, {1} active adapter(s) applied now' -f $ifaces.Length, $live
               if ($rebootNeeded) { $msg += ' (reboot required)' }
               $msg
           } },
        @{ Name = 'RemoteRegistry'; Reboot = $false
           Action = 'Stop and disable Remote Registry'
           Run = { Disable-XPService @('RemoteRegistry') } },
        @{ Name = 'Messenger'; Reboot = $false
           Action = 'Stop and disable the Messenger service'
           Run = { Disable-XPService @('Messenger') } },
        @{ Name = 'Telnet'; Reboot = $false
           Action = 'Stop and disable the Telnet server'
           Run = { Disable-XPService @('TlntSvr') } },
        @{ Name = 'Guest'; Reboot = $false
           Action = 'Disable the built-in Guest account (found by SID, so a renamed Guest is covered)'
           Run = {
               $g = Get-GuestAccount
               if (-not $g) { 'Guest: not installed' }
               else {
                   $out = & net.exe user $g.Name /active:no 2>&1
                   if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }
                   'Guest account "{0}" disabled' -f $g.Name
               }
           } },
        @{ Name = 'RestrictAnonymous'; Reboot = $true
           Action = 'Block anonymous (null session) listing of accounts and shares (RestrictAnonymous = 1, RestrictAnonymousSAM = 1)'
           Run = {
               Set-RegistryDword -Path $script:LsaPath -Name 'RestrictAnonymous' -Value 1
               Set-RegistryDword -Path $script:LsaPath -Name 'RestrictAnonymousSAM' -Value 1
               'Set, reboot to apply'
           } },
        @{ Name = 'NoLMHash'; Reboot = $false
           Action = 'Stop storing weak LM password hashes (NoLMHash = 1)'
           Run = { Set-RegistryDword -Path $script:LsaPath -Name 'NoLMHash' -Value 1; 'Set; old LM hashes clear at each account''s next password change' } },
        @{ Name = 'NTLMv2'; Reboot = $false
           Action = 'Send NTLMv2 responses only (LmCompatibilityLevel = 3)'
           Run = { Set-RegistryDword -Path $script:LsaPath -Name 'LmCompatibilityLevel' -Value 3; 'Set to 3' } },
        @{ Name = 'PasswordPolicy'; Reboot = $false
           Action = 'Password policy: 8+ characters, lock out for 30 minutes after 10 bad tries (net accounts)'
           Run = {
               $out = & net.exe accounts /minpwlen:8 2>&1
               if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }
               $out = & net.exe accounts /lockoutthreshold:10 /lockoutwindow:30 /lockoutduration:30 2>&1
               if ($LASTEXITCODE -ne 0) { throw ('Min length 8 set, lockout not set: ' + ($out | Out-String).Trim()) }
               'Min length 8, lockout 10 tries / 30 min (new length applies at next password change)'
           } },
        @{ Name = 'AutoRun'; Reboot = $false
           Action = 'Turn off AutoRun on all drive types (NoDriveTypeAutoRun = 0xFF)'
           Run = { Set-RegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255; 'Set to 0xFF' } }
    )

    Write-Section 'Set-XPHardening'
    $colors = @{ 'Applied' = 'Green'; 'N/A' = 'Gray'; 'Skipped' = 'Gray'; 'Failed' = 'Red'; 'WhatIf' = 'Cyan'; 'Declined' = 'Yellow' }
    $results = @()
    $needReboot = $false

    foreach ($s in $steps) {
        $status = ''
        $detail = ''
        if ($Skip -contains $s.Name) {
            $status = 'Skipped'
            $detail = 'Left alone (-Skip)'
        } elseif ($PSCmdlet.ShouldProcess($s.Action)) {
            try {
                $detail = [string](& $s.Run)
                $status = 'Applied'
                if (($detail -match 'not installed') -and ($detail -notmatch 'disabled')) { $status = 'N/A' }
                if ($s.Reboot) { $needReboot = $true }
            } catch {
                $status = 'Failed'
                $detail = $_.Exception.Message
            }
        } else {
            if ($WhatIfPreference) { $status = 'WhatIf' } else { $status = 'Declined' }
            $detail = $s.Action
        }
        Write-Host ('  [{0,-8}] {1,-17} {2}' -f $status, $s.Name, $detail) -ForegroundColor $colors[$status]
        $results += New-Object PSObject -Property @{ Step = $s.Name; Status = $status; Detail = $detail }
    }

    $failed = @($results | Where-Object { $_.Status -eq 'Failed' })
    Write-Host ''
    if ($failed.Length -gt 0) {
        Write-Host ('  {0} step(s) failed. Fix the cause or re-run with -Skip for those steps.' -f $failed.Length) -ForegroundColor Yellow
    }
    if ($needReboot) {
        Write-Host '  Reboot to finish (port 445 and anonymous-access changes apply after restart), then run Get-XPHardeningStatus.' -ForegroundColor Yellow
    } elseif (-not $WhatIfPreference) {
        Write-Host '  Run Get-XPHardeningStatus to verify.' -ForegroundColor DarkGray
    }
    if (-not $WhatIfPreference) {
        # Earlier status/account findings no longer describe this PC.
        $script:LastRun.Remove('Get-XPHardeningStatus')
        $script:LastRun.Remove('Get-AccountAuditXP')
    }

    if ($PassThru) { $results | Select-Object Step, Status, Detail }
}

function Get-XPHardeningStatus {
<#
.SYNOPSIS
    Read-only check of the XP hardening baseline.
.DESCRIPTION
    Checks the firewall, the services Set-XPHardening disables, SMB/NetBIOS,
    the Guest account, AutoRun, anonymous access, LM hashes, NTLMv2, the
    password and lockout policy, DEP, the three wormable-flaw fixes (by the file
    version each fix installed, so superseding updates count) and which
    TCP ports are listening on the network. Changes nothing.
.PARAMETER PassThru
    Also return the findings as objects.
.EXAMPLE
    Get-XPHardeningStatus
#>
    [CmdletBinding()]
    param([switch]$PassThru)

    $findings = @()
    $fixCmd = 'Set-XPHardening'

    Write-Section 'Firewall'
    $noExceptions = $false
    $raException = $false
    try {
        $mgr = New-Object -ComObject HNetCfg.FwMgr
        $prof = $mgr.LocalPolicy.CurrentProfile
        if ($prof.FirewallEnabled) {
            $findings += New-Finding -Area 'Firewall' -Level 'OK' -Message 'Firewall is on.'
        } else {
            $findings += New-Finding -Area 'Firewall' -Level 'Risk' -Message 'Firewall is OFF.' -Fix $fixCmd
        }
        $noExceptions = [bool]$prof.ExceptionsNotAllowed
        if ($noExceptions) {
            $findings += New-Finding -Area 'Firewall' -Level 'OK' -Message 'Exceptions are disabled.'
        } else {
            $findings += New-Finding -Area 'Firewall' -Level 'Warn' -Message 'Exceptions are allowed.' -Fix $fixCmd
        }
        foreach ($s in $prof.Services) {
            if ($s.Enabled) {
                $level = 'Warn'
                $note = ''
                if ($noExceptions) { $level = 'Info'; $note = ' (ignored while exceptions are disabled)' }
                $findings += New-Finding -Area 'Firewall' -Level $level -Message ('{0} exception is enabled{1}.' -f $s.Name, $note) -Fix $fixCmd
            }
        }
        try {
            if ($prof.RemoteAdminSettings.Enabled) {
                $findings += New-Finding -Area 'Firewall' -Level 'Warn' -Message 'Remote Administration exception is enabled.' -Fix $fixCmd
            }
        } catch { }
        foreach ($app in $prof.AuthorizedApplications) {
            if (([string]$app.ProcessImageFileName -like '*\sessmgr.exe') -and $app.Enabled) { $raException = $true }
        }
    } catch {
        $findings += New-Finding -Area 'Firewall' -Level 'Risk' -Message ('Could not read firewall policy: ' + $_.Exception.Message)
    }

    $fwLog = Get-FirewallLogging
    if ($fwLog -and $fwLog.DroppedPackets) {
        $findings += New-Finding -Area 'Firewall' -Level 'OK' -Message 'Dropped-packet logging is on.'
    } elseif ($fwLog) {
        $findings += New-Finding -Area 'Firewall' -Level 'Warn' -Message 'Dropped-packet logging is off.' -Fix $fixCmd
    } else {
        $findings += New-Finding -Area 'Firewall' -Level 'Info' -Message 'Could not read firewall logging settings.'
    }

    Write-Section 'Services'
    foreach ($n in @('MSMQ', 'upnphost', 'SSDPSRV', 'SimpTcp', 'lanmanserver', 'Browser', 'RemoteRegistry', 'Messenger', 'TlntSvr')) {
        $w = Get-WmiObject -Class Win32_Service -Filter ("Name = '{0}'" -f $n) -ErrorAction SilentlyContinue
        if (-not $w) {
            $findings += New-Finding -Area 'Services' -Level 'OK' -Message ('{0} is not installed.' -f $n)
        } elseif (($w.StartMode -eq 'Disabled') -and ($w.State -eq 'Stopped')) {
            $findings += New-Finding -Area 'Services' -Level 'OK' -Message ('{0} ({1}) is stopped and disabled.' -f $w.DisplayName, $n)
        } else {
            $findings += New-Finding -Area 'Services' -Level 'Warn' -Message ('{0} ({1}) is {2}, startup {3}.' -f $w.DisplayName, $n, $w.State, $w.StartMode) -Fix $fixCmd
        }
    }

    Write-Section 'SMB, NetBIOS, accounts, Remote Assistance, AutoRun'
    $netbt = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -ErrorAction SilentlyContinue
    $smbOff = ($netbt -and ($netbt.SMBDeviceEnabled -ne $null) -and ($netbt.SMBDeviceEnabled -eq 0))
    if ($smbOff) {
        $findings += New-Finding -Area 'SMB' -Level 'OK' -Message 'SMB over port 445 is off (SMBDeviceEnabled = 0).'
    } else {
        $findings += New-Finding -Area 'SMB' -Level 'Warn' -Message 'SMBDeviceEnabled is not 0, so port 445 stays open.' -Fix ($fixCmd + ', then reboot')
    }

    # NetBIOS is checked per NetBT interface, so disabled or unplugged
    # adapters that would turn NetBIOS back on when reconnected are caught too.
    $ifaces = @(Get-NetbtInterface)
    $nbOn = @($ifaces | Where-Object { $_.NetbiosOptions -ne 2 })
    if ($ifaces.Length -eq 0) {
        $findings += New-Finding -Area 'NetBIOS' -Level 'Info' -Message 'Could not read the NetBT interface settings.'
    } elseif ($nbOn.Length -eq 0) {
        $findings += New-Finding -Area 'NetBIOS' -Level 'OK' -Message ('NetBIOS over TCP/IP is off on all {0} network interface(s).' -f $ifaces.Length)
    } else {
        $names = ($nbOn | ForEach-Object { $_.Description }) -join ', '
        $findings += New-Finding -Area 'NetBIOS' -Level 'Warn' -Message ('NetBIOS over TCP/IP is not off on: ' + $names) -Fix $fixCmd
    }

    $guest = Get-GuestAccount
    if (-not $guest) {
        $findings += New-Finding -Area 'Accounts' -Level 'Info' -Message 'Built-in Guest account not found.'
    } elseif ($guest.Disabled) {
        $findings += New-Finding -Area 'Accounts' -Level 'OK' -Message ('Guest account ("{0}") is disabled.' -f $guest.Name)
    } else {
        $findings += New-Finding -Area 'Accounts' -Level 'Warn' -Message ('Guest account ("{0}") is enabled.' -f $guest.Name) -Fix $fixCmd
    }

    $ts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    if ($ts -and ($ts.fAllowToGetHelp -ne $null) -and ($ts.fAllowToGetHelp -eq 0)) {
        $findings += New-Finding -Area 'Remote' -Level 'OK' -Message 'Remote Assistance is off.'
    } else {
        $findings += New-Finding -Area 'Remote' -Level 'Warn' -Message 'Remote Assistance is on.' -Fix $fixCmd
    }
    if ($raException) {
        $level = 'Warn'
        $note = ''
        if ($noExceptions) { $level = 'Info'; $note = ' (ignored while exceptions are disabled)' }
        $findings += New-Finding -Area 'Remote' -Level $level -Message ('Remote Assistance firewall exception is enabled{0}.' -f $note) -Fix $fixCmd
    }

    $explorer = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue
    if ($explorer -and ($explorer.NoDriveTypeAutoRun -eq 255)) {
        $findings += New-Finding -Area 'AutoRun' -Level 'OK' -Message 'AutoRun is off for all drive types.'
    } else {
        $findings += New-Finding -Area 'AutoRun' -Level 'Warn' -Message 'AutoRun is not fully disabled.' -Fix $fixCmd
    }

    Write-Section 'Logon security'
    $lsa = Get-ItemProperty -Path $script:LsaPath -ErrorAction SilentlyContinue
    $lsaChecks = @(
        @{ Name = 'RestrictAnonymous';    Min = 1; Good = 'Anonymous listing of accounts and shares is blocked (RestrictAnonymous).'
           Bad = 'Anonymous (null session) users can list shares (RestrictAnonymous is 0).' },
        @{ Name = 'RestrictAnonymousSAM'; Min = 1; Good = 'Anonymous listing of accounts is blocked (RestrictAnonymousSAM).'
           Bad = 'Anonymous (null session) users can list accounts (RestrictAnonymousSAM is 0).' },
        @{ Name = 'NoLMHash';             Min = 1; Good = 'LM password hashes are not stored (NoLMHash = 1).'
           Bad = 'Windows stores weak LM password hashes (NoLMHash is not 1).' },
        @{ Name = 'LmCompatibilityLevel'; Min = 3; Good = 'Sends NTLMv2 only (LmCompatibilityLevel 3 or higher).'
           Bad = 'Still sends weak LM/NTLMv1 logon responses (LmCompatibilityLevel below 3).' }
    )
    foreach ($c in $lsaChecks) {
        $v = $null
        if ($lsa) { $v = $lsa.($c.Name) }
        if (($v -ne $null) -and ([int]$v -ge $c.Min)) {
            $findings += New-Finding -Area 'Logon' -Level 'OK' -Message $c.Good
        } else {
            $findings += New-Finding -Area 'Logon' -Level 'Warn' -Message $c.Bad -Fix $fixCmd
        }
    }

    $policy = ConvertFrom-NetAccounts -Text (& net.exe accounts 2>&1)
    if (-not $policy) {
        $findings += New-Finding -Area 'Logon' -Level 'Info' -Message 'Could not read the password policy (net accounts).'
    } else {
        if ($policy.MinLength -ge 8) {
            $findings += New-Finding -Area 'Logon' -Level 'OK' -Message ('Minimum password length is {0}.' -f $policy.MinLength)
        } else {
            $findings += New-Finding -Area 'Logon' -Level 'Warn' -Message ('Minimum password length is {0}; 8 or more is recommended.' -f $policy.MinLength) -Fix $fixCmd
        }
        if ($policy.LockoutThreshold -gt 0) {
            $findings += New-Finding -Area 'Logon' -Level 'OK' -Message ('Accounts lock after {0} bad password tries.' -f $policy.LockoutThreshold)
        } else {
            $findings += New-Finding -Area 'Logon' -Level 'Warn' -Message 'No account lockout: passwords can be guessed without limit.' -Fix $fixCmd
        }
    }

    # DEP: 0 AlwaysOff, 1 AlwaysOn, 2 OptIn (XP default), 3 OptOut.
    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($os -and ($os.DataExecutionPrevention_SupportPolicy -ne $null)) {
        $depFix = 'In boot.ini change /noexecute=optin to /noexecute=optout (System Properties > Advanced > Performance Settings > Data Execution Prevention > "Turn on DEP for all programs"), then reboot'
        switch ([int]$os.DataExecutionPrevention_SupportPolicy) {
            0 { $findings += New-Finding -Area 'DEP' -Level 'Warn' -Message 'DEP is turned off (AlwaysOff).' -Fix $depFix }
            1 { $findings += New-Finding -Area 'DEP' -Level 'OK' -Message 'DEP is on for all programs (AlwaysOn).' }
            2 { $findings += New-Finding -Area 'DEP' -Level 'Info' -Message 'DEP covers Windows system programs only (OptIn, the XP default).' -Fix $depFix }
            3 { $findings += New-Finding -Area 'DEP' -Level 'OK' -Message 'DEP is on for all programs except ones you exclude (OptOut).' }
        }
        if ($os.DataExecutionPrevention_Available -eq $false) {
            $findings += New-Finding -Area 'DEP' -Level 'Info' -Message 'This CPU has no hardware DEP (NX), so only software DEP applies.'
        }
    }

    Write-Section 'Patches'
    # The three wormable flaws are checked by the version of the file each fix
    # replaced, not by KB number: later updates (POSReady 2009 and others)
    # supersede the original KBs, so a fully patched PC often lacks them.
    # Minimum versions are from Microsoft's file-information tables (XP SP3, x86).
    # The minimum versions below are 32-bit XP SP3 (5.1.2600.x) file versions.
    # XP x64 / Server 2003 files are 5.2.3790.x and would always compare as
    # newer, so the check is skipped there instead of reporting false "patched".
    $patchCheck = Test-IsXP32
    if (-not $patchCheck) {
        $findings += New-Finding -Area 'Patches' -Level 'Info' -Message ('Wormable-flaw checks only cover 32-bit Windows XP SP3; skipped on version {0}. Check this system''s updates separately.' -f (Get-OSVersionInfo))
    }
    $sys32 = $env:windir + '\system32'
    $fileChecks = @(
        @{ Name = 'MS08-067, SMB worm flaw (Conficker)'; Kb = 'KB958644';  File = 'netapi32.dll';       Min = '5.1.2600.5694'
           Fix = 'Legacy Update' },
        @{ Name = 'MS17-010, SMBv1 (WannaCry)';          Kb = 'KB4012598'; File = 'drivers\srv.sys';    Min = '5.1.2600.7208'
           Fix = 'Legacy Update, or KB4012598 from the Microsoft Update Catalog' },
        @{ Name = 'CVE-2019-0708, Remote Desktop (BlueKeep)'; Kb = 'KB4500331'; File = 'drivers\termdd.sys'; Min = '5.1.2600.7701'
           Fix = 'KB4500331 from the Microsoft Update Catalog (not offered through Windows Update on XP)' }
    )
    foreach ($c in $fileChecks) {
        if (-not $patchCheck) { break }
        $path = $sys32 + '\' + $c.File
        $leaf = ($c.File -split '\\')[-1]
        $current = Get-FileVersionObject -Path $path
        $minimum = New-Object System.Version -ArgumentList $c.Min
        if (-not $current) {
            $findings += New-Finding -Area 'Patches' -Level 'Info' -Message ('{0}: {1} not found, cannot check.' -f $c.Name, $leaf)
        } elseif ($current -ge $minimum) {
            $findings += New-Finding -Area 'Patches' -Level 'OK' -Message ('{0} patched: {1} {2} (fix is {3}).' -f $c.Name, $leaf, $current, $minimum)
        } else {
            $findings += New-Finding -Area 'Patches' -Level 'Risk' -Message ('{0} NOT patched: {1} {2}, needs {3} or later ({4}).' -f $c.Name, $leaf, $current, $minimum, $c.Kb) -Fix $c.Fix
        }
    }

    # AutoRun fix: checked by KB number only, so a miss may just mean superseded.
    $installed = @()
    $installed += @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.HotFixID })
    $installed += @(Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.PSChildName })
    $autorunFix = @($installed | Where-Object { $_ -like 'KB967715*' })
    if ($autorunFix.Length -gt 0) {
        $findings += New-Finding -Area 'Patches' -Level 'OK' -Message 'KB967715 installed (AutoRun fix that makes NoDriveTypeAutoRun fully work).'
    } else {
        $findings += New-Finding -Area 'Patches' -Level 'Info' -Message 'KB967715 (AutoRun fix) not found by KB number; it may be superseded. Legacy Update will offer it if needed.'
    }

    Write-Section 'Listening TCP ports (network-facing)'
    $listeners = @()
    foreach ($line in @(netstat -an)) {
        if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING') {
            $addr = $matches[1]
            $port = [int]$matches[2]
            if (($addr -ne '127.0.0.1') -and ($addr -ne '[::1]')) {
                $listeners += New-Object PSObject -Property @{ Address = $addr; Port = $port }
            }
        }
    }
    $ports = @($listeners | ForEach-Object { $_.Port } | Sort-Object -Unique)
    if ($ports.Length -eq 0) {
        $findings += New-Finding -Area 'Ports' -Level 'OK' -Message 'Nothing is listening on the network.'
    }
    foreach ($port in $ports) {
        $where = (@($listeners | Where-Object { $_.Port -eq $port } | ForEach-Object { $_.Address }) -join ', ')
        $key = [string]$port
        if ($port -eq 135) {
            $findings += New-Finding -Area 'Ports' -Level 'Info' -Message ('135 RPC on {0}: cannot be closed on XP; the firewall blocks it.' -f $where)
        } elseif (($port -eq 445) -and $smbOff) {
            $findings += New-Finding -Area 'Ports' -Level 'Warn' -Message ('445 SMB is still listening on {0}: SMBDeviceEnabled is already 0, so a reboot is pending.' -f $where) -Fix 'Restart-Computer'
        } elseif ($script:RiskyPorts.ContainsKey($key)) {
            $findings += New-Finding -Area 'Ports' -Level 'Warn' -Message ('{0} {1} is listening on {2}.' -f $port, $script:RiskyPorts[$key], $where) -Fix $fixCmd
        } elseif (@(7, 9, 13, 17, 19) -contains $port) {
            $findings += New-Finding -Area 'Ports' -Level 'Warn' -Message ('{0} Simple TCP/IP Services is listening on {1}.' -f $port, $where) -Fix $fixCmd
        } else {
            $note = ''
            if ($noExceptions) { $note = ' Blocked while firewall exceptions are disabled.' }
            $findings += New-Finding -Area 'Ports' -Level 'Info' -Message ('{0} is listening on {1}.{2} Check with: netstat -ano' -f $port, $where, $note)
        }
    }

    $risk = @($findings | Where-Object { $_.Level -eq 'Risk' }).Length
    $warn = @($findings | Where-Object { $_.Level -eq 'Warn' }).Length
    Write-Section 'Summary'
    $color = 'Green'
    if ($warn -gt 0) { $color = 'Yellow' }
    if ($risk -gt 0) { $color = 'Red' }
    Write-Host ('  {0} risk(s), {1} warning(s).' -f $risk, $warn) -ForegroundColor $color
    if (($risk + $warn) -gt 0) {
        Write-Host '  Ask the assistant what to fix first: Invoke-XPAssistant (then type: plan)' -ForegroundColor DarkGray
    }

    Save-RunFindings -Name 'Get-XPHardeningStatus' -Findings $findings
    if ($PassThru) { $findings }
}

#endregion

#region Audit helpers (0.3.0)

function ConvertFrom-NetAccounts {
    # Parses `net accounts` (English XP output). "Never", "None" and
    # "Unlimited" become 0. Returns $null if the output is unreadable.
    param([object[]]$Text)
    $map = @{}
    foreach ($line in @($Text)) {
        if ([string]$line -match '^(.+?):\s+(\S.*?)\s*$') { $map[$matches[1].Trim()] = $matches[2] }
    }
    if (-not $map.ContainsKey('Minimum password length')) { return $null }
    $num = {
        param($v)
        $n = 0
        if ([int]::TryParse([string]$v, [ref]$n)) { return $n }
        return 0
    }
    New-Object PSObject -Property @{
        MinLength        = (& $num $map['Minimum password length'])
        MaxAgeDays       = (& $num $map['Maximum password age (days)'])
        History          = (& $num $map['Length of password history maintained'])
        LockoutThreshold = (& $num $map['Lockout threshold'])
        LockoutMinutes   = (& $num $map['Lockout duration (minutes)'])
    }
}

function Get-LocalAdminMember {
    # Members of the local Administrators group. The group is found by its SID
    # (S-1-5-32-544), so a renamed or non-English group name still works.
    # Returns $null if `net localgroup` fails.
    $grp = @(Get-WmiObject -Class Win32_Group -Filter 'LocalAccount = TRUE' -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.SID -eq 'S-1-5-32-544' }) | Select-Object -First 1
    $name = 'Administrators'
    if ($grp) { $name = $grp.Name }
    $out = @(& net.exe localgroup $name 2>&1)
    if ($LASTEXITCODE -ne 0) { return $null }
    $members = @()
    $inList = $false
    foreach ($line in $out) {
        $s = ([string]$line).Trim()
        if ($s -match '^-{10,}$') { $inList = $true; continue }
        if ((-not $inList) -or (-not $s)) { continue }
        if ($s -like 'The command completed*') { break }
        $members += $s
    }
    New-Object PSObject -Property @{ Group = $name; Members = $members }
}

function Read-SharedTextFile {
    # Reads a text file that another process keeps open for writing (the
    # firewall service holds pfirewall.log open), so it opens with ReadWrite
    # sharing instead of the read-only open Get-Content would need.
    param([string]$Path)
    $fs = $null
    $sr = $null
    try {
        $fs = New-Object System.IO.FileStream -ArgumentList $Path, ([System.IO.FileMode]::Open), ([System.IO.FileAccess]::Read), ([System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader -ArgumentList $fs
        $sr.ReadToEnd() -split "`r?`n"
    } finally {
        if ($sr) { $sr.Close() }
        if ($fs) { $fs.Close() }
    }
}

function ConvertFrom-FirewallLogLine {
    # Parses one pfirewall.log line (W3C format):
    # date time action protocol src-ip dst-ip src-port dst-port size ...
    # Returns nothing for headers, blank or malformed lines.
    param([string]$Line)
    if ((-not $Line) -or $Line.StartsWith('#')) { return }
    $f = $Line.Trim() -split '\s+'
    if ($f.Length -lt 8) { return }
    $t = [datetime]::MinValue
    $ok = [datetime]::TryParseExact(($f[0] + ' ' + $f[1]), 'yyyy-MM-dd HH:mm:ss',
        [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$t)
    if (-not $ok) { return }
    New-Object PSObject -Property @{
        Time = $t; Action = $f[2]; Protocol = $f[3]; Source = $f[4]
        Destination = $f[5]; SourcePort = $f[6]; DestPort = $f[7]
    }
}

function Get-LocalNetworkList {
    # One object per local IPv4 subnet: Start (network as int64) and Block size.
    $nets = @()
    foreach ($a in @(Get-XPAdapterInfo)) {
        if ($a.IPv4 -and $a.PrefixLength) {
            $block = [int64][math]::Pow(2, 32 - $a.PrefixLength)
            $ip = ConvertTo-IPv4Int64 $a.IPv4
            $nets += New-Object PSObject -Property @{ Address = $a.IPv4; Start = ($ip - ($ip % $block)); Block = $block }
        }
    }
    return $nets
}

function Test-InNetworkList {
    param([string]$Address, $Networks)
    if ($Address -notmatch $script:Ipv4Pattern) { return $true }
    $v = ConvertTo-IPv4Int64 $Address
    foreach ($n in @($Networks)) {
        if ($n -and ($v -ge $n.Start) -and ($v -lt ($n.Start + $n.Block))) { return $true }
    }
    return $false
}

function Test-PrivateIPv4 {
    # RFC 1918, CGNAT (100.64/10), link-local and loopback.
    param([string]$Address)
    if ($Address -notmatch $script:Ipv4Pattern) { return $false }
    $o = $Address.Split('.')
    $a = [int]$o[0]
    $b = [int]$o[1]
    if (($a -eq 10) -or ($a -eq 127)) { return $true }
    if (($a -eq 172) -and ($b -ge 16) -and ($b -le 31)) { return $true }
    if (($a -eq 192) -and ($b -eq 168)) { return $true }
    if (($a -eq 169) -and ($b -eq 254)) { return $true }
    if (($a -eq 100) -and ($b -ge 64) -and ($b -le 127)) { return $true }
    return $false
}

function Get-VirtualGatewayKind {
    # Names the VM software when a MAC belongs to a virtual NAT gateway.
    param([string]$Mac)
    $m = ([string]$Mac).ToUpper() -replace ':', '-'
    if ($m -like '00-50-56-*') { return 'VMware' }
    if ($m -like '52-54-00-*') { return 'VirtualBox/QEMU' }
    if ($m -like '08-00-27-*') { return 'VirtualBox' }
    if ($m -like '00-15-5D-*') { return 'Hyper-V' }
    return $null
}

function Test-TcpPort {
    # TCP connect test with a timeout (.NET 2.0 BeginConnect, since PS 2.0 has
    # no Test-NetConnection). Returns $true if the port accepted a connection.
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 800)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($ar)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Find-UpnpGateway {
    # Sends an SSDP M-SEARCH for an Internet Gateway Device and returns the
    # router's reply (Server and Location headers) if the given address
    # answers within the timeout, else $null.
    param([string]$Router, [int]$TimeoutMs = 2500)
    $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`n" +
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
    $udp = $null
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 500
        $multicast = New-Object System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Parse('239.255.255.250')), 1900
        $unicast = New-Object System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Parse($Router)), 1900
        [void]$udp.Send($bytes, $bytes.Length, $multicast)
        [void]$udp.Send($bytes, $bytes.Length, $unicast)
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            $from = New-Object System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any), 0
            $data = $null
            try { $data = $udp.Receive([ref]$from) } catch { continue }
            if ($from.Address.ToString() -ne $Router) { continue }
            $text = [System.Text.Encoding]::ASCII.GetString($data)
            $server = ''
            $location = ''
            if ($text -match '(?im)^SERVER:\s*(.+?)\s*$') { $server = $matches[1] }
            if ($text -match '(?im)^LOCATION:\s*(.+?)\s*$') { $location = $matches[1] }
            return (New-Object PSObject -Property @{ Server = $server; Location = $location })
        }
    } catch {
    } finally {
        if ($udp) { $udp.Close() }
    }
    return $null
}

function Get-DefaultReportDir {
    # My Documents\SecurityChecks, with fallbacks if the shell folder is
    # not set (a broken profile, or a service account).
    $base = [Environment]::GetFolderPath('MyDocuments')
    if ((-not $base) -and $env:USERPROFILE) { $base = Join-Path $env:USERPROFILE 'My Documents' }
    if (-not $base) { $base = [System.IO.Path]::GetTempPath() }
    return (Join-Path $base 'SecurityChecks')
}

function ConvertTo-HtmlText {
    param([string]$Text)
    # IE6-8 do not know &apos;, so use the numeric form.
    return ([string][System.Security.SecurityElement]::Escape([string]$Text)).Replace('&apos;', '&#39;')
}

function Export-FindingsHtml {
    # Writes findings as a self-contained HTML page (opens in IE6+ on XP).
    # Built by hand so the escaping is the same on every PowerShell version.
    param($Findings, [string]$Path, [string]$Title, [string[]]$Notes, [string[]]$Plan)
    $rank = @{ 'Risk' = 0; 'Warn' = 1; 'Info' = 2; 'OK' = 3 }
    $rows = @($Findings | Where-Object { $_ } | Sort-Object @{ Expression = { $rank[[string]$_.Level] } })
    $risk = @($rows | Where-Object { $_.Level -eq 'Risk' }).Length
    $warn = @($rows | Where-Object { $_.Level -eq 'Warn' }).Length
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html><head><meta charset="us-ascii"><title>' + (ConvertTo-HtmlText $Title) + '</title><style>')
    [void]$sb.Append('body{font-family:Tahoma,Arial,sans-serif;font-size:13px;margin:16px;color:#222;background:#fff}')
    [void]$sb.Append('h1{font-size:18px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}')
    [void]$sb.Append('th{background:#dde4ee}tr.risk td{background:#f8d7d7}tr.warn td{background:#fff1c9}tr.ok td{background:#e6f4e6}code{font-family:Consolas,monospace}')
    [void]$sb.Append('</style></head><body><h1>' + (ConvertTo-HtmlText $Title) + '</h1>')
    [void]$sb.Append(('<p><b>{0} risk(s), {1} warning(s)</b>, {2} finding(s) in total.</p>' -f $risk, $warn, $rows.Length))
    foreach ($n in @($Notes)) { if ($n) { [void]$sb.Append('<p>' + (ConvertTo-HtmlText $n) + '</p>') } }
    if (@($Plan).Length -gt 0) {
        [void]$sb.Append('<h2 style="font-size:15px">What to fix first</h2><ol>')
        foreach ($step in @($Plan)) {
            $parts = ([string]$step -replace '^\d+\.\s*', '') -split "`n\s*Fix:\s*", 2
            $item = ConvertTo-HtmlText $parts[0]
            if ($parts.Length -gt 1) { $item += '<br>Fix: <code>' + (ConvertTo-HtmlText $parts[1]) + '</code>' }
            [void]$sb.Append('<li style="margin-bottom:6px">' + $item + '</li>')
        }
        [void]$sb.Append('</ol>')
    }
    [void]$sb.Append('<table><tr><th>Level</th><th>Area</th><th>Finding</th><th>Fix</th></tr>')
    foreach ($f in $rows) {
        $cls = ([string]$f.Level).ToLower()
        [void]$sb.Append(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td><code>{4}</code></td></tr>' -f
            $cls, (ConvertTo-HtmlText $f.Level), (ConvertTo-HtmlText $f.Area), (ConvertTo-HtmlText $f.Message), (ConvertTo-HtmlText $f.Fix)))
    }
    [void]$sb.Append('</table><p>Generated by NetSecToolkitXP.</p></body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.Encoding]::ASCII)
}

#endregion

#region Audits (0.3.0)

function Get-AccountAuditXP {
<#
.SYNOPSIS
    Read-only audit of local accounts and logon settings on Windows XP.
.DESCRIPTION
    Lists the local accounts and who is in Administrators, and flags enabled
    accounts that are allowed a blank password, enabled built-in support
    accounts, blank-password network logons (LimitBlankPasswordUse),
    automatic logon and a plain-text DefaultPassword in the registry, and a
    screen saver without a password. Changes nothing. The password and
    lockout policy is checked by Get-XPHardeningStatus.
.PARAMETER PassThru
    Also return the accounts and findings as an object.
.EXAMPLE
    Get-AccountAuditXP
#>
    [CmdletBinding()]
    param([switch]$PassThru)

    $findings = @()
    Write-Section 'Local accounts'

    $admin = Get-LocalAdminMember
    $adminNames = @()
    if ($admin) { $adminNames = @($admin.Members | ForEach-Object { ([string]$_).ToLower() }) }

    $rows = @()
    foreach ($a in @(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount = TRUE' -ErrorAction SilentlyContinue)) {
        if (-not $a) { continue }
        $rid = ([string]$a.SID -split '-')[-1]
        $builtin = ''
        if ($rid -eq '500') { $builtin = 'Administrator' }
        elseif ($rid -eq '501') { $builtin = 'Guest' }
        elseif ($a.Name -eq 'HelpAssistant') { $builtin = 'Remote Assistance' }
        elseif ([string]$a.Name -like 'SUPPORT_*') { $builtin = 'Help and Support' }
        elseif ($a.Name -eq 'ASPNET') { $builtin = 'Service (.NET)' }
        elseif (([string]$a.Name -like 'IUSR_*') -or ([string]$a.Name -like 'IWAM_*')) { $builtin = 'Service (IIS)' }
        $lname = ([string]$a.Name).ToLower()
        $isAdmin = $false
        foreach ($m in $adminNames) {
            if (($m -eq $lname) -or $m.EndsWith('\' + $lname)) { $isAdmin = $true }
        }
        $rows += New-Object PSObject -Property @{
            Name = $a.Name; Enabled = (-not $a.Disabled); Admin = $isAdmin
            PasswordRequired = [bool]$a.PasswordRequired; LockedOut = [bool]$a.Lockout; BuiltIn = $builtin
        }
    }
    $rows = @($rows | Sort-Object Name | Select-Object Name, Enabled, Admin, PasswordRequired, LockedOut, BuiltIn)
    if ($rows.Length -eq 0) {
        $findings += New-Finding -Area 'Accounts' -Level 'Info' -Message 'Could not read the local accounts (WMI Win32_UserAccount).'
    } else {
        Write-TableToHost $rows
    }

    foreach ($r in $rows) {
        if (-not $r.Enabled) { continue }
        if ($r.BuiltIn -like 'Service*') {
            # ASPNET / IUSR_ / IWAM_ are created by .NET and IIS with random
            # passwords; PasswordRequired = False on them is normal.
            $findings += New-Finding -Area 'Accounts' -Level 'Info' -Message ('"{0}" is a service account created by {1}, with a random password. Disable it if this PC does not run a web server.' -f $r.Name, ($r.BuiltIn -replace '^Service \((.+)\)$', '$1')) -Fix ('net user "{0}" /active:no' -f $r.Name)
            continue
        }
        # Guest never requires a password; Get-XPHardeningStatus covers it.
        if ((-not $r.PasswordRequired) -and ($r.BuiltIn -ne 'Guest')) {
            $findings += New-Finding -Area 'Accounts' -Level 'Warn' -Message ('"{0}" is allowed a blank password (PasswordRequired = False).' -f $r.Name) -Fix ('net user "{0}" /passwordreq:yes   (and give it a password)' -f $r.Name)
        }
        if (($r.BuiltIn -eq 'Remote Assistance') -or ($r.BuiltIn -eq 'Help and Support')) {
            $findings += New-Finding -Area 'Accounts' -Level 'Warn' -Message ('Built-in support account "{0}" is enabled.' -f $r.Name) -Fix ('net user "{0}" /active:no' -f $r.Name)
        }
        if ($r.LockedOut) {
            $findings += New-Finding -Area 'Accounts' -Level 'Info' -Message ('"{0}" is locked out after bad password tries.' -f $r.Name)
        }
    }

    if (-not $admin) {
        $findings += New-Finding -Area 'Accounts' -Level 'Info' -Message 'Could not read the Administrators group (net localgroup).'
    } else {
        $enabledAdmins = @($rows | Where-Object { $_.Enabled -and $_.Admin } | ForEach-Object { $_.Name })
        $level = 'Info'
        if ($enabledAdmins.Length -gt 2) { $level = 'Warn' }
        $findings += New-Finding -Area 'Accounts' -Level $level -Message ('{0} enabled administrator account(s): {1}. Use a limited account for everyday work.' -f $enabledAdmins.Length, ($enabledAdmins -join ', '))
    }

    Write-Section 'Logon settings'
    $lsa = Get-ItemProperty -Path $script:LsaPath -ErrorAction SilentlyContinue
    if ($lsa -and ($lsa.LimitBlankPasswordUse -ne $null) -and ([int]$lsa.LimitBlankPasswordUse -eq 0)) {
        $findings += New-Finding -Area 'Logon' -Level 'Risk' -Message 'Accounts with blank passwords can log on over the network (LimitBlankPasswordUse = 0).' -Fix 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f'
    } else {
        $findings += New-Finding -Area 'Logon' -Level 'OK' -Message 'Blank-password accounts can only log on at the keyboard (LimitBlankPasswordUse = 1).'
    }

    $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    $auto = ($wl -and ([string]$wl.AutoAdminLogon -eq '1'))
    $plain = ($wl -and ($wl.DefaultPassword -ne $null) -and ([string]$wl.DefaultPassword -ne ''))
    $who = ''
    if ($wl) { $who = [string]$wl.DefaultUserName }
    $delPw = 'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f'
    if ($auto -and $plain) {
        $findings += New-Finding -Area 'Logon' -Level 'Risk' -Message ('Automatic logon is on and the password for "{0}" is stored in plain text in the registry (Winlogon DefaultPassword).' -f $who) -Fix ($delPw + '; then control userpasswords2 > tick "Users must enter a user name and password"')
    } elseif ($auto) {
        $findings += New-Finding -Area 'Logon' -Level 'Warn' -Message ('Automatic logon is on: anyone who turns this PC on gets the desktop of "{0}".' -f $who) -Fix 'control userpasswords2 > tick "Users must enter a user name and password to use this computer"'
    } elseif ($plain) {
        $findings += New-Finding -Area 'Logon' -Level 'Warn' -Message 'Automatic logon is off, but a plain-text DefaultPassword is still in the registry.' -Fix $delPw
    } else {
        $findings += New-Finding -Area 'Logon' -Level 'OK' -Message 'Automatic logon is off.'
    }

    $desk = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
    if ($desk -and ([string]$desk.ScreenSaveActive -eq '1') -and ([string]$desk.ScreenSaverIsSecure -eq '1')) {
        $mins = 0
        $secs = 0
        if ([int]::TryParse([string]$desk.ScreenSaveTimeOut, [ref]$secs)) { $mins = [int]($secs / 60) }
        $findings += New-Finding -Area 'Logon' -Level 'OK' -Message ('Screen saver locks the PC after {0} minute(s) (this user).' -f $mins)
    } else {
        $findings += New-Finding -Area 'Logon' -Level 'Info' -Message 'Screen saver does not ask for a password (this user).' -Fix 'Display Properties > Screen Saver > tick "On resume, password protect"; Windows key + L locks right away'
    }

    Save-RunFindings -Name 'Get-AccountAuditXP' -Findings $findings
    if ($PassThru) {
        New-Object PSObject -Property @{ Accounts = $rows; Administrators = $adminNames; Findings = $findings }
    }
}

function Get-FirewallLogXP {
<#
.SYNOPSIS
    Summarizes what Windows Firewall blocked, from pfirewall.log.
.DESCRIPTION
    Reads pfirewall.log (and pfirewall.log.old after a rollover) for the last
    -Hours, counts dropped packets, lists the sources that tried to reach
    this PC directly, flags likely port scans (one source, 10+ ports) and
    blocked traffic from the internet or from outside your subnet.
    Needs dropped-packet logging (Set-XPHardening turns it on). Run it as an
    administrator if the log cannot be read. Changes nothing.
.PARAMETER Hours
    How far back to read. Default 24.
.PARAMETER Path
    Log file. Default: the path netsh reports, else %windir%\pfirewall.log.
.PARAMETER Top
    How many source/port rows to show.
.PARAMETER PassThru
    Also return the drops aimed at this PC and the findings as an object.
.EXAMPLE
    Get-FirewallLogXP -Hours 72
#>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 720)][int]$Hours = 24,
        [string]$Path,
        [ValidateRange(1, 100)][int]$Top = 10,
        [switch]$PassThru
    )

    $findings = @()
    Write-Section ('Firewall log (last {0} hours)' -f $Hours)

    $fwLog = Get-FirewallLogging
    if (-not $Path) {
        if ($fwLog -and $fwLog.Path) { $Path = [Environment]::ExpandEnvironmentVariables([string]$fwLog.Path) }
        else { $Path = $env:windir + '\pfirewall.log' }
    } else {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
    if ($fwLog -and (-not $fwLog.DroppedPackets)) {
        $findings += New-Finding -Area 'FirewallLog' -Level 'Warn' -Message 'Dropped-packet logging is off, so there is no blocked traffic to review.' -Fix 'netsh firewall set logging droppedpackets=ENABLE connections=ENABLE'
    }

    $files = @()
    foreach ($f in @(($Path + '.old'), $Path)) {
        if (Test-Path -LiteralPath $f) { $files += $f }
    }

    $direct = New-Object System.Collections.ArrayList
    $outside = @{}
    $drops = 0
    $readErrors = @()

    if ($files.Length -eq 0) {
        $findings += New-Finding -Area 'FirewallLog' -Level 'Info' -Message ('No firewall log found at {0}.' -f $Path)
    } else {
        $myIPs = @()
        foreach ($a in @(Get-XPAdapterInfo)) { if ($a.IPv4) { $myIPs += $a.IPv4 } }
        $nets = @(Get-LocalNetworkList)
        $cut = (Get-Date).AddHours(-$Hours).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)

        foreach ($file in $files) {
            $lines = @()
            try { $lines = @(Read-SharedTextFile -Path $file) }
            catch { $readErrors += ('{0}: {1}' -f $file, $_.Exception.Message); continue }
            foreach ($line in $lines) {
                # Cheap string checks first: PS 2.0 on XP is slow at creating
                # objects, and a 4 MB log can hold 40,000 lines.
                if ((-not $line) -or ($line.IndexOf(' DROP ') -lt 0)) { continue }
                if (($line.Length -lt 19) -or ([string]::CompareOrdinal($line.Substring(0, 19), $cut) -lt 0)) { continue }
                $e = ConvertFrom-FirewallLogLine -Line $line
                if (-not $e) { continue }
                $drops++
                if ($myIPs -contains $e.Destination) { [void]$direct.Add($e) }
                $src = $e.Source
                if (($src -match $script:Ipv4Pattern) -and ($src -ne '0.0.0.0') -and (-not ($myIPs -contains $src)) -and (-not (Test-InNetworkList $src $nets))) {
                    if ((-not $outside.ContainsKey($src)) -or ($outside[$src] -lt $e.Time)) { $outside[$src] = $e.Time }
                }
            }
        }

        Write-Host ('  Log: {0}' -f ($files -join ', '))
        Write-Host ('  Blocked packets: {0}   aimed at this PC: {1}' -f $drops, $direct.Count)

        foreach ($err in $readErrors) {
            $findings += New-Finding -Area 'FirewallLog' -Level 'Info' -Message ('Could not read {0}. Run as administrator.' -f $err)
        }

        if ($direct.Count -gt 0) {
            $rows = @($direct | Group-Object Source | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
                $ports = @($_.Group | ForEach-Object { [string]$_.Protocol + '/' + [string]$_.DestPort } | Sort-Object -Unique)
                $portText = (@($ports | Select-Object -First 6)) -join ' '
                if ($ports.Length -gt 6) { $portText += (' +{0} more' -f ($ports.Length - 6)) }
                $lastSeen = @($_.Group | Sort-Object Time | Select-Object -Last 1)[0].Time
                $where = 'private'
                if ($_.Name -notmatch $script:Ipv4Pattern) { $where = 'IPv6' }
                elseif (-not (Test-PrivateIPv4 $_.Name)) { $where = 'INTERNET' }
                New-Object PSObject -Property @{ Count = $_.Count; Source = $_.Name; From = $where; Ports = $portText; LastSeen = $lastSeen }
            } | Select-Object Count, Source, From, LastSeen, Ports)
            Write-Host ''
            Write-Host '  Blocked connections aimed at this PC, by source:' -ForegroundColor White
            Write-TableToHost $rows
        }

        if ($drops -eq 0) {
            $findings += New-Finding -Area 'FirewallLog' -Level 'OK' -Message ('No blocked packets in the last {0} hours.' -f $Hours)
        } else {
            $findings += New-Finding -Area 'FirewallLog' -Level 'Info' -Message ('{0} packet(s) blocked in the last {1} hours; {2} aimed at this PC, the rest broadcast or multicast.' -f $drops, $Hours, $direct.Count)
        }

        # One source probing many ports looks like a scan.
        foreach ($g in @($direct | Group-Object Source)) {
            $ports = @($g.Group | ForEach-Object { [string]$_.DestPort } | Sort-Object -Unique)
            if ($ports.Length -ge 10) {
                $findings += New-Finding -Area 'FirewallLog' -Level 'Warn' -Message ('Possible port scan: {0} tried {1} different ports on this PC.' -f $g.Name, $ports.Length) -Fix 'Find-NetworkDeviceXP to identify the device; if it is not yours, remove it from the network'
            }
        }

        $publicDirect = @($direct | Where-Object { ($_.Source -match $script:Ipv4Pattern) -and (-not (Test-PrivateIPv4 $_.Source)) } | ForEach-Object { $_.Source } | Sort-Object -Unique)
        if ($publicDirect.Length -gt 0) {
            $shown = @($publicDirect | Select-Object -First 5) -join ', '
            $findings += New-Finding -Area 'FirewallLog' -Level 'Warn' -Message ('Blocked traffic from the internet reached this PC directly ({0} address(es): {1}). The router may forward ports or use DMZ for this PC.' -f $publicDirect.Length, $shown) -Fix 'Check the router for port forwards / DMZ pointing at this PC; Test-RouterExposureXP'
        }

        $localDirect = @($direct | Where-Object { Test-PrivateIPv4 $_.Source }).Length
        if ($localDirect -gt 0) {
            $findings += New-Finding -Area 'FirewallLog' -Level 'Info' -Message ('{0} blocked packet(s) from private addresses were aimed at this PC (usually discovery traffic from other devices).' -f $localDirect)
        }

        $outsidePrivate = @($outside.Keys | Where-Object { Test-PrivateIPv4 $_ })
        if ($outsidePrivate.Length -gt 0) {
            $findings += New-Finding -Area 'FirewallLog' -Level 'Info' -Message ('Blocked traffic from private addresses outside your subnet: {0}' -f ((@($outsidePrivate | Sort-Object | Select-Object -First 8)) -join ', '))
        }
    }

    Save-RunFindings -Name 'Get-FirewallLogXP' -Findings $findings
    if ($PassThru) {
        New-Object PSObject -Property @{ Drops = $drops; Direct = @($direct); Findings = $findings }
    }
}

function Test-RouterExposureXP {
<#
.SYNOPSIS
    Checks which services the router exposes on the LAN, and whether it answers UPnP.
.DESCRIPTION
    Connects to common TCP ports on the router (default: this PC's gateway)
    one at a time, then sends an SSDP discovery to see whether the router
    has UPnP turned on. Read-only. This is the inside view only; for the
    internet's view, run GRC ShieldsUP from a modern PC or phone.
.PARAMETER Router
    Router address. Default: the primary adapter's default gateway.
.PARAMETER TimeoutMs
    Connect timeout per port.
.PARAMETER NoUpnp
    Skip the UPnP check.
.PARAMETER PassThru
    Also return the port results and findings as an object.
.EXAMPLE
    Test-RouterExposureXP
.EXAMPLE
    Test-RouterExposureXP -Router 192.168.1.1
#>
    [CmdletBinding()]
    param(
        [string]$Router,
        [ValidateRange(100, 10000)][int]$TimeoutMs = 800,
        [switch]$NoUpnp,
        [switch]$PassThru
    )

    $findings = @()
    if (-not $Router) {
        $p = Get-PrimaryAdapter
        if ($p) { $Router = $p.Gateway }
    }
    if ((-not $Router) -or ($Router -notmatch $script:Ipv4Pattern)) {
        throw 'No IPv4 default gateway found. Use -Router 192.168.1.1'
    }
    Write-Section ('Router ' + $Router)

    # High = should normally be off. Review = fine if you use it. Expected = normal.
    $ports = @(
        @{ Port = 21;   Service = 'FTP';                Risk = 'High' },
        @{ Port = 22;   Service = 'SSH';                Risk = 'Review' },
        @{ Port = 23;   Service = 'Telnet';             Risk = 'High' },
        @{ Port = 53;   Service = 'DNS';                Risk = 'Expected' },
        @{ Port = 80;   Service = 'Web admin (HTTP)';   Risk = 'Review' },
        @{ Port = 139;  Service = 'NetBIOS/Samba';      Risk = 'Review' },
        @{ Port = 443;  Service = 'HTTPS';              Risk = 'Review' },
        @{ Port = 445;  Service = 'SMB file sharing';   Risk = 'Review' },
        @{ Port = 515;  Service = 'LPD printing';       Risk = 'Review' },
        @{ Port = 631;  Service = 'IPP printing';       Risk = 'Review' },
        @{ Port = 1723; Service = 'PPTP VPN';           Risk = 'High' },
        @{ Port = 5000; Service = 'UPnP/web service';   Risk = 'Review' },
        @{ Port = 7547; Service = 'TR-069 remote mgmt'; Risk = 'High' },
        @{ Port = 8080; Service = 'Alt HTTP';           Risk = 'Review' },
        @{ Port = 8443; Service = 'Web admin (HTTPS)';  Risk = 'Expected' },
        @{ Port = 9100; Service = 'Raw printing';       Risk = 'Review' }
    )
    Write-Host ('  Checking {0} TCP ports (up to {1} s)...' -f $ports.Length, [math]::Ceiling($ports.Length * $TimeoutMs / 1000))

    $results = @()
    foreach ($p in $ports) {
        $open = Test-TcpPort -Address $Router -Port $p.Port -TimeoutMs $TimeoutMs
        $note = ''
        if ($open) {
            if ($p.Risk -eq 'High') { $note = 'Turn off unless you really need it' }
            elseif ($p.Risk -eq 'Review') { $note = 'OK if you use it; otherwise disable' }
            else { $note = 'Normal' }
        }
        $results += New-Object PSObject -Property @{ Port = $p.Port; Service = $p.Service; Open = $open; Risk = $p.Risk; Note = $note }
    }
    $results = @($results | Select-Object Port, Service, Open, Risk, Note)
    Write-TableToHost @($results | Select-Object Port, Service, Open, Note)

    # A VM's gateway is usually the VM software's own NAT service, not the
    # home router, so its open ports say nothing about the real router.
    $gwMac = ''
    foreach ($e in @(ConvertFrom-ArpTable -Text (arp -a))) { if ($e.IPAddress -eq $Router) { $gwMac = $e.MAC } }
    $virtual = Get-VirtualGatewayKind -Mac $gwMac
    $high = 'Risk'
    $warnLevel = 'Warn'
    if ($virtual) {
        $high = 'Info'
        $warnLevel = 'Info'
        $findings += New-Finding -Area 'Router' -Level 'Info' -Message ('The gateway {0} is {1}''s virtual NAT (MAC {2}), not a real router, so the results below describe the VM software. To check your home router, run Test-RouterExposureXP on a PC on your real network, or the main toolkit''s Test-RouterExposure.' -f $Router, $virtual, $gwMac)
    }

    $openPorts = @($results | Where-Object { $_.Open })
    foreach ($r in @($openPorts | Where-Object { $_.Risk -eq 'High' })) {
        $findings += New-Finding -Area 'Router' -Level $high -Message ('Router port {0} ({1}) is open on the LAN.' -f $r.Port, $r.Service) -Fix 'Turn it off in the router admin page (Administration / Services / WAN), or update the router firmware'
    }
    foreach ($r in @($openPorts | Where-Object { $_.Risk -eq 'Review' })) {
        $findings += New-Finding -Area 'Router' -Level 'Info' -Message ('Router port {0} ({1}) is open. Fine if you use it.' -f $r.Port, $r.Service)
    }
    $http = @($openPorts | Where-Object { $_.Port -eq 80 }).Length -gt 0
    $https = @($openPorts | Where-Object { ($_.Port -eq 443) -or ($_.Port -eq 8443) }).Length -gt 0
    if ($http -and (-not $https)) {
        $findings += New-Finding -Area 'Router' -Level $warnLevel -Message 'Router admin page is HTTP only, so its password crosses the network unencrypted.' -Fix 'Turn on HTTPS for the admin page (often under Administration > System) if the router supports it'
    }
    if ($openPorts.Length -eq 0) {
        $findings += New-Finding -Area 'Router' -Level 'Info' -Message 'No common TCP ports answered (the router may block this PC, or use other ports).'
    }

    $upnp = $null
    if (-not $NoUpnp) {
        Write-Host '  Checking for UPnP (SSDP)...'
        $upnp = Find-UpnpGateway -Router $Router
        if ($upnp) {
            $detail = ''
            if ($upnp.Server) { $detail = ' (' + $upnp.Server + ')' }
            $findings += New-Finding -Area 'Router' -Level $warnLevel -Message ('The router answers UPnP discovery{0}: any program on any device here can open ports to the internet without a password.' -f $detail) -Fix 'Turn off UPnP in the router admin page unless a console or app really needs it'
        } else {
            $findings += New-Finding -Area 'Router' -Level 'OK' -Message 'The router did not answer UPnP discovery (off, or not reachable from this PC).'
        }
    }

    Write-Host ''
    Write-Host '  Inside view only. For what the internet sees, run GRC ShieldsUP (grc.com/shieldsup)' -ForegroundColor DarkGray
    Write-Host '  from a modern PC or phone on this network; XP''s browsers cannot load it.' -ForegroundColor DarkGray

    Save-RunFindings -Name 'Test-RouterExposureXP' -Findings $findings
    if ($PassThru) {
        New-Object PSObject -Property @{ Router = $Router; Ports = $results; Upnp = $upnp; Findings = $findings }
    }
}

function Get-USBHistoryXP {
<#
.SYNOPSIS
    Lists every USB storage device that has been connected to this PC.
.DESCRIPTION
    Reads HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR, where Windows records
    each USB disk and CD drive with its serial number, and reports whether
    USB storage is blocked (USBSTOR Start = 4). Invoke-XPSecurityCheck uses
    this to flag new devices since the last check. Changes nothing.
.PARAMETER PassThru
    Also return the devices and findings as an object.
.EXAMPLE
    Get-USBHistoryXP
#>
    [CmdletBinding()]
    param([switch]$PassThru)

    $findings = @()
    Write-Section 'USB storage devices ever connected'
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $devices = @()
    foreach ($model in @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
        if (-not $model) { continue }
        $modelKey = [string]$model.PSChildName
        $kind = ($modelKey -split '&')[0]
        foreach ($inst in @(Get-ChildItem -Path ($root + '\' + $modelKey) -ErrorAction SilentlyContinue)) {
            if (-not $inst) { continue }
            $instKey = [string]$inst.PSChildName
            $props = Get-ItemProperty -Path ($root + '\' + $modelKey + '\' + $instKey) -ErrorAction SilentlyContinue
            $name = ''
            if ($props) { $name = [string]$props.FriendlyName }
            if (-not $name) { $name = $modelKey }
            # Serials ending in &0 are real; a 2nd character of & means Windows
            # made one up because the device has no serial number.
            $serial = $instKey -replace '&\d+$', ''
            $noSerial = ($instKey.Length -gt 1) -and ($instKey.Substring(1, 1) -eq '&')
            $devices += New-Object PSObject -Property @{ Device = $name; Kind = $kind; Serial = $serial; NoSerial = $noSerial }
        }
    }
    $devices = @($devices | Sort-Object Device | Select-Object Device, Kind, Serial, NoSerial)
    if ($devices.Length -eq 0) {
        Write-Host '  (none recorded)'
    } else {
        Write-TableToHost $devices
    }
    $findings += New-Finding -Area 'USB' -Level 'Info' -Message ('{0} USB storage device(s) have been connected to this PC.' -f $devices.Length)

    $svc = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -ErrorAction SilentlyContinue
    if ($svc -and ($svc.Start -eq 4)) {
        $findings += New-Finding -Area 'USB' -Level 'OK' -Message 'USB storage is blocked (USBSTOR Start = 4).'
    } else {
        $findings += New-Finding -Area 'USB' -Level 'Info' -Message 'USB storage is allowed. AutoRun being off is what stops USB worms.'
    }

    Save-RunFindings -Name 'Get-USBHistoryXP' -Findings $findings
    if ($PassThru) {
        New-Object PSObject -Property @{ Devices = $devices; Findings = $findings }
    }
}

function Invoke-XPSecurityCheck {
<#
.SYNOPSIS
    All-in-one security check for this XP PC and the network it is on.
.DESCRIPTION
    Runs, in order: Get-XPHardeningStatus, Get-AccountAuditXP,
    Get-NetAdapterHealthXP, Get-FirewallLogXP, Find-NetworkDeviceXP (ARP
    cache only unless -ActiveScan), Test-RouterExposureXP and
    Get-USBHistoryXP. Then it flags devices and USB drives that are new
    since the last check, prints a summary and the assistant's fix order,
    and saves a transcript, an HTML report and a snapshot to ReportDir.
    Read-only: it changes no settings.
.PARAMETER ActiveScan
    Ping-sweep the subnet (slower). Only on networks you own or may scan.
.PARAMETER LogHours
    How far back to read the firewall log.
.PARAMETER ReportDir
    Folder for reports and snapshots. Default: My Documents\SecurityChecks.
.PARAMETER NoRouter
    Skip the router port and UPnP check.
.PARAMETER NoReport
    Save nothing (no transcript, report or snapshot).
.PARAMETER PassThru
    Also return every finding.
.EXAMPLE
    Invoke-XPSecurityCheck
.EXAMPLE
    Invoke-XPSecurityCheck -ActiveScan -LogHours 72
#>
    [CmdletBinding()]
    param(
        [switch]$ActiveScan,
        [ValidateRange(1, 720)][int]$LogHours = 24,
        [string]$ReportDir,
        [switch]$NoRouter,
        [switch]$NoReport,
        [switch]$PassThru
    )

    if (-not $ReportDir) { $ReportDir = Get-DefaultReportDir }
    # .NET file APIs resolve relative paths against the process folder, not
    # the PowerShell location, so make the path absolute first.
    $ReportDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportDir)
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $prev = $null
    $transcribing = $false
    if (-not $NoReport) {
        if (-not (Test-Path -LiteralPath $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir | Out-Null }
        $last = @(Get-ChildItem -Path $ReportDir -Filter 'Snapshot_*.xml' -ErrorAction SilentlyContinue | Sort-Object Name -Descending) | Select-Object -First 1
        if ($last) { try { $prev = Import-Clixml -Path $last.FullName } catch { $prev = $null } }
        try { Start-Transcript -Path (Join-Path $ReportDir ('Check_' + $stamp + '.txt')) | Out-Null; $transcribing = $true } catch { }
    }

    $all = @()
    $extra = @()
    $devices = @()
    $usb = @()
    $gwMac = ''
    try {
        Write-Host ('Security check - {0}' -f (Get-Date -Format 'dddd, MMMM d, yyyy h:mm tt')) -ForegroundColor Green
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
        $osText = ''
        if ($os) { $osText = ('{0} {1}' -f $os.Caption, $os.CSDVersion) }
        Write-Host ('Computer: {0}   User: {1}   {2}   PowerShell {3}' -f $env:COMPUTERNAME, $env:USERNAME, $osText, $PSVersionTable.PSVersion)
        if (-not (Test-IsAdmin)) {
            Write-Finding -Level 'Info' -Message 'Not an Administrator window: the firewall log and some settings may not be readable.'
        }

        $all += @(Get-XPHardeningStatus -PassThru)
        $acct = Get-AccountAuditXP -PassThru
        if ($acct) { $all += @($acct.Findings) }
        $health = Get-NetAdapterHealthXP -PassThru
        if ($health) { $all += @($health.Findings) }
        $log = Get-FirewallLogXP -Hours $LogHours -PassThru
        if ($log) { $all += @($log.Findings) }

        $devices = @(Find-NetworkDeviceXP -NoSweep:(-not $ActiveScan) -PassThru | Where-Object { $_ })
        $gw = @($devices | Where-Object { $_.Role -eq 'Gateway' }) | Select-Object -First 1
        if ($gw) { $gwMac = [string]$gw.MAC }
        Write-Section 'New devices'
        if ($prev -and $prev.GatewayMAC -and $gwMac -and ($prev.GatewayMAC -eq $gwMac)) {
            $known = @($prev.Devices | ForEach-Object { [string]$_.MAC })
            $new = @($devices | Where-Object { $_.MAC -and ($_.Role -ne 'This PC') -and (-not ($known -contains [string]$_.MAC)) })
            if ($new.Length -eq 0) {
                $extra += New-Finding -Area 'Devices' -Level 'OK' -Message ('No new devices on this network since the last check ({0}).' -f $prev.Date)
            }
            foreach ($d in $new) {
                $level = 'Warn'
                $why = ''
                if ($d.RandomMAC) { $level = 'Info'; $why = ' Randomized MAC: likely a phone or laptop.' }
                $who = (@($d.IPAddress, $d.MAC, $d.HostName) | Where-Object { $_ }) -join ' '
                $extra += New-Finding -Area 'Devices' -Level $level -Message ('New device since {0}: {1}.{2}' -f $prev.Date, $who, $why) -Fix 'If you do not recognize it, check the router''s client list'
            }
        } elseif ($gwMac) {
            $extra += New-Finding -Area 'Devices' -Level 'Info' -Message ('First check on this network (router MAC {0}); this device list is saved as the baseline.' -f $gwMac)
        } else {
            $extra += New-Finding -Area 'Devices' -Level 'Info' -Message 'No gateway found in the device list, so new devices cannot be compared.'
        }

        if (-not $NoRouter) {
            try {
                $router = Test-RouterExposureXP -PassThru
                if ($router) { $all += @($router.Findings) }
            } catch {
                $extra += New-Finding -Area 'Router' -Level 'Info' -Message ('Router check skipped: ' + $_.Exception.Message)
            }
        }

        $usbResult = Get-USBHistoryXP -PassThru
        if ($usbResult) { $usb = @($usbResult.Devices); $all += @($usbResult.Findings) }
        # Test for the property, not its value: an empty list is falsy, and
        # the first USB drive after an empty baseline must still be flagged.
        if ($prev -and $prev.PSObject.Properties['Usb']) {
            $knownSerials = @($prev.Usb | ForEach-Object { [string]$_.Serial })
            foreach ($u in @($usb | Where-Object { -not ($knownSerials -contains [string]$_.Serial) })) {
                $extra += New-Finding -Area 'USB' -Level 'Warn' -Message ('USB storage device connected since the last check ({0}): {1}, serial {2}.' -f $prev.Date, $u.Device, $u.Serial) -Fix 'If nobody you know plugged it in, find out who did'
            }
        }

        $all += $extra
        Save-RunFindings -Name 'Invoke-XPSecurityCheck' -Findings $extra

        $risk = @($all | Where-Object { $_.Level -eq 'Risk' })
        $warn = @($all | Where-Object { $_.Level -eq 'Warn' })
        Write-Section 'Overall summary'
        $color = 'Green'
        if ($warn.Length -gt 0) { $color = 'Yellow' }
        if ($risk.Length -gt 0) { $color = 'Red' }
        Write-Host ('  {0} risk(s), {1} warning(s), {2} finding(s) in total.' -f $risk.Length, $warn.Length, $all.Length) -ForegroundColor $color
        foreach ($f in @($risk + $warn)) {
            Write-Host ('  [{0,-4}] {1}: {2}' -f $f.Level, $f.Area, $f.Message) -ForegroundColor $(if ($f.Level -eq 'Risk') { 'Red' } else { 'Yellow' })
        }

        Write-Section 'What to fix first (assistant)'
        foreach ($step in @(Get-AssistantFixPlan -Findings $all)) { Write-Wrapped -Text $step -Indent 2 }
        Write-Host ''
        Write-Host '  Ask about any of it: Invoke-XPAssistant' -ForegroundColor DarkGray
    } finally {
        if ($transcribing) { try { Stop-Transcript | Out-Null } catch { } }
    }

    if (-not $NoReport) {
        # Keep every device seen on this network so far, not just this run:
        # XP ages ARP entries out within minutes, so an idle phone missing from
        # one run must not come back as "new" on the next.
        $baseline = @($devices | Select-Object IPAddress, MAC, HostName, RandomMAC)
        if ($prev -and $prev.GatewayMAC -and $gwMac -and ($prev.GatewayMAC -eq $gwMac)) {
            $seenMacs = @($baseline | ForEach-Object { [string]$_.MAC })
            foreach ($old in @($prev.Devices)) {
                if ($old -and $old.MAC -and (-not ($seenMacs -contains [string]$old.MAC))) {
                    $baseline += ($old | Select-Object IPAddress, MAC, HostName, RandomMAC)
                }
            }
        }
        $snap = New-Object PSObject -Property @{
            Date       = (Get-Date -Format 'yyyy-MM-dd HH:mm')
            Computer   = $env:COMPUTERNAME
            GatewayMAC = $gwMac
            Devices    = $baseline
            Usb        = @($usb | Select-Object Device, Serial)
        }
        $snapFile = Join-Path $ReportDir ('Snapshot_' + $stamp + '.xml')
        $htmlFile = Join-Path $ReportDir ('Report_' + $stamp + '.html')
        $snap | Export-Clixml -Path $snapFile
        $notes = @(('Computer {0}, {1}.' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')))
        Export-FindingsHtml -Findings $all -Path $htmlFile -Title ('XP security check ' + $stamp) -Notes $notes -Plan @(Get-AssistantFixPlan -Findings $all)
        Write-Host ''
        Write-Host ('  Saved to {0}' -f $ReportDir) -ForegroundColor Green
        Write-Host ('    Report_{0}.html (open in a browser), Check_{0}.txt, Snapshot_{0}.xml' -f $stamp) -ForegroundColor Green
    }

    if ($PassThru) { $all }
}

#endregion

#region Assistant knowledge base

# Offline notes for Invoke-XPAssistant. Each topic is matched by its Words:
# words of 4 characters or fewer must match a whole word, longer ones match
# anywhere, and phrases (with a space) count the most. Keep this ASCII.
$script:AssistantKB = @(
    @{ Id = 'commands'; Title = 'What this toolkit can do'
       Words = @('commands', 'what can you do', 'toolkit', 'functions', 'cmdlets')
       Text = 'Checks: Get-XPHardeningStatus (baseline), Get-AccountAuditXP (accounts and logon), Get-FirewallAuditXP (every firewall exception), Get-FirewallLogXP (what was blocked), Get-NetAdapterHealthXP (adapters and connectivity), Find-NetworkDeviceXP (devices on the subnet), Test-RouterExposureXP (router ports and UPnP), Get-USBHistoryXP (USB drives ever used). Invoke-XPSecurityCheck runs them all and saves a report. Changes: Set-XPHardening (preview with -WhatIf). Help on any of them: Get-Help <name> -Full'
       Do = 'Invoke-XPSecurityCheck' },
    @{ Id = 'firewall'; Title = 'Windows Firewall on XP'
       Words = @('firewall', 'sharedaccess', 'opmode', 'program exception', 'allow exceptions', 'exceptions are allowed', 'icmp', 'inbound ping')
       Text = 'XP SP2 and SP3 have an inbound-only firewall run by the SharedAccess service (Windows Firewall/ICS). It drops unsolicited inbound connections but does not filter outbound traffic, so it will not stop malware already on the PC from calling out. It has two profiles: Domain (used only when the PC is joined to a domain) and Standard (everything else). "Don''t allow exceptions" makes it ignore every exception, which is the safest setting for a PC that shares nothing. Allowing inbound ping is low risk but tells scanners the PC is there.'
       Do = 'Get-FirewallAuditXP lists every exception; Set-XPHardening turns the firewall on with no exceptions.' },
    @{ Id = 'firewalllog'; Title = 'Firewall logging and pfirewall.log'
       Words = @('pfirewall', 'firewall log', 'logging', 'dropped', 'blocked', 'blocked traffic', 'port scan', 'drops')
       Text = 'With dropped-packet logging on, the XP firewall writes every blocked connection to pfirewall.log in the Windows folder (4 MB by default, then it rolls over to pfirewall.log.old). Get-FirewallLogXP summarizes it: how much was blocked, which addresses tried to reach this PC directly, likely port scans (one source trying 10 or more ports) and traffic from outside your subnet. Blocked traffic from a public internet address that reached this PC usually means the router forwards a port to it or puts it in a DMZ.'
       Do = 'Get-FirewallLogXP -Hours 72 (from an Administrator window if the log cannot be read)' },
    @{ Id = 'smb'; Title = 'SMB file sharing and port 445'
       Words = @('smb', 'smbv1', '445', 'file sharing', 'file and printer', 'shares', 'share', 'server service', 'lanmanserver', 'smbdeviceenabled')
       Text = 'SMB is Windows file and printer sharing. XP''s Server service (lanmanserver) answers on TCP 445 and, through NetBIOS, on TCP 139. SMBv1 on XP is what Conficker (MS08-067) and WannaCry (MS17-010) attacked. If this PC does not share files or printers, turn the Server service off and set SMBDeviceEnabled = 0, which closes 445 after a reboot. If you need file sharing, keep those steps with -Skip Server,SmbDevice,NetBIOS,FileAndPrint and limit the share to your local subnet.'
       Do = 'Set-XPHardening (Server, SmbDevice and FileAndPrint steps), then reboot' },
    @{ Id = 'netbios'; Title = 'NetBIOS over TCP/IP (ports 137-139)'
       Words = @('netbios', 'netbios over tcp', '137', '138', '139', 'nbt', 'nbtstat', 'wins', 'computer browser', 'browser service')
       Text = 'NetBIOS over TCP/IP (NetBT) is the old Windows naming and browsing system. It uses UDP 137 (names), UDP 138 (datagrams) and TCP 139 (sessions), and broadcasts this PC''s name and workgroup to the whole network. Modern networks use DNS instead. Turning it off on every adapter closes 137-139 and stops the broadcasts; the Computer Browser service depends on it, so that is turned off too. The toolkit also sets it on disabled and unplugged adapters, so it stays off when they come back.'
       Do = 'Set-XPHardening (NetBIOS and Server steps). Check with: nbtstat -n' },
    @{ Id = 'ms08067'; Title = 'MS08-067 (Conficker)'
       Words = @('ms08-067', 'conficker', 'netapi32', 'kb958644')
       Text = 'MS08-067 (KB958644, October 2008) fixed a flaw in the Server service (netapi32.dll) that let anyone on the network run code on XP without logging on, over SMB. The Conficker worm used it to infect millions of PCs. The toolkit checks that netapi32.dll is 5.1.2600.5694 or later, so later updates that replaced the file count too.'
       Do = 'Legacy Update (legacyupdate.net) installs it; turning off the Server service also blocks it.' },
    @{ Id = 'ms17010'; Title = 'MS17-010 (EternalBlue / WannaCry)'
       Words = @('ms17-010', 'wannacry', 'eternalblue', 'notpetya', 'srv.sys', 'kb4012598')
       Text = 'MS17-010 fixed the SMBv1 flaws (EternalBlue) that WannaCry and NotPetya spread through in 2017. Microsoft released an emergency XP fix, KB4012598, in May 2017 even though XP support had ended. The toolkit checks that srv.sys is 5.1.2600.7208 or later. Turning off SMB (Server service and port 445) also removes what it attacks.'
       Do = 'KB4012598 from the Microsoft Update Catalog, or Legacy Update' },
    @{ Id = 'bluekeep'; Title = 'BlueKeep (CVE-2019-0708)'
       Words = @('bluekeep', 'cve-2019-0708', 'termdd', 'kb4500331')
       Text = 'BlueKeep is a flaw in Remote Desktop that lets an attacker run code before logging on, and it can spread like a worm. Microsoft released KB4500331 for XP in May 2019; it is offered through the Microsoft Update Catalog, not Windows Update. The toolkit checks that termdd.sys is 5.1.2600.7701 or later. Keeping Remote Desktop off and its firewall exception closed also blocks it.'
       Do = 'KB4500331 (WindowsXP-KB4500331-x86-Custom-ENU.exe) from the Microsoft Update Catalog' },
    @{ Id = 'rdp'; Title = 'Remote Desktop (port 3389)'
       Words = @('remote desktop', 'rdp', '3389', 'terminal services', 'mstsc')
       Text = 'Remote Desktop lets someone log on to this PC over the network on TCP 3389. XP Professional includes the server; XP Home does not. If you do not use it, keep it off: System Properties > Remote > untick "Allow users to connect remotely". Set-XPHardening closes its firewall exception. If you need it, allow it from your local subnet only and make sure the BlueKeep fix (KB4500331) is installed.'
       Do = 'Set-XPHardening (RemoteDesktop step), or -Skip RemoteDesktop to keep it' },
    @{ Id = 'remoteassist'; Title = 'Remote Assistance'
       Words = @('remote assistance', 'sessmgr', 'fallowtogethelp', 'helpassistant', 'support_388945a0', 'support account')
       Text = 'Remote Assistance lets someone you invite view or control your desktop, using the HelpAssistant account and sessmgr.exe. Few people use it on XP today, and its firewall exception opens the PC to the network. Set-XPHardening sets fAllowToGetHelp = 0 and disables the sessmgr.exe firewall exception. The HelpAssistant and SUPPORT_388945a0 accounts should stay disabled.'
       Do = 'Set-XPHardening (RemoteAssistance step)' },
    @{ Id = 'rpc'; Title = 'RPC (port 135) and Remote Administration'
       Words = @('rpc', '135', 'dcom', 'remote administration', 'remoteadmin', 'endpoint mapper')
       Text = 'RPC listens on TCP 135 and Windows itself depends on it, so XP cannot turn it off; the firewall is what protects it (the Blaster worm used an RPC flaw in 2003). The Remote Administration exception opens RPC/DCOM and port 445 to the network for remote admin tools, so keep it disabled unless a domain admin tool needs it.'
       Do = 'Set-XPHardening (RemoteAdmin step)' },
    @{ Id = 'routerupnp'; Title = 'UPnP on the router'
       Words = @('upnp discovery', 'answers upnp', 'router upnp', 'port forward', 'port forwarding', 'igd', 'internet gateway', 'dmz')
       Text = 'When the router answers UPnP discovery, any program on any device on your network can ask it to open ports to the internet, with no password. Malware uses this to expose PCs. Turn UPnP off in the router admin page unless a game console or app really needs it. Also check the router for port forwards or a DMZ host pointing at this PC.'
       Do = 'Test-RouterExposureXP' },
    @{ Id = 'router'; Title = 'Router exposure'
       Words = @('router', 'router port', 'admin page', 'web admin', 'shieldsup', 'tr-069', '7547', 'pptp', 'firmware')
       Text = 'Test-RouterExposureXP connects to the router''s common TCP ports from inside your network. Telnet (23), FTP (21), PPTP (1723) and TR-069 (7547) should normally be off. An admin page on HTTP only (port 80) means the router password crosses the network unencrypted. This is the inside view only; to see what the internet sees, run GRC ShieldsUP from a modern PC or phone on this network. Keep the router firmware up to date; it guards everything behind it, including this XP PC.'
       Do = 'Test-RouterExposureXP' },
    @{ Id = 'upnp'; Title = 'UPnP services on XP (ports 1900 and 2869)'
       Words = @('upnp', 'ssdp', '1900', '2869', 'upnphost', 'ssdpsrv', 'upnp framework', 'plug and play')
       Text = 'UPnP on XP is two services: SSDP Discovery (UDP 1900) finds devices, and UPnP Device Host (TCP 2869) lets this PC act as a UPnP device. Both answer on the network, and XP''s UPnP had a remote code flaw (MS01-059). Most XP PCs never need them. Set-XPHardening stops and disables both and closes the UPnP Framework firewall exception.'
       Do = 'Set-XPHardening (UPnP and UPnPException steps)' },
    @{ Id = 'msmq'; Title = 'Message Queuing (MSMQ)'
       Words = @('msmq', 'message queuing', '1801')
       Text = 'Message Queuing is an optional Windows component that listens on TCP 1801 and RPC ports 2103-2107. It is rarely installed on home XP PCs, and it has had remote code flaws (MS05-017). Set-XPHardening stops and disables it if it is there.'
       Do = 'Set-XPHardening (MSMQ step)' },
    @{ Id = 'simptcp'; Title = 'Simple TCP/IP Services'
       Words = @('simptcp', 'simple tcp', 'chargen', 'echo service', 'quote of the day', 'daytime')
       Text = 'Simple TCP/IP Services is an optional component that runs the old echo (7), discard (9), daytime (13), quote of the day (17) and chargen (19) services. Nothing modern uses them, and echo and chargen can be abused to flood a network. Set-XPHardening stops and disables the service.'
       Do = 'Set-XPHardening (SimpleTcp step)' },
    @{ Id = 'remotereg'; Title = 'Remote Registry'
       Words = @('remote registry', 'remoteregistry')
       Text = 'Remote Registry lets other computers read and change this PC''s registry over the network (with an admin password). A home PC does not need it, and attackers who get one password use it to spread. Set-XPHardening stops and disables it.'
       Do = 'Set-XPHardening (RemoteRegistry step)' },
    @{ Id = 'messenger'; Title = 'Messenger service'
       Words = @('messenger', 'net send', 'pop-up', 'popup')
       Text = 'The Messenger service (not MSN or Windows Messenger) shows "net send" pop-ups sent over the network. Spammers used it for pop-up ads, and it had a remote code flaw (MS03-043). XP SP2 already disables it; Set-XPHardening makes sure.'
       Do = 'Set-XPHardening (Messenger step)' },
    @{ Id = 'telnet'; Title = 'Telnet server'
       Words = @('telnet', 'tlntsvr', '23')
       Text = 'The Telnet server (TlntSvr) gives a command prompt over the network on TCP 23 with no encryption, so passwords cross the network in plain text. XP Professional includes it. Set-XPHardening disables it. If you need remote access, use something encrypted instead.'
       Do = 'Set-XPHardening (Telnet step)' },
    @{ Id = 'guest'; Title = 'The Guest account'
       Words = @('guest', 'visitor', 'forceguest', 'simple file sharing')
       Text = 'The Guest account lets anyone log on without a password. With XP''s Simple File Sharing, network users are mapped to Guest, so an enabled Guest account also opens shared folders to anyone on the network. The toolkit finds Guest by its SID (ending in -501), so a renamed Guest is still covered.'
       Do = 'Set-XPHardening (Guest step)' },
    @{ Id = 'autorun'; Title = 'AutoRun'
       Words = @('autorun', 'autoplay', 'autorun.inf', 'nodrivetypeautorun', 'kb967715')
       Text = 'AutoRun starts the program listed in autorun.inf when a CD or USB drive is inserted. Worms such as Conficker spread between PCs on USB drives this way. Set-XPHardening sets NoDriveTypeAutoRun = 0xFF (all drive types). On XP that setting only fully works with KB967715 installed, which the status check looks for.'
       Do = 'Set-XPHardening (AutoRun step)' },
    @{ Id = 'anonymous'; Title = 'Anonymous (null session) access'
       Words = @('restrictanonymous', 'null session', 'anonymous', 'ipc$', 'enum4linux')
       Text = 'XP allows "null sessions": an anonymous network user can connect to IPC$ and ask the PC about itself. RestrictAnonymous = 1 blocks anonymous listing of shares and accounts, and RestrictAnonymousSAM = 1 (already the XP default) blocks listing of accounts. Attackers and tools like enum4linux use null sessions to find user names to guess. The change applies after a reboot.'
       Do = 'Set-XPHardening (RestrictAnonymous step), then reboot' },
    @{ Id = 'lmhash'; Title = 'LM password hashes'
       Words = @('lm hash', 'lm password', 'nolmhash', 'lanman', 'password hash', 'hashes')
       Text = 'XP stores two hashes of each password. The LM hash uppercases the password and splits it into two 7-character halves, so it can be cracked in seconds. NoLMHash = 1 stops Windows storing new LM hashes; the old ones go away the next time each password is changed. Passwords of 15 characters or more never get an LM hash at all.'
       Do = 'Set-XPHardening (NoLMHash step), then change your password' },
    @{ Id = 'ntlm'; Title = 'NTLMv2 and LmCompatibilityLevel'
       Words = @('ntlm', 'ntlmv1', 'ntlmv2', 'lmcompatibilitylevel', 'lm/ntlmv1')
       Text = 'When XP logs on to another computer it proves the password with an LM, NTLMv1 or NTLMv2 response. LM and NTLMv1 responses are easy to capture and crack or relay. LmCompatibilityLevel = 3 makes XP send NTLMv2 only (the XP default is 0). Windows 2000 and later and modern Samba all accept NTLMv2. Skip this step only if the PC must reach Windows 9x or a very old NAS.'
       Do = 'Set-XPHardening (NTLMv2 step), or -Skip NTLMv2' },
    @{ Id = 'policy'; Title = 'Password length and account lockout'
       Words = @('password policy', 'password length', 'lockout', 'net accounts', 'minpwlen', 'guess')
       Text = 'XP''s default policy has no minimum password length and no lockout, so short passwords are allowed and guessing is unlimited. Set-XPHardening sets a minimum of 8 characters (it applies at the next password change) and locks an account for 30 minutes after 10 bad tries. The built-in Administrator account is never locked out, so give it a strong password.'
       Do = 'Set-XPHardening (PasswordPolicy step). Check with: net accounts' },
    @{ Id = 'blankpw'; Title = 'Blank passwords'
       Words = @('blank password', 'blank-password', 'passwordrequired', 'passwordreq', 'no password', 'limitblankpassworduse')
       Text = 'An account with PasswordRequired = False is allowed to have a blank password. XP''s User Accounts control panel creates accounts this way, so it does not always mean the password is blank right now. While LimitBlankPasswordUse = 1 (the XP default), blank-password accounts can only log on at the keyboard, not over the network; if it is 0, anyone on the network can use them.'
       Do = 'net user "name" /passwordreq:yes, then give the account a password' },
    @{ Id = 'admin'; Title = 'Administrator accounts'
       Words = @('administrator', 'administrators', 'admin account', 'limited account', 'least privilege')
       Text = 'On XP most people use an administrator account every day, so any program they run, malware included, gets full control. A limited account for daily use and a separate admin account for installs limits the damage. Keep the number of admin accounts small, and give the built-in Administrator (hidden on the Welcome screen) a strong password.'
       Do = 'Get-AccountAuditXP; Control Panel > User Accounts to change an account type' },
    @{ Id = 'autologon'; Title = 'Automatic logon'
       Words = @('automatic logon', 'auto logon', 'autologon', 'autoadminlogon', 'defaultpassword', 'auto login')
       Text = 'Automatic logon (AutoAdminLogon = 1) skips the password at startup, so anyone who turns the PC on gets your desktop. If the password was typed into the registry value DefaultPassword, anyone who can read the registry can read it in plain text. Turn it off in control userpasswords2 by ticking "Users must enter a user name and password to use this computer", and delete DefaultPassword.'
       Do = 'Get-AccountAuditXP shows the exact fix command' },
    @{ Id = 'screensaver'; Title = 'Screen saver lock'
       Words = @('screen saver', 'screensaver', 'lock screen', 'lock the pc', 'walk away')
       Text = 'A password-protected screen saver locks the PC when you walk away. Display Properties > Screen Saver > tick "On resume, password protect" (with Fast User Switching on it says "On resume, display Welcome screen"). Windows key + L locks the PC right away.'
       Do = 'Display Properties > Screen Saver' },
    @{ Id = 'dep'; Title = 'Data Execution Prevention (DEP)'
       Words = @('dep', 'data execution', 'noexecute', 'optin', 'optout', 'nx', 'boot.ini')
       Text = 'DEP stops code from running in memory that is marked as data, which blocks many buffer-overflow exploits. XP SP2 and later default to OptIn, which protects only Windows'' own programs. OptOut protects every program except ones you exclude. Change it in System Properties > Advanced > Performance Settings > Data Execution Prevention, or set /noexecute=optout in boot.ini, then reboot. Hardware DEP needs a CPU with NX/XD support; most CPUs from 2005 on have it.'
       Do = 'System Properties > Advanced > Performance > Settings > Data Execution Prevention' },
    @{ Id = 'patches'; Title = 'Patches and updates on XP'
       Words = @('patch', 'patches', 'patched', 'update', 'updates', 'legacy update', 'posready', 'windows update', 'hotfix', 'kb')
       Text = 'XP''s last regular security updates came out in April 2014, with a few emergency fixes after that (WannaCry in 2017, BlueKeep in 2019). Legacy Update (legacyupdate.net) can still install the XP updates Microsoft published. The toolkit checks the three wormable flaws by file version, because later updates replace the original KBs. Even fully patched, XP has years of unfixed flaws, so it should not be used on the internet.'
       Do = 'Get-XPHardeningStatus (Patches section)' },
    @{ Id = 'internet'; Title = 'Is XP safe online?'
       Words = @('internet', 'online', 'safe', 'web browsing', 'email', 'antivirus', 'virus', 'malware', 'security essentials')
       Text = 'XP should not be used on the open internet. It gets no security updates, its browsers cannot load most modern HTTPS sites safely, and antivirus makers dropped it years ago (Microsoft Security Essentials stopped updating on XP in 2015). Use it offline, on a host-only or isolated VM network, or behind a router with no port forwards, and copy files in from a modern PC that has scanned them first.'
       Do = 'Keep it off untrusted networks; Invoke-XPSecurityCheck after any change' },
    @{ Id = 'apipa'; Title = 'APIPA (169.254.x.x) and DHCP'
       Words = @('apipa', '169.254', 'dhcp', 'ipconfig', 'no ip')
       Text = 'An address starting with 169.254 (APIPA) means the adapter asked for an address by DHCP, got no answer, and picked one itself, so it can only talk to other APIPA devices. Check the cable or Wi-Fi, then run ipconfig /release and ipconfig /renew. In a VMware VM, check the VM''s network setting (NAT, bridged or host-only) and that the VMware DHCP service is running on the host.'
       Do = 'ipconfig /release, then ipconfig /renew' },
    @{ Id = 'connectivity'; Title = 'Gateway, DNS and connectivity'
       Words = @('gateway', 'dns', 'dns lookup', 'ping', '8.8.8.8', 'connectivity', 'no internet', 'latency')
       Text = 'Get-NetAdapterHealthXP pings the default gateway (your router), pings 8.8.8.8 (the internet) and does a DNS lookup. If the gateway fails, the problem is the local link. If the gateway works but 8.8.8.8 fails, the problem is the router or the internet connection. If both pings work but DNS fails, check the DNS servers in the adapter''s TCP/IP settings. A VM on a host-only network is expected to fail the internet tests.'
       Do = 'Get-NetAdapterHealthXP' },
    @{ Id = 'devices'; Title = 'Devices on the network, ARP and MAC addresses'
       Words = @('arp', 'device', 'devices', 'new device', 'sweep', 'random mac', 'randomized', 'mac address', 'mac')
       Text = 'Find-NetworkDeviceXP pings every address on your subnet and reads the ARP cache (arp -a), which maps IP addresses to MAC addresses. Devices that block ping still show up if they answered ARP. A randomized MAC (the locally administered bit is set) usually means a phone or laptop using a private Wi-Fi address. Invoke-XPSecurityCheck saves the list and flags devices that are new since the last check on the same network. Only scan networks you own or are allowed to scan.'
       Do = 'Find-NetworkDeviceXP -ResolveNames' },
    @{ Id = 'usb'; Title = 'USB storage history'
       Words = @('usb', 'usbstor', 'flash drive', 'thumb drive', 'usb storage', 'serial')
       Text = 'Windows keeps a record of every USB storage device ever connected, with its model and serial number, under HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR. Get-USBHistoryXP lists them, and Invoke-XPSecurityCheck flags ones that are new since the last check. A drive you do not recognize means someone plugged it in. Setting the USBSTOR service Start value to 4 blocks USB storage entirely.'
       Do = 'Get-USBHistoryXP' },
    @{ Id = 'ports'; Title = 'Listening ports'
       Words = @('listening', 'netstat', 'open port', 'open ports', 'ports', 'port')
       Text = 'A listening port is a program waiting for network connections. netstat -ano lists them with the process ID (PID); match the PID with tasklist /svc or in Task Manager (View > Select Columns > PID). Port 135 (RPC) always listens on XP. Ports bound to 127.0.0.1 are only reachable from this PC; ones on 0.0.0.0 or a real address are reachable from the network unless the firewall blocks them.'
       Do = 'netstat -ano, then tasklist /svc' },
    @{ Id = 'undo'; Title = 'Undoing a hardening step'
       Words = @('undo', 'revert', 'turn back on', 're-enable', 'reenable', 'restore', 'broke', 'broken', 'stopped working')
       Text = 'Set-XPHardening has no automatic undo, which is why -WhatIf and a VM snapshot first are a good idea. To turn one thing back on: file sharing: sc config lanmanserver start= auto, then net start lanmanserver. Port 445: delete SMBDeviceEnabled under HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters and reboot. NetBIOS: adapter Properties > TCP/IP > Advanced > WINS > Default. Firewall exceptions: netsh firewall set opmode mode=ENABLE exceptions=ENABLE. NTLMv2: set LmCompatibilityLevel back to 0. Next time use -Skip for the steps you need to keep.'
       Do = 'Set-XPHardening -WhatIf before the real run' },
    @{ Id = 'whatif'; Title = '-WhatIf and -Skip'
       Words = @('whatif', 'preview', 'dry run', 'skip', 'step names', 'steps')
       Text = '-WhatIf shows every step Set-XPHardening would take without changing anything. -Skip leaves named steps alone, for example: Set-XPHardening -Skip RemoteDesktop. The steps are: Firewall, Logging, FileAndPrint, RemoteDesktop, RemoteAdmin, UPnPException, RemoteAssistance, MSMQ, UPnP, SimpleTcp, Server, SmbDevice, NetBIOS, RemoteRegistry, Messenger, Telnet, Guest, RestrictAnonymous, NoLMHash, NTLMv2, PasswordPolicy, AutoRun.'
       Do = 'Set-XPHardening -WhatIf' },
    @{ Id = 'daily'; Title = 'The all-in-one check and its reports'
       Words = @('daily', 'daily check', 'security check', 'report', 'reports', 'invoke-xpsecuritycheck', 'baseline')
       Text = 'Invoke-XPSecurityCheck runs every check in one go: hardening status, accounts, adapters, the firewall log, devices on the network, the router and USB history. It saves a text transcript, an HTML report and a snapshot to My Documents\SecurityChecks. The snapshot is how the next run spots new devices and USB drives. Add -ActiveScan to ping-sweep the subnet as well.'
       Do = 'Invoke-XPSecurityCheck' },
    @{ Id = 'assistant'; Title = 'This assistant and Claude mode'
       Words = @('assistant', 'claude', 'relay', 'api key', 'ai', 'offline mode', 'claude mode')
       Text = 'This assistant has two modes. Offline (the default) uses notes built into the module and sends nothing anywhere. Claude mode sends your question and the loaded findings to Claude through a relay script on a modern PC, because XP cannot make the TLS 1.2 connections the Claude API needs. The API key stays on that PC; XP only gets a relay token. Setup: run relay\Start-ClaudeRelay.ps1 on the host (PowerShell 7), then on XP run Set-XPAssistantConfig -RelayUrl <address> -RelayToken <token> -Test.'
       Do = 'Set-XPAssistantConfig -RelayUrl http://<host>:8787 -RelayToken <token> -Test' },
    @{ Id = 'vm'; Title = 'Testing in a VM'
       Words = @('vmware', 'virtual machine', 'vm', 'host-only', 'vmnet', 'snapshot')
       Text = 'On a VM, take a snapshot before Set-XPHardening so any change can be undone in seconds. A host-only network (VMnet1 in VMware) keeps XP off the internet but still lets it reach the host, which is where the Claude relay runs. NAT (VMnet8) gives XP internet access through the host. The toolkit''s own snapshots (Invoke-XPSecurityCheck) are different: they are saved device and USB lists.'
       Do = 'Take a VM snapshot, then Set-XPHardening -WhatIf' }
)

#endregion

#region Assistant

function Write-Wrapped {
    # Prints text that fits the console: short lines as they are, long lines
    # word-wrapped with the same leading indent.
    param([string]$Text, [int]$Indent = 2, [string]$Color = 'Gray')
    $width = (Get-ConsoleWidth) - $Indent
    if ($width -gt 100) { $width = 100 }
    if ($width -lt 30) { $width = 30 }
    $pad = ' ' * $Indent
    foreach ($para in ([string]$Text -split "`r?`n")) {
        if ($para.Length -le $width) { Write-Host ($pad + $para) -ForegroundColor $Color; continue }
        $lead = ''
        if ($para -match '^(\s+)') { $lead = $matches[1] }
        $line = ''
        foreach ($word in ($para.Trim() -split '\s+')) {
            if ($line.Length -eq 0) { $line = $lead + $word }
            elseif (($line.Length + 1 + $word.Length) -le $width) { $line += ' ' + $word }
            else {
                Write-Host ($pad + $line) -ForegroundColor $Color
                $line = $lead + '   ' + $word
            }
        }
        if ($line) { Write-Host ($pad + $line) -ForegroundColor $Color }
    }
}

function ConvertTo-AssistantKeyText {
    # Lowercase, punctuation to spaces, padded so whole words can be matched
    # as ' word '.
    param([string]$Text)
    $t = ' ' + (([string]$Text).ToLower() -replace '[^a-z0-9_\.\-\$/]', ' ') + ' '
    $t = $t -replace '[\.\-/]+(?=\s)', ' '
    return ($t -replace '\s+', ' ')
}

function Get-AssistantTopic {
    # Knowledge-base topics that match the text, best first.
    param([string]$Text)
    $t = ConvertTo-AssistantKeyText $Text
    $scored = @()
    $i = 0
    foreach ($topic in $script:AssistantKB) {
        $score = 0
        foreach ($w in $topic.Words) {
            if ($w.IndexOf(' ') -ge 0) { if ($t.Contains($w)) { $score += 3 } }
            elseif ($w.Length -le 4) { if ($t.Contains(' ' + $w + ' ')) { $score += 1 } }
            elseif ($t.Contains($w)) { $score += 2 }
        }
        if ($score -gt 0) { $scored += New-Object PSObject -Property @{ Topic = $topic; Score = $score; Order = $i } }
        $i++
    }
    $scored | Sort-Object @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.Order }; Ascending = $true } |
        ForEach-Object { $_.Topic }
}

function Get-AssistantIssueList {
    # Non-OK findings in a stable order (Risk, Warn, Info): what "list" shows
    # and what "explain <n>" numbers.
    param($Findings)
    $rank = @{ 'Risk' = 0; 'Warn' = 1; 'Info' = 2 }
    $i = 0
    $tagged = @()
    foreach ($f in @($Findings)) {
        if ($f -and ($f.Level -ne 'OK')) {
            $tagged += New-Object PSObject -Property @{ F = $f; R = $rank[[string]$f.Level]; I = $i }
        }
        $i++
    }
    $tagged | Sort-Object R, I | ForEach-Object { $_.F }
}

function Format-PlanStep {
    param($Finding)
    $fix = [string]$Finding.Fix
    if (-not $fix) {
        $topic = @(Get-AssistantTopic ($Finding.Area + ' ' + $Finding.Message)) | Select-Object -First 1
        if ($topic) { $fix = $topic.Do }
    }
    $text = '[{0}] {1}' -f $Finding.Level, $Finding.Message
    if ($fix) { $text += "`n     Fix: " + $fix }
    return $text
}

function Get-AssistantFixPlan {
    # Turns findings into an ordered to-do list: risks that need their own
    # fix first, then one Set-XPHardening run for everything it covers, then
    # the remaining warnings (one step per distinct fix).
    param($Findings)
    $todo = @($Findings | Where-Object { $_ -and (($_.Level -eq 'Risk') -or ($_.Level -eq 'Warn')) })
    if ($todo.Length -eq 0) {
        return @('Nothing to fix: no risks or warnings in the loaded findings. Keep XP off the internet and untrusted Wi-Fi, and re-check after any change.')
    }
    $hard = @($todo | Where-Object { [string]$_.Fix -like 'Set-XPHardening*' })
    $rest = @($todo | Where-Object { [string]$_.Fix -notlike 'Set-XPHardening*' })
    $steps = @()
    $seen = @{}
    foreach ($f in @($rest | Where-Object { $_.Level -eq 'Risk' })) {
        $key = [string]$f.Fix
        if ($key -and $seen.ContainsKey($key)) { continue }
        if ($key) { $seen[$key] = $true }
        $steps += (Format-PlanStep $f)
    }
    if ($hard.Length -gt 0) {
        $examples = @($hard | Select-Object -First 4 | ForEach-Object { ([string]$_.Message).TrimEnd('.') }) -join '; '
        $more = ''
        if ($hard.Length -gt 4) { $more = ' and {0} more' -f ($hard.Length - 4) }
        $txt = 'Run Set-XPHardening -WhatIf to preview, then Set-XPHardening in an Administrator window. It fixes {0} item(s): {1}{2}.' -f $hard.Length, $examples, $more
        if (@($hard | Where-Object { [string]$_.Fix -like '*reboot*' }).Length -gt 0) { $txt += ' Reboot afterwards.' }
        $txt += ' Add -Skip for anything you still use (-Skip Server,SmbDevice,NetBIOS,FileAndPrint keeps file sharing).'
        $steps += $txt
    }
    foreach ($f in @($rest | Where-Object { $_.Level -ne 'Risk' })) {
        $key = [string]$f.Fix
        if ($key -and $seen.ContainsKey($key)) { continue }
        if ($key) { $seen[$key] = $true }
        $steps += (Format-PlanStep $f)
    }
    $steps += 'Then run Get-XPHardeningStatus (or Invoke-XPSecurityCheck) again to confirm.'
    $out = @()
    for ($n = 0; $n -lt $steps.Length; $n++) { $out += ('{0}. {1}' -f ($n + 1), $steps[$n]) }
    return $out
}

function Get-AssistantSummary {
    param($State)
    $f = @($State.Findings)
    if ($f.Length -eq 0) {
        return 'No findings loaded yet. Type scan to run Get-XPHardeningStatus and Get-AccountAuditXP, or run any check (for example Invoke-XPSecurityCheck) and start the assistant again.'
    }
    $risk = @($f | Where-Object { $_.Level -eq 'Risk' })
    $warn = @($f | Where-Object { $_.Level -eq 'Warn' })
    $info = @($f | Where-Object { $_.Level -eq 'Info' }).Length
    $ok = @($f | Where-Object { $_.Level -eq 'OK' }).Length
    $lines = @(('Loaded {0} findings from {1}: {2} risk(s), {3} warning(s), {4} info, {5} OK.' -f $f.Length, (@($State.Sources) -join ', '), $risk.Length, $warn.Length, $info, $ok))
    if ($risk.Length -gt 0) {
        $lines += 'Fix the risks first (type plan for the order):'
        foreach ($r in @($risk | Select-Object -First 5)) { $lines += ('  - ' + $r.Message) }
    } elseif ($warn.Length -gt 0) {
        $lines += ('No risks, but {0} warning(s) to review. Type plan for the order, or list to see them.' -f $warn.Length)
    } else {
        $lines += 'This PC matches the hardening baseline in everything that was checked.'
    }
    $lines += 'XP gets no security updates, so keep it off the internet and untrusted Wi-Fi either way.'
    return ($lines -join "`n")
}

function Get-AssistantTopicAnswer {
    param($Topic, $State)
    $lines = @($Topic.Title, $Topic.Text)
    if ($Topic.Do) { $lines += ('What to run: ' + $Topic.Do) }
    $mine = @()
    foreach ($f in @(Get-AssistantIssueList $State.Findings)) {
        $t = @(Get-AssistantTopic ($f.Area + ' ' + $f.Message)) | Select-Object -First 1
        if ($t -and ($t.Id -eq $Topic.Id)) { $mine += ('  [{0}] {1}' -f $f.Level, $f.Message) }
    }
    if ($mine.Length -gt 0) { $lines += 'On this PC:'; $lines += $mine }
    return ($lines -join "`n")
}

function Get-AssistantExplain {
    param($Finding, [int]$Number)
    $lines = @(('#{0} [{1}] {2}: {3}' -f $Number, $Finding.Level, $Finding.Area, $Finding.Message))
    $topic = @(Get-AssistantTopic ($Finding.Area + ' ' + $Finding.Message)) | Select-Object -First 1
    if ($topic) { $lines += ('What it means: ' + $topic.Text) }
    if ($Finding.Fix) { $lines += ('Fix: ' + $Finding.Fix) }
    elseif ($topic -and $topic.Do -and ($Finding.Level -ne 'Info')) { $lines += ('Fix: ' + $topic.Do) }
    else { $lines += 'No change needed: this is for information.' }
    return ($lines -join "`n")
}

function Get-AssistantHelp {
    return (@(
        'Commands:',
        '  scan          run Get-XPHardeningStatus and Get-AccountAuditXP and load the results',
        '  summary       how this PC is doing',
        '  plan          what to fix first, in order, with the commands',
        '  list          numbered list of the issues found',
        '  explain <n>   what issue <n> means and how to fix it',
        '  topics        everything the offline notes cover',
        '  mode claude   ask Claude through your relay (mode offline to switch back)',
        '  relay         test the connection to the relay',
        '  exit          leave the assistant',
        'Or just ask, for example: what is netbios / why turn off smb / how do I undo the hardening'
    ) -join "`n")
}

function Get-AssistantOfflineAnswer {
    param($State, [string]$Question)
    $l = $Question.ToLower()
    $topics = @(Get-AssistantTopic $Question)
    if (($topics.Length -eq 0) -or ($l -match 'fix first|first to fix|priorit|what should i (do|fix)')) {
        if ($l -match 'fix|first|priorit|what should i do') { return ((Get-AssistantFixPlan $State.Findings) -join "`n") }
        if ($l -match 'how am i|how is (my|this)|secure|status|doing') { return (Get-AssistantSummary $State) }
    }
    if ($topics.Length -eq 0) {
        $msg = 'That is not in my offline notes. Type topics to see what they cover, list for this PC''s issues, or plan for what to fix first.'
        if ($State.Mode -eq 'Claude') { $msg += ' (Claude could not be reached, so this answer is from the offline notes.)' }
        elseif ($State.Cfg.RelayUrl -and $State.Cfg.RelayToken) { $msg += ' Type mode claude to ask Claude instead.' }
        else { $msg += ' For open questions, set up Claude mode (ask: how do I use claude mode).' }
        return $msg
    }
    $ans = Get-AssistantTopicAnswer $topics[0] $State
    $related = @($topics | Select-Object -Skip 1 -First 2 | ForEach-Object { $_.Title })
    if ($related.Length -gt 0) { $ans += "`nRelated: " + ($related -join '; ') }
    return $ans
}

function Update-AssistantFindings {
    # Loads the findings each audit command saved on its last run.
    param($State)
    $all = @()
    $src = @()
    foreach ($k in @($script:LastRun.Keys | Sort-Object)) {
        $items = @($script:LastRun[$k])
        if ($items.Length -gt 0) { $all += $items; $src += $k }
    }
    $State.Findings = $all
    $State.Sources = $src
}

function Invoke-AssistantScan {
    param($State)
    Write-Host '  Running Get-XPHardeningStatus and Get-AccountAuditXP...' -ForegroundColor DarkGray
    $null = Get-XPHardeningStatus
    $null = Get-AccountAuditXP
    Update-AssistantFindings $State
}

function ConvertTo-JsonStringXP {
    # PS 2.0 has no ConvertTo-Json. Escapes a string as a JSON literal and
    # writes every non-ASCII character as \uXXXX, so the body is pure ASCII.
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in ([string]$Text).ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif (($code -lt 32) -or ($code -gt 126)) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Protect-AssistantText {
    # Masks MAC addresses, this PC's name and the user name before anything
    # is sent to the relay.
    param([string]$Text)
    $t = [string]$Text -replace '\b([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b', 'xx-xx-xx-xx-xx-xx'
    if ($env:COMPUTERNAME -and ($env:COMPUTERNAME.Length -ge 3)) { $t = $t -replace [regex]::Escape($env:COMPUTERNAME), '<PC-NAME>' }
    # Built-in names stay: masking "Administrator" would garble every finding.
    if ($env:USERNAME -and ($env:USERNAME.Length -ge 3) -and ($env:USERNAME -notmatch '^(Administrator|Admin|Owner|User|Guest)$')) {
        $t = $t -replace [regex]::Escape($env:USERNAME), '<USER>'
    }
    return $t
}

function Get-AssistantContext {
    # What Claude is told about this PC: OS and the loaded findings.
    param($State)
    $lines = @()
    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($os) { $lines += ('OS: {0} {1} (version {2})' -f $os.Caption, $os.CSDVersion, $os.Version) }
    $lines += ('PowerShell: {0}; NetSecToolkitXP {1}; Administrator window: {2}' -f $PSVersionTable.PSVersion, $script:ToolkitVersion, (Test-IsAdmin))
    $issues = @(Get-AssistantIssueList $State.Findings)
    $oks = @($State.Findings | Where-Object { $_ -and ($_.Level -eq 'OK') })
    $lines += ('Findings from: {0}' -f (@($State.Sources) -join ', '))
    $lines += 'Level | Area | Finding | Fix'
    # Issues come first and keep the numbers the user sees in "list".
    $n = 0
    foreach ($f in @($issues + $oks)) {
        $n++
        if ($n -gt 120) { break }
        $prefix = ''
        if ($n -le $issues.Length) { $prefix = '#' + $n + ' ' }
        $lines += ('{0}{1} | {2} | {3} | {4}' -f $prefix, $f.Level, $f.Area, $f.Message, $f.Fix)
    }
    $text = $lines -join "`n"
    if (-not $State.NoRedact) { $text = Protect-AssistantText $text }
    if ($text.Length -gt 24000) { $text = $text.Substring(0, 24000) }
    return $text
}

function Get-AssistantConfigPath {
    $base = $env:APPDATA
    if (-not $base) { $base = $env:TEMP }
    return (Join-Path (Join-Path $base 'NetSecToolkitXP') 'assistant.clixml')
}

function Get-AssistantConfig {
    # Saved settings (Set-XPAssistantConfig), overridden by the environment
    # variables NSTXP_RELAY_URL and NSTXP_RELAY_TOKEN.
    param([switch]$FileOnly)
    $cfg = @{ RelayUrl = $null; RelayToken = $null; DefaultMode = 'Offline' }
    $p = Get-AssistantConfigPath
    if (Test-Path -LiteralPath $p) {
        try {
            $saved = Import-Clixml -Path $p
            foreach ($k in @('RelayUrl', 'RelayToken', 'DefaultMode')) { if ($saved.$k) { $cfg[$k] = $saved.$k } }
        } catch { }
    }
    if (-not $FileOnly) {
        if ($env:NSTXP_RELAY_URL) { $cfg.RelayUrl = $env:NSTXP_RELAY_URL }
        if ($env:NSTXP_RELAY_TOKEN) { $cfg.RelayToken = $env:NSTXP_RELAY_TOKEN }
    }
    return $cfg
}

function Invoke-AssistantRelay {
    # Calls the relay over plain HTTP on the local network. Returns the reply
    # text, or throws with the relay's error message.
    param([string]$Url, [string]$Token, [string]$Path = '/ask', [string]$Body, [int]$TimeoutSec = 150)
    $uri = $Url.TrimEnd('/') + $Path
    try {
        $req = [System.Net.WebRequest]::Create($uri)
        $req.Timeout = $TimeoutSec * 1000
        $req.Proxy = $null
        # .NET 2.0 waits for a "100 Continue" the relay never sends.
        $req.ServicePoint.Expect100Continue = $false
        $req.Headers.Add('X-Relay-Token', $Token)
        if ($Body) {
            $req.Method = 'POST'
            $req.ContentType = 'application/json; charset=utf-8'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentLength = $bytes.Length
            $rs = $req.GetRequestStream()
            $rs.Write($bytes, 0, $bytes.Length)
            $rs.Close()
        } else {
            $req.Method = 'GET'
        }
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader -ArgumentList $resp.GetResponseStream(), ([System.Text.Encoding]::UTF8)
        $text = $sr.ReadToEnd()
        $sr.Close()
        $resp.Close()
        return $text
    } catch {
        $ex = $_.Exception
        while ($ex -and (-not ($ex -is [System.Net.WebException]))) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) {
            $msg = ''
            try {
                $er = New-Object System.IO.StreamReader -ArgumentList $ex.Response.GetResponseStream()
                $msg = $er.ReadToEnd().Trim()
                $er.Close()
            } catch { }
            throw ('Relay answered {0}: {1}' -f [int]$ex.Response.StatusCode, $msg)
        }
        $why = $_.Exception.Message
        if ($ex) { $why = $ex.Message }
        throw ('Could not reach the relay at {0}: {1}' -f $uri, $why)
    }
}

function Invoke-AssistantClaude {
    param($State, [string]$Question)
    $q = $Question
    if (-not $State.NoRedact) { $q = Protect-AssistantText $q }
    $context = ConvertTo-JsonStringXP (Get-AssistantContext $State)
    $hist = @($State.History | Where-Object { $_ })
    # The relay takes at most 64 KB: drop the oldest question/answer pairs
    # until the request fits.
    while ($true) {
        $parts = @()
        foreach ($h in $hist) { $parts += ('{"role":' + (ConvertTo-JsonStringXP $h.Role) + ',"content":' + (ConvertTo-JsonStringXP $h.Content) + '}') }
        $parts += ('{"role":"user","content":' + (ConvertTo-JsonStringXP $q) + '}')
        $body = '{"context":' + $context + ',"messages":[' + ($parts -join ',') + ']}'
        if (($body.Length -lt 60000) -or ($hist.Length -lt 2)) { break }
        $hist = @($hist | Select-Object -Skip 2)
    }
    $State.History = $hist
    Write-Host '  (asking Claude...)' -ForegroundColor DarkGray
    $answer = (Invoke-AssistantRelay -Url $State.Cfg.RelayUrl -Token $State.Cfg.RelayToken -Body $body).Trim()
    $hist = @($State.History)
    $hist += New-Object PSObject -Property @{ Role = 'user'; Content = $q }
    $hist += New-Object PSObject -Property @{ Role = 'assistant'; Content = $answer }
    if ($hist.Length -gt 12) { $hist = @($hist | Select-Object -Last 12) }
    $State.History = $hist
    return $answer
}

function Invoke-AssistantTurn {
    # Handles one line typed at the XP-AI prompt. Prints the answer and
    # returns it.
    param($State, [string]$Line)
    $q = $Line.Trim()
    $l = $q.ToLower()
    $text = ''
    $issues = @(Get-AssistantIssueList $State.Findings)

    if ($l -match '^(help|\?|commands)$') {
        $text = Get-AssistantHelp
    } elseif ($l -match '^(scan|rescan)$') {
        Invoke-AssistantScan $State
        Write-Host ''
        $text = Get-AssistantSummary $State
    } elseif ($l -match '^(summary|status)$') {
        $text = Get-AssistantSummary $State
    } elseif ($l -match '^(plan|fix|fixes|what should i fix( first)?\??)$') {
        $text = (Get-AssistantFixPlan $State.Findings) -join "`n"
    } elseif ($l -match '^(list|findings|issues)$') {
        if ($issues.Length -eq 0) { $text = 'No issues loaded. Type scan, or summary.' }
        else {
            $rows = @()
            for ($i = 0; $i -lt $issues.Length; $i++) { $rows += ('{0,3}. [{1}] {2}: {3}' -f ($i + 1), $issues[$i].Level, $issues[$i].Area, $issues[$i].Message) }
            $text = ($rows -join "`n") + "`nType explain <n> for any of them."
        }
    } elseif ($l -match '^(?:explain\s*#?|(?:why|what is|what''s|tell me about)\s*#)\s*(\d{1,4})\s*\??$') {
        # "explain 3" or "what is #3"; "what is 445" is a question about port 445.
        $n = [int]$matches[1]
        if (($n -lt 1) -or ($n -gt $issues.Length)) {
            $text = ('There is no issue #{0}. Type list to see the {1} issue(s).' -f $n, $issues.Length)
        } elseif ($State.Mode -eq 'Claude') {
            $f = $issues[$n - 1]
            $ask = ('Explain issue #{0} on my XP PC: [{1}] {2}: {3} (suggested fix: {4}). What does it mean, how serious is it on XP, and how do I fix it?' -f $n, $f.Level, $f.Area, $f.Message, $f.Fix)
            try { $text = Invoke-AssistantClaude $State $ask }
            catch {
                Write-Finding -Level 'Warn' -Message ($_.Exception.Message + ' Answering offline.')
                $text = Get-AssistantExplain $issues[$n - 1] $n
            }
        } else {
            $text = Get-AssistantExplain $issues[$n - 1] $n
        }
    } elseif ($l -match '^(topics|what can you do\??)$') {
        $text = 'Offline notes cover:' + "`n" + ((@($script:AssistantKB | ForEach-Object { '  - ' + $_.Title })) -join "`n")
    } elseif ($l -match '^mode\s+(offline|claude)$') {
        if (($matches[1] -eq 'claude') -and (-not ($State.Cfg.RelayUrl -and $State.Cfg.RelayToken))) {
            $text = 'Claude mode needs a relay first. Ask: how do I use claude mode'
        } else {
            $State.Mode = (Get-Culture).TextInfo.ToTitleCase($matches[1])
            $text = 'Mode: ' + $State.Mode
        }
    } elseif ($l -match '^relay$') {
        if (-not ($State.Cfg.RelayUrl -and $State.Cfg.RelayToken)) { $text = 'No relay set. Ask: how do I use claude mode' }
        else {
            try { $text = 'Relay OK: ' + (Invoke-AssistantRelay -Url $State.Cfg.RelayUrl -Token $State.Cfg.RelayToken -Path '/health' -TimeoutSec 10).Trim() }
            catch { $text = $_.Exception.Message }
        }
    } elseif ($State.Mode -eq 'Claude') {
        try { $text = Invoke-AssistantClaude $State $q }
        catch {
            Write-Finding -Level 'Warn' -Message ($_.Exception.Message + ' Answering offline.')
            $text = Get-AssistantOfflineAnswer $State $q
        }
    } else {
        $text = Get-AssistantOfflineAnswer $State $q
    }

    Write-Wrapped -Text $text -Indent 2 -Color 'White'
    return $text
}

function Invoke-XPAssistant {
<#
.SYNOPSIS
    Security assistant: explains findings, answers questions and says what to fix first.
.DESCRIPTION
    Loads the findings from the checks you ran this session (or from the
    pipeline, or runs a scan with -Scan) and answers questions about them.

    Offline mode (default) uses notes built into the module; nothing leaves
    the PC. Claude mode sends the question and the findings to Claude
    through relay\Start-ClaudeRelay.ps1 running on a modern PC, because XP
    cannot make the TLS 1.2 connections the Claude API needs. MAC
    addresses, this PC's name and the user name are masked first unless
    -NoRedact is given. Set the relay up once with Set-XPAssistantConfig.

    With no -Question it opens an interactive prompt (XP-AI>). Type help
    there for the commands.
.PARAMETER Question
    Ask one question (or a command such as plan or summary) and return.
.PARAMETER InputObject
    Findings from a check's -PassThru output.
.PARAMETER Mode
    Offline or Claude. Default: the saved DefaultMode, else Offline.
.PARAMETER RelayUrl
    Relay address for this run, e.g. http://192.168.80.1:8787
.PARAMETER RelayToken
    Relay token for this run.
.PARAMETER Scan
    Run Get-XPHardeningStatus and Get-AccountAuditXP first.
.PARAMETER NoRedact
    Send MAC addresses, the PC name and the user name to the relay as they are.
.PARAMETER PassThru
    With -Question, also return the answer text.
.EXAMPLE
    Invoke-XPAssistant -Scan
.EXAMPLE
    Get-XPHardeningStatus -PassThru | Invoke-XPAssistant -Question plan
.EXAMPLE
    xpai "what is netbios"
.EXAMPLE
    Invoke-XPAssistant -Mode Claude
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Question,
        [Parameter(ValueFromPipeline = $true)][object[]]$InputObject,
        [ValidateSet('Offline', 'Claude')][string]$Mode,
        [string]$RelayUrl,
        [string]$RelayToken,
        [switch]$Scan,
        [switch]$NoRedact,
        [switch]$PassThru
    )
    begin { $piped = @() }
    process {
        foreach ($o in @($InputObject)) {
            if (-not $o) { continue }
            if ($o.PSObject.Properties['Findings']) { $piped += @($o.Findings | Where-Object { $_ }) }
            elseif ($o.PSObject.Properties['Level'] -and $o.PSObject.Properties['Message']) { $piped += $o }
        }
    }
    end {
        $cfg = Get-AssistantConfig
        if ($RelayUrl) { $cfg.RelayUrl = $RelayUrl.TrimEnd('/') }
        if ($RelayToken) { $cfg.RelayToken = $RelayToken }
        if (-not $Mode) { $Mode = [string]$cfg.DefaultMode }
        if ($Mode -ne 'Claude') { $Mode = 'Offline' }
        if (($Mode -eq 'Claude') -and (-not ($cfg.RelayUrl -and $cfg.RelayToken))) {
            Write-Finding -Level 'Warn' -Message 'Claude mode needs a relay: Set-XPAssistantConfig -RelayUrl http://<host>:8787 -RelayToken <token>. Using offline mode.'
            $Mode = 'Offline'
        }
        $state = @{ Mode = $Mode; Cfg = $cfg; Findings = @(); Sources = @(); History = @(); NoRedact = [bool]$NoRedact }

        if ($Scan) { Invoke-AssistantScan $state }
        elseif ($piped.Length -gt 0) { $state.Findings = $piped; $state.Sources = @('pipeline') }
        else { Update-AssistantFindings $state }

        if ($Question) {
            $answer = Invoke-AssistantTurn -State $state -Line $Question
            if ($PassThru) { $answer }
            return
        }

        Write-Section 'NetSecToolkitXP assistant'
        if ($state.Mode -eq 'Claude') {
            Write-Host ('  Mode: Claude, through the relay at {0}' -f $cfg.RelayUrl)
            if (-not $NoRedact) { Write-Host '  MAC addresses, this PC''s name and your user name are masked before sending.' -ForegroundColor DarkGray }
        } else {
            Write-Host '  Mode: offline (built-in notes; nothing leaves this PC)'
        }
        Write-Host ''
        Write-Wrapped -Text (Get-AssistantSummary $state) -Indent 2 -Color 'White'
        Write-Host ''
        Write-Host '  Ask a question, or type: scan, summary, plan, list, explain <n>, topics, help, exit' -ForegroundColor DarkGray

        $done = $false
        while (-not $done) {
            Write-Host ''
            $line = Read-Host 'XP-AI'
            if ($line -eq $null) { break }
            $line = ([string]$line).Trim()
            if (-not $line) { continue }
            if ($line -match '^(exit|quit|q|bye)$') { $done = $true; continue }
            Write-Host ''
            $null = Invoke-AssistantTurn -State $state -Line $line
        }
    }
}

function Set-XPAssistantConfig {
<#
.SYNOPSIS
    Saves the Claude relay address and token for Invoke-XPAssistant.
.DESCRIPTION
    Stores the relay URL, the relay token and the default mode in
    %APPDATA%\NetSecToolkitXP\assistant.clixml for the current user. The
    token only lets this PC use your relay; your Claude API key stays on
    the PC running the relay and is never stored here. The environment
    variables NSTXP_RELAY_URL and NSTXP_RELAY_TOKEN override the saved values.
.PARAMETER RelayUrl
    The address Start-ClaudeRelay.ps1 printed, e.g. http://192.168.80.1:8787
.PARAMETER RelayToken
    The token Start-ClaudeRelay.ps1 printed.
.PARAMETER DefaultMode
    Offline or Claude: what Invoke-XPAssistant uses when -Mode is not given.
.PARAMETER Test
    Check that the relay answers.
.PARAMETER Clear
    Delete the saved settings.
.EXAMPLE
    Set-XPAssistantConfig -RelayUrl http://192.168.80.1:8787 -RelayToken <token the relay printed> -DefaultMode Claude -Test
#>
    [CmdletBinding()]
    param(
        [string]$RelayUrl,
        [string]$RelayToken,
        [ValidateSet('Offline', 'Claude')][string]$DefaultMode,
        [switch]$Test,
        [switch]$Clear
    )
    $p = Get-AssistantConfigPath
    if ($Clear) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p }
        Write-Host '  Assistant settings removed.'
        return
    }
    $cfg = Get-AssistantConfig -FileOnly
    if ($PSBoundParameters.ContainsKey('RelayUrl')) {
        if ($RelayUrl -notmatch '^http://[^/\s:]+(:\d{1,5})?/?$') {
            throw 'Use the http:// address the relay printed, for example http://192.168.80.1:8787'
        }
        $cfg.RelayUrl = $RelayUrl.TrimEnd('/')
    }
    if ($PSBoundParameters.ContainsKey('RelayToken')) { $cfg.RelayToken = $RelayToken }
    if ($PSBoundParameters.ContainsKey('DefaultMode')) { $cfg.DefaultMode = $DefaultMode }

    $changed = $PSBoundParameters.ContainsKey('RelayUrl') -or $PSBoundParameters.ContainsKey('RelayToken') -or $PSBoundParameters.ContainsKey('DefaultMode')
    if ($changed) {
        $dir = Split-Path -Parent $p
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $cfg | Export-Clixml -Path $p
        Write-Host ('  Saved to {0}' -f $p)
    }
    $masked = '(not set)'
    if ($cfg.RelayToken) { $masked = ([string]$cfg.RelayToken).Substring(0, [math]::Min(4, ([string]$cfg.RelayToken).Length)) + '...' }
    $url = $cfg.RelayUrl
    if (-not $url) { $url = '(not set)' }
    Write-Host ('  Relay URL   : {0}' -f $url)
    Write-Host ('  Relay token : {0}' -f $masked)
    Write-Host ('  Default mode: {0}' -f $cfg.DefaultMode)

    if ($Test) {
        if (-not ($cfg.RelayUrl -and $cfg.RelayToken)) { Write-Finding -Level 'Warn' -Message 'Set -RelayUrl and -RelayToken first.'; return }
        try {
            $r = Invoke-AssistantRelay -Url $cfg.RelayUrl -Token $cfg.RelayToken -Path '/health' -TimeoutSec 10
            Write-Finding -Level 'OK' -Message ('Relay answered: ' + $r.Trim())
        } catch {
            Write-Finding -Level 'Risk' -Message $_.Exception.Message -Fix 'Is Start-ClaudeRelay.ps1 running on the host, and does the host firewall allow the port from this VM?'
        }
    }
}

Set-Alias -Name xpai -Value Invoke-XPAssistant

#endregion

#region Menu (0.4.0)

function Set-ConsoleWidth {
    # Widens the console so tables fit. The buffer must be at least as wide
    # as the window, so it is widened first. Never wider than the screen.
    param([int]$Width = 110)
    try {
        $ui = $Host.UI.RawUI
        $max = $ui.MaxPhysicalWindowSize.Width
        if ($Width -gt $max) { $Width = $max }
        $buf = $ui.BufferSize
        if ($buf.Width -lt $Width) {
            $buf.Width = $Width
            if ($buf.Height -lt 3000) { $buf.Height = 3000 }
            $ui.BufferSize = $buf
        }
        $win = $ui.WindowSize
        if ($win.Width -lt $Width) {
            $win.Width = $Width
            $ui.WindowSize = $win
        }
    } catch { }
}

function Read-MenuAnswer {
    param([string]$Prompt)
    $a = Read-Host $Prompt
    if ($a -eq $null) { return '' }
    return ([string]$a).Trim()
}

function Wait-MenuReturn {
    Write-Host ''
    $null = Read-Host 'Press Enter to go back to the menu'
}

function Invoke-MenuHardening {
    # Preview first, then apply only after the user types YES.
    if (-not (Test-IsAdmin)) {
        Write-Finding -Level 'Warn' -Message 'Hardening needs an administrator account. Log on as an administrator and run NetSecToolkitXP.exe again.'
        return
    }
    Write-Host ''
    Write-Host '  Step 1 of 2: preview. Nothing is changed yet.' -ForegroundColor Cyan
    Set-XPHardening -WhatIf
    Write-Host ''
    Write-Host '  Step 2 of 2: apply.' -ForegroundColor Cyan
    Write-Host '  Type YES to apply all steps, S to choose steps to leave alone, or press Enter to cancel.'
    $answer = Read-MenuAnswer 'Apply'
    $skip = @()
    if ($answer -eq 'S') {
        Write-Host '  Step names: Firewall Logging FileAndPrint RemoteDesktop RemoteAdmin UPnPException RemoteAssistance'
        Write-Host '              MSMQ UPnP SimpleTcp Server SmbDevice NetBIOS RemoteRegistry Messenger Telnet Guest'
        Write-Host '              RestrictAnonymous NoLMHash NTLMv2 PasswordPolicy AutoRun'
        Write-Host '  To keep file sharing: Server,SmbDevice,NetBIOS,FileAndPrint'
        $list = Read-MenuAnswer 'Steps to leave alone (separate with commas)'
        $skip = @($list -split '[,\s]+' | Where-Object { $_ })
        $valid = @((Get-Command Set-XPHardening).Parameters['Skip'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
        $unknown = @($skip | Where-Object { -not ($valid -contains $_) })
        if ($unknown.Length -gt 0) {
            Write-Host ('  Not a step name: {0}. Nothing was changed; choose H to try again.' -f ($unknown -join ', ')) -ForegroundColor Yellow
            return
        }
        $answer = Read-MenuAnswer ('Type YES to apply everything except: ' + ($skip -join ', '))
    }
    if ($answer -ne 'YES') {
        Write-Host '  Cancelled. Nothing was changed.' -ForegroundColor Yellow
        return
    }
    if ($skip.Length -gt 0) { Set-XPHardening -Skip $skip } else { Set-XPHardening }
    Write-Host ''
    $reboot = Read-MenuAnswer 'Restart now so every change applies? (Y/N)'
    if ($reboot -eq 'Y') {
        Write-Host '  Restarting. After it starts again, run the full check (option 1).'
        Restart-Computer -Force
    } else {
        Write-Host '  Restart later, then run the full check (option 1) to confirm.' -ForegroundColor DarkGray
    }
}

function Open-LastReport {
    $dir = Get-DefaultReportDir
    $last = @(Get-ChildItem -Path $dir -Filter 'Report_*.html' -ErrorAction SilentlyContinue | Sort-Object Name -Descending) | Select-Object -First 1
    if (-not $last) {
        Write-Finding -Level 'Info' -Message ('No report yet in {0}. Run the full check (option 1) first.' -f $dir)
        return
    }
    Write-Host ('  Opening {0}' -f $last.FullName)
    Invoke-Item -LiteralPath $last.FullName
}

function Show-ToolkitMenu {
    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor DarkCyan
    Write-Host (' NetSecToolkitXP {0} - Windows XP security toolkit' -f $script:ToolkitVersion) -ForegroundColor Cyan
    $admin = 'yes'
    if (-not (Test-IsAdmin)) { $admin = 'NO (checks only; option H needs an administrator)' }
    Write-Host (' Computer: {0}   User: {1}   Administrator: {2}' -f $env:COMPUTERNAME, $env:USERNAME, $admin) -ForegroundColor DarkGray
    Write-Host ('=' * 60) -ForegroundColor DarkCyan
    Write-Host '  Checks (change nothing)' -ForegroundColor White
    Write-Host '    1  Full security check (all of the below, saves a report)'
    Write-Host '    2  Hardening status'
    Write-Host '    3  Firewall exceptions'
    Write-Host '    4  Accounts and logon'
    Write-Host '    5  Firewall log (what was blocked)'
    Write-Host '    6  Devices on the network'
    Write-Host '    7  Router ports and UPnP'
    Write-Host '    8  Network adapters and connectivity'
    Write-Host '    9  USB storage history'
    Write-Host '  Fix' -ForegroundColor White
    Write-Host '    H  Harden this PC (shows a preview first)'
    Write-Host '  Help' -ForegroundColor White
    Write-Host '    A  Ask the assistant (what to fix first, what a finding means)'
    Write-Host '    R  Open the last report'
    Write-Host '    P  PowerShell prompt with the toolkit loaded (type exit to come back)'
    Write-Host '    Q  Quit'
}

function Start-NetSecToolkitXP {
<#
.SYNOPSIS
    Menu for the whole toolkit. NetSecToolkitXP.exe opens this.
.DESCRIPTION
    Shows a numbered menu of the checks, the hardening run (always previewed
    first and applied only after you type YES), the assistant and the last
    report, so the toolkit can be used without typing commands. Errors in
    one option are shown and the menu carries on.
.EXAMPLE
    Start-NetSecToolkitXP
#>
    [CmdletBinding()]
    param()

    try { $Host.UI.RawUI.WindowTitle = 'NetSecToolkitXP ' + $script:ToolkitVersion } catch { }
    Set-ConsoleWidth -Width 110

    $done = $false
    while (-not $done) {
        Show-ToolkitMenu
        Write-Host ''
        $choice = (Read-MenuAnswer 'Choose').ToUpper()
        $wait = $true
        try {
            switch ($choice) {
                '1' { Invoke-XPSecurityCheck }
                '2' { Get-XPHardeningStatus }
                '3' { Get-FirewallAuditXP }
                '4' { Get-AccountAuditXP }
                '5' { Get-FirewallLogXP }
                '6' {
                    $sweep = Read-MenuAnswer 'Ping every address on the subnet too? Takes about a minute. (Y/N)'
                    if ($sweep -eq 'Y') { Find-NetworkDeviceXP } else { Find-NetworkDeviceXP -NoSweep }
                }
                '7' { Test-RouterExposureXP }
                '8' { Get-NetAdapterHealthXP }
                '9' { Get-USBHistoryXP }
                'H' { Invoke-MenuHardening }
                'A' { Invoke-XPAssistant; $wait = $false }
                'R' { Open-LastReport }
                'P' {
                    Write-Host '  Type exit to come back to the menu. Get-Help <command> -Full explains any command.' -ForegroundColor DarkGray
                    $wait = $false
                    $Host.EnterNestedPrompt()
                }
                'Q' { $done = $true; $wait = $false }
                ''  { $wait = $false }
                default { Write-Host ('  "{0}" is not on the menu.' -f $choice) -ForegroundColor Yellow }
            }
        } catch {
            Write-Host ''
            Write-Host ('  Error: ' + $_.Exception.Message) -ForegroundColor Red
            Write-Host '  The menu is still running. If this keeps happening, send a photo of this screen.' -ForegroundColor DarkGray
        }
        if ($wait -and (-not $done)) { Wait-MenuReturn }
    }
}

#endregion

Export-ModuleMember -Function Get-NetAdapterHealthXP, Get-FirewallAuditXP, Find-NetworkDeviceXP,
    Set-XPHardening, Get-XPHardeningStatus, Get-AccountAuditXP, Get-FirewallLogXP,
    Test-RouterExposureXP, Get-USBHistoryXP, Invoke-XPSecurityCheck, Invoke-XPAssistant,
    Set-XPAssistantConfig, Start-NetSecToolkitXP -Alias xpai
