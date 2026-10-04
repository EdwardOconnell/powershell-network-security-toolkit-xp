# NetSecToolkitXP - Windows XP SP3 / PowerShell 2.0 test build of NetSecToolkit.
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

function Write-TableToHost {
    param($InputRows)
    if (@($InputRows).Length -gt 0) {
        $InputRows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
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

        # Logging lives in the registry on XP. Missing values mean "off".
        $logKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{0}\Logging' -f $p.RegKey
        $log = Get-ItemProperty -Path $logKey -ErrorAction SilentlyContinue
        $dropped = $false
        $allowed = $false
        if ($log) {
            $dropped = ($log.LogDroppedPackets -eq 1)
            $allowed = ($log.LogSuccessfulConnections -eq 1)
        }
        if ($dropped) {
            $path = '%windir%\pfirewall.log'
            if ($log.LogFilePath) { $path = $log.LogFilePath }
            $findings += New-Finding -Area $p.Name -Level (Limit-Level 'OK' $inactiveDomain) -Message ('Dropped-packet logging is on ({0}).' -f $path)
        } else {
            $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Warn' $inactiveDomain) -Message 'Dropped-packet logging is off.' -Fix 'netsh firewall set logging droppedpackets=ENABLE connections=ENABLE'
        }
        if ($dropped -and -not $allowed) {
            $findings += New-Finding -Area $p.Name -Level (Limit-Level 'Info' $inactiveDomain) -Message 'Successful-connection logging is off.'
        }
    }

    $exceptions = @($exceptions | Select-Object Profile, Kind, Name, Detail, Enabled, Scope)
    Write-Section 'Exception list'
    if ($exceptions.Length -eq 0) {
        Write-Host '  (none)'
    } else {
        Write-TableToHost $exceptions
    }

    if ($ExportPath) {
        $exceptions | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host ('  Exceptions exported to ' + $ExportPath) -ForegroundColor DarkGray
    }

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
    Turns on Windows Firewall with no exceptions, closes the File and Printer
    Sharing / Remote Desktop / Remote Admin / UPnP exceptions, disables
    MSMQ, UPnP, Simple TCP/IP Services, the Server service, Remote Registry,
    Messenger and Telnet, turns off SMB over port 445 and NetBIOS over
    TCP/IP, disables the Guest account and turns off AutoRun.
    Each step reports Applied, N/A (not installed), Skipped or Failed.
    Run with -WhatIf first to see what it will do.
.PARAMETER Skip
    Step names to leave alone, e.g. -Skip Server,SmbDevice,NetBIOS,FileAndPrint
    to keep file sharing working.
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
        [ValidateSet('Firewall', 'FileAndPrint', 'RemoteDesktop', 'RemoteAdmin', 'UPnPException',
                     'MSMQ', 'UPnP', 'SimpleTcp', 'Server', 'SmbDevice', 'NetBIOS',
                     'RemoteRegistry', 'Messenger', 'Telnet', 'Guest', 'AutoRun')]
        [string[]]$Skip = @(),
        [switch]$PassThru
    )

    if ((-not $WhatIfPreference) -and (-not (Test-IsAdmin))) {
        throw 'Set-XPHardening must run in an Administrator PowerShell window.'
    }

    $steps = @(
        @{ Name = 'Firewall'; Reboot = $false
           Action = 'Turn on Windows Firewall with exceptions disabled (all profiles)'
           Run = { Invoke-NetshFirewall @('set', 'opmode', 'mode=ENABLE', 'exceptions=DISABLE', 'profile=ALL'); 'On, no exceptions' } },
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
           Action = 'Turn off NetBIOS over TCP/IP on every IP-enabled adapter (137-139)'
           Run = {
               $bad = @()
               $count = 0
               foreach ($c in @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE')) {
                   $r = $c.SetTcpipNetbios(2)
                   if ($r.ReturnValue -ne 0) { $bad += ('{0} (code {1})' -f $c.Description, $r.ReturnValue) } else { $count++ }
               }
               if ($bad.Length -gt 0) { throw ('Failed on: ' + ($bad -join '; ')) }
               '{0} adapter(s) set' -f $count
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
           Action = 'Disable the Guest account'
           Run = {
               $out = & net.exe user guest /active:no 2>&1
               if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }
               'Guest disabled'
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
        Write-Host ('  [{0,-8}] {1,-14} {2}' -f $status, $s.Name, $detail) -ForegroundColor $colors[$status]
        $results += New-Object PSObject -Property @{ Step = $s.Name; Status = $status; Detail = $detail }
    }

    $failed = @($results | Where-Object { $_.Status -eq 'Failed' })
    Write-Host ''
    if ($failed.Length -gt 0) {
        Write-Host ('  {0} step(s) failed. Fix the cause or re-run with -Skip for those steps.' -f $failed.Length) -ForegroundColor Yellow
    }
    if ($needReboot) {
        Write-Host '  Reboot to finish (port 445 closes after restart), then run Get-XPHardeningStatus.' -ForegroundColor Yellow
    } elseif (-not $WhatIfPreference) {
        Write-Host '  Run Get-XPHardeningStatus to verify.' -ForegroundColor DarkGray
    }

    if ($PassThru) { $results | Select-Object Step, Status, Detail }
}

function Get-XPHardeningStatus {
<#
.SYNOPSIS
    Read-only check of the XP hardening baseline.
.DESCRIPTION
    Checks the firewall, the services Set-XPHardening disables, SMB/NetBIOS,
    the Guest account, AutoRun, the three wormable-flaw fixes (by the file
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
    } catch {
        $findings += New-Finding -Area 'Firewall' -Level 'Risk' -Message ('Could not read firewall policy: ' + $_.Exception.Message)
    }

    Write-Section 'Services'
    foreach ($n in @('MSMQ', 'upnphost', 'SSDPSRV', 'SimpTcp', 'lanmanserver', 'RemoteRegistry', 'Messenger', 'TlntSvr')) {
        $w = Get-WmiObject -Class Win32_Service -Filter ("Name = '{0}'" -f $n) -ErrorAction SilentlyContinue
        if (-not $w) {
            $findings += New-Finding -Area 'Services' -Level 'OK' -Message ('{0} is not installed.' -f $n)
        } elseif (($w.StartMode -eq 'Disabled') -and ($w.State -eq 'Stopped')) {
            $findings += New-Finding -Area 'Services' -Level 'OK' -Message ('{0} ({1}) is stopped and disabled.' -f $w.DisplayName, $n)
        } else {
            $findings += New-Finding -Area 'Services' -Level 'Warn' -Message ('{0} ({1}) is {2}, startup {3}.' -f $w.DisplayName, $n, $w.State, $w.StartMode) -Fix $fixCmd
        }
    }

    Write-Section 'SMB, NetBIOS, accounts, AutoRun'
    $netbt = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -ErrorAction SilentlyContinue
    $smbOff = ($netbt -and ($netbt.SMBDeviceEnabled -ne $null) -and ($netbt.SMBDeviceEnabled -eq 0))
    if ($smbOff) {
        $findings += New-Finding -Area 'SMB' -Level 'OK' -Message 'SMB over port 445 is off (SMBDeviceEnabled = 0).'
    } else {
        $findings += New-Finding -Area 'SMB' -Level 'Warn' -Message 'SMBDeviceEnabled is not 0, so port 445 stays open.' -Fix ($fixCmd + ', then reboot')
    }

    $adapters = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' -ErrorAction SilentlyContinue)
    $nbOn = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
    if ($nbOn.Length -eq 0) {
        $findings += New-Finding -Area 'NetBIOS' -Level 'OK' -Message ('NetBIOS over TCP/IP is off on all {0} IP-enabled adapter(s).' -f $adapters.Length)
    } else {
        $names = ($nbOn | ForEach-Object { $_.Description }) -join ', '
        $findings += New-Finding -Area 'NetBIOS' -Level 'Warn' -Message ('NetBIOS over TCP/IP is on: ' + $names) -Fix $fixCmd
    }

    $guest = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = TRUE AND Name = 'Guest'" -ErrorAction SilentlyContinue
    if (-not $guest) {
        $findings += New-Finding -Area 'Accounts' -Level 'Info' -Message 'No local account named Guest found.'
    } elseif ($guest.Disabled) {
        $findings += New-Finding -Area 'Accounts' -Level 'OK' -Message 'Guest account is disabled.'
    } else {
        $findings += New-Finding -Area 'Accounts' -Level 'Warn' -Message 'Guest account is enabled.' -Fix $fixCmd
    }

    $explorer = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue
    if ($explorer -and ($explorer.NoDriveTypeAutoRun -eq 255)) {
        $findings += New-Finding -Area 'AutoRun' -Level 'OK' -Message 'AutoRun is off for all drive types.'
    } else {
        $findings += New-Finding -Area 'AutoRun' -Level 'Warn' -Message 'AutoRun is not fully disabled.' -Fix $fixCmd
    }

    Write-Section 'Patches'
    # The three wormable flaws are checked by the version of the file each fix
    # replaced, not by KB number: later updates (POSReady 2009 and others)
    # supersede the original KBs, so a fully patched PC often lacks them.
    # Minimum versions are from Microsoft's file-information tables (XP SP3, x86).
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

    if ($PassThru) { $findings }
}

#endregion

Export-ModuleMember -Function Get-NetAdapterHealthXP, Get-FirewallAuditXP, Find-NetworkDeviceXP,
    Set-XPHardening, Get-XPHardeningStatus
