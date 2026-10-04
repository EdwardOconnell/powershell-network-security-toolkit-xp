@{
    ModuleToProcess   = 'NetSecToolkitXP.psm1'
    ModuleVersion     = '0.2.1'
    GUID              = '5f3c2a8e-9d41-4b7e-a6c2-1e8f0b9d7c34'
    Author            = "Edward O'Connell III"
    Description       = 'Windows XP SP3 / PowerShell 2.0 test build of NetSecToolkit: firewall audit, adapter health, ARP device discovery, hardening.'
    PowerShellVersion = '2.0'
    FunctionsToExport = @('Get-NetAdapterHealthXP', 'Get-FirewallAuditXP', 'Find-NetworkDeviceXP',
                          'Set-XPHardening', 'Get-XPHardeningStatus')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
