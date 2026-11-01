@{
    ModuleToProcess   = 'NetSecToolkitXP.psm1'
    ModuleVersion     = '0.5.2'
    GUID              = '5f3c2a8e-9d41-4b7e-a6c2-1e8f0b9d7c34'
    Author            = "Edward O'Connell III"
    Copyright         = "Copyright Edward O'Connell III 2026"
    Description       = 'Windows XP SP3 / PowerShell 2.0 build of NetSecToolkit: hardening, firewall and account audits, firewall log, router and USB checks, root certificate updates, an all-in-one check, and a security assistant (offline, or Claude through a relay).'
    PowerShellVersion = '2.0'
    FunctionsToExport = @('Get-NetAdapterHealthXP', 'Get-FirewallAuditXP', 'Find-NetworkDeviceXP',
                          'Set-XPHardening', 'Get-XPHardeningStatus', 'Get-AccountAuditXP',
                          'Get-FirewallLogXP', 'Test-RouterExposureXP', 'Get-USBHistoryXP',
                          'Invoke-XPSecurityCheck', 'Invoke-XPAssistant', 'Set-XPAssistantConfig',
                          'Start-NetSecToolkitXP', 'Get-ThreatExposureXP', 'Find-MalwareIndicatorXP',
                          'Get-RootCertStatusXP', 'Update-XPRootCertificate')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('xpai')
}
