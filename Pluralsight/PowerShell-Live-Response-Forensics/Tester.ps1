
function Export-CsvLogs {
    [CmdletBinding()]
    Param(
        [string]$OutPath
    )

    $items = @(
        @{ FileName = "Computer-Information.log"; Content = $ComputerInfo }
        @{ FileName = "Memory-Information.log"; Content = $MemoryInfo }
        @{ FileName = "Operating-System-Information.log"; Content = $OSinfo }
        @{ FileName = "Installed-Application-Information.log"; Content = $InstalledApplicationInfo }
        @{ FileName = "Local-Logon-Information.log"; Content = $LocalLogonInfo }
        @{ FileName = "Local-User-Information.log"; Content = $LocalUserInfo }
        @{ FileName = "Local-Groups-Information.log"; Content = $LocalGroupInfo }
        @{ FileName = "Logon-Session-Information.log"; Content = $LogonSessionInfo }
        @{ FileName = "Processor-Information.log"; Content = $ProcessInfo }
        @{ FileName = "BIOS-Information.log"; Content = $BiosInfo }
        @{ FileName = "Disk-Information.log"; Content = $DiskInfo }
        @{ FileName = "Disk-Encryption-Information.log"; Content = $DiskEncryptionInfo }
        @{ FileName = "Services-Information.log"; Content = $ServicesInfo }
        @{ FileName = "Process-Information.log"; Content = $ProcessesInfo }
        @{ FileName = "Enabled-Windows-Features.log"; Content = $WindowsFeaturesInfo }
        @{ FileName = "Network-Information.log"; Content = $NetworkAdapterInfo }
        @{ FileName = "IP-Address-Information.log"; Content = $IPAddressInfo }
        @{ FileName = "DNS-Cache-Information.log"; Content = $DNSCacheInfo }
        @{ FileName = "ARP-Cache-Information.log"; Content = $ARPCacheInfo }
        @{ FileName = "Routing-Table-Information.log"; Content = $RoutingTableInfo }  
        @{ FileName = "Host-Entry-Information.log"; Content = $HostEntriesInfo }
        @{ FileName = "Firewall-Rules-Information.log"; Content = $FirewallRulesInfo }
        @{ FileName = "TCP-View-and-Port-Information.log"; Content = $TCPPortInformation }
        @{ FileName = "Startup-Processes.log"; Content = $StartupProcessesInfo }
        @{ FileName = "Autorun-Processes.log"; Content = $AutoRunInformation }
        @{ FileName = "Scheduled-Tasks.log"; Content = $ScheduledTasksInfo }
        @{ FileName = "USB-Device-Information.log"; Content = $USBDevicesInfo }
        @{ FileName = "Modified-Files-Information.log"; Content = $ModifiedFilesInfo }
        @{ FileName = "Open-Files-by-Process-Information.log"; Content = $OpenFilesByprocessInfo }  
        @{ FileName = "PowerShell-History.log"; Content = $HistoryInfo }
        @{ FileName = "Windows-Prefetch-Files-Information.log"; Content = $PrefetchFilesInfo }
        @{ FileName = "Windows-DLLs.log"; Content = $DLLFilesInfo }
        @{ FileName = "Kerberos-Session-Information.log"; Content = $KerberosSessionsInfo }
        @{ FileName = "SMB-Session-Information.log"; Content = $SMBSessionsInfo }
        @{ FileName = "Process-Connection-Information.log"; Content = $ProcessConnectionsInfo }
        @{ FileName = "Shared-Folder-Information.log"; Content = $SharedFoldersInfo }
        @{ FileName = "Shadow-Copy-Information.log"; Content = $ShadowCopyInfo }
        @{ FileName = "Group-Policy-Information.log"; Content = $GroupPolicyInfo }
        @{ FileName = "Current-Opened-Explorer-Windows.log"; Content = $OpenedExplorerWindowInfo }
        @{ FileName = "Event-Logs-Information.log"; Content = $EventLogsInfo }
        @{ FileName = "Application-Event-Log-Entries.log"; Content = $ApplicationEvents }
        @{ FileName = "Security-Event-Log-Entries.log"; Content = $SecurityEvents }
        @{ FileName = "System-Event-Log-Entries.log"; Content = $SystemEvents }
    )

    foreach ($item in $items) {
        Write-Host $item.FileName

        Add-content "$OutPath/$($item.FileName)" -Value $item.Content
    }
}