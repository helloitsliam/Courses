###############
## Variables ##
###############

$logoPath = "C:\PROJECTS\PowerShell-Live-Response-Forensics\Assets\Methodize-Logo-Small.png"
$reportName = "Methodize-Report.html"
$reportLocation = "C:\PROJECTS\PowerShell-Live-Response-Forensics\Report\"
$sysinternalsPath = "C:\PROJECTS\PowerShell-Live-Response-Forensics\Assets\Sysinternals"


###########################
## Create Remote Session ##
###########################

function New-HtmlDocument {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [Array]$ContentSets,
        [string]$Css,
        [string]$LogoPath
    )
  
    # Create the directory if it doesn't exist
    $dir = Split-Path $FilePath
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
  
    # Create the HTML document
    $html = "<html><head><title>Methodize: Rapid Digital Assessment ($(Get-Date))</title><style>$Css</style></head><body>"

    if ($LogoPath) {
        $html += "<div class='header'><img src='$LogoPath'></div>"
    }
    # Add the table of contents
    $html += "<ul>"
    $i = 1
    foreach ($set in $ContentSets) {
        $html += "<li>"
        $html += "<a href='#set-$i'>$($set.Title)</a>"
        $html += "</li>"
        $i++
    }
    $html += "</ul>"
      
    # Add the content sets
    $i = 1
    foreach ($set in $ContentSets) {
        $html += "<div id='set-$i'>"
        if ($set.Title) {
            $html += "<h2>$($set.Title)</h2><a href='#top'>[Back]</a>"
        }

        if ($set.Content -is [Array]) {
            foreach ($content in $set.Content) {
                $html += "<div id='set-$i'>$content</div>"
            }
        }
        else {
            $html += "<div id='set-$i'>$($set.Content)</div>"
        }

        $html += "</div>"
        $html += '<div class="page-break"></div>'
        $i++
    }
      
    # Close the HTML document
    $html += "</body></html>"
      
    # Write the HTML content to the file
    $html | Out-File -FilePath $FilePath -Encoding utf8
}

function Invoke-CommandCheck {
    param(
        [string]$Command
    )

    [bool]$commandExists = $false

    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        $commandExists = $true
    }
    else {
        $commandExists = $false
    }

    return $commandExists
}


function Get-SystemInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem

    if (Invoke-CommandCheck -Command "Get-TimeZone") {
        $timeZone = (Get-TimeZone).DisplayName
    }
    else {
        $timeZone = tzutil /g
    }

    $systemInfo = @{
        'OS Name'                   = $os.Caption
        'OS Version'                = $os.Version
        'OS Manufacturer'           = $os.Manufacturer
        'OS Configuration'          = $os.OSArchitecture
        'OS Build Type'             = $os.BuildType
        'Registered Owner'          = $os.RegisteredUser
        'Registered Organization'   = $os.RegisteredOrganization
        'Product ID'                = $os.SerialNumber
        'Original Install Date'     = $os.InstallDate
        'System Boot Time'          = $os.LastBootUpTime
        'System Manufacturer'       = $computer.Manufacturer
        'System Model'              = $computer.Model
        'System Type'               = $computer.SystemType
        '# of Processor(s)'         = $computer.NumberOfProcessors
        'BIOS Version'              = $bios.SMBIOSBIOSVersion
        'BIOS Manufacturer'         = $bios.Manufacturer
        'BIOS Release Date'         = $bios.ReleaseDate
        'System Locale'             = $os.MUILanguages[0]
        'Input Locale'              = $os.MUILanguages[0]
        'Time Zone'                 = $timeZone
        'Total Physical Memory'     = "{0:N2}" -f ($computer.TotalPhysicalMemory / 1GB) + ' GB'
        'Available Physical Memory' = "{0:N2}" -f ($os.FreePhysicalMemory / 1MB) + ' MB'
        'Virtual Memory: Max Size'  = "{0:N2}" -f ($os.TotalVirtualMemorySize / 1GB) + ' GB'
        'Virtual Memory: Available' = "{0:N2}" -f ($os.FreeVirtualMemory / 1MB) + ' MB'
        'Virtual Memory: In Use'    = "{0:N2}" -f (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1MB) + ' MB'
        'Page File Location(s)'     = $os.PageFileName
        'Domain'                    = $computer.Domain
        'Logon Server'              = $computer.DomainRole
        'Hotfix(s)'                 = $os.HotFixes | Select-Object -ExpandProperty HotFixID | Sort-Object
        'Network Card(s)'           = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true } | Select-Object -ExpandProperty Name
        'Processor(s)'              = $processor.Name
    }

    $output = '<table>'

    foreach ($prop in $systemInfo.Keys) {
        $value = $systemInfo[$prop]
        $output += "<tr><td>$prop</td><td>$value</td></tr>"
    }

    $output += '</table>'

    return $output
}

function Get-HostEntries {
    # Define the path to the hosts file
    $path = "C:\Windows\System32\drivers\etc\hosts"

    # Check if the hosts file exists
    if (-not (Test-Path -Path $path)) {
        Write-Verbose "[!] Could not find hosts file at: $path"
        return
    }

    # Read the contents of the hosts file and extract the host entries
    Get-Content -Path $path | Where-Object { $_ -notmatch '^#' } | Where-Object { $_ -match '^\s*\d+\.\d+\.\d+\.\d+' } | ForEach-Object {
        # Extract the IP address and hostname
        if ($_ -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+(.+)$') {
            $ipAddress = $Matches[1]
            $hostname = $Matches[2]

            # Create an object with the properties "IPAddress" and "Hostname"
            New-Object -TypeName PSObject -Property @{
                IPAddress = $ipAddress
                Hostname  = $hostname
            }
        }
    } | ConvertTo-Html -Fragment
}

function Convert-XmlToHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [xml]$XmlDocument
    )

    # Initialize the HTML output
    $html = '<table border="1">'

    # Get the root element of the XML document
    $root = $XmlDocument.SelectSingleNode("/*")

    # Create the table header row
    $html += '<tr>'
    foreach ($node in $root.ChildNodes) {
        $html += "<th>$($node.Name)</th>"
    }
    $html += '</tr>'

    # Iterate each child element of the root element
    foreach ($item in $root.SelectNodes('./*')) {
        $html += '<tr>'

        # Iterate each child node of the item element
        foreach ($node in $item.ChildNodes) {
            $html += "<td>$($node.InnerText)</td>"
        }

        $html += '</tr>'
    }

    $html += '</table>'

    # Output the HTML
    Write-Output $html
}

$css = @"
<style>
h1 {
    font-family: Arial, Helvetica, sans-serif;
    color: #8B008B;
    font-size: 32px;
}

h2 {
    font-family: Arial, Helvetica, sans-serif;
    color: #00BFFF;
    font-size: 24px;
}

table {
    font-size: 14px;
    border: 1px solid #ddd; 
    font-family: Arial, Helvetica, sans-serif;
    border-collapse: collapse;
    width: 100%;
}

td, th {
    border: 1px solid #ddd;
    padding: 8px;
}

th {
    background-color: #4CAF50;
    color: white;
}

tbody tr:nth-child(even) {
    background-color: #f2f2f2;
}

div {
    font-family: Arial, Helvetica, sans-serif;
    font-size: 12px;
}

pre {
    font-size: 14px;
    border: 1px solid #ddd; 
    font-family: Arial, Helvetica, sans-serif;
}

#CreationDate {
    font-family: Arial, Helvetica, sans-serif;
    color: #ff9900;
    font-size: 14px;
}

.StopStatus {
    color: #ff0000;
}

.RunningStatus {
    color: #008000;
}

.FalseStatus {
    color: #ff0000;
}

.TrueStatus {
    color: #008000;
}

.back-link {
    float: right;
    margin-right: 100px;
    font-family: Arial, Helvetica, sans-serif;
    color: #8B008B;
    font-size: 32px;
    display: inline-block;
}

.page-break {
    page-break-after: always;
}

.header {
    width: 100%;
    text-align: center;
    background-color: #303745;
}

.header img {
    display: inline-block;
    vertical-align: middle;
}

ul {
    list-style: none;
    padding: 0;
    font-family: Arial, Helvetica, sans-serif;
    column-count: 3;
    column-gap: 20px;
    column-rule: 1px solid #ccc;
}

li {
    font-family: Arial, Helvetica, sans-serif;
    margin: 10px 0;
}
  
a {
    text-decoration: none;
    color: #395870;
    font-size: 16px;
}
  
a:hover {
    color: #e68a00;
}  
</style>
"@

Set-Location $sysinternalsPath


$ComputerName = "<h2>Computer name: $env:computername</h2>"
$ComputerInfo = Get-SystemInfo

$exists = Invoke-CommandCheck -Command "Get-LocalUser"
if ($exists) {
    $LocalUserInfo = Get-LocalUser | Select-Object -Property Name, Description, Enabled | ConvertTo-HTML -Fragment
    $LocalGroupInfo = Get-LocalGroup | ForEach-Object {
        $members = Get-LocalGroupMember -Group "$($_.Name)" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

        New-Object -TypeName PSObject -Property @{
            Name    = $_.Name
            Members = $members -join ','
        }
    } | ConvertTo-HTML -Property Name, Members -Fragment
}
else {
    $LocalUsers = Get-CimInstance -ClassName win32_useraccount -Filter "LocalAccount='True'"
    $LocalUserInfo = $LocalUsers | Select-Object -ExpandProperty Name
    
    $groupsList = net localgroup
    $LocalGroupInfo = $groupsList | ForEach-Object {
        $group = $_.Replace("*", "")
        $members = net localgroup $group | Select-String "^[^ ].*$" | Select-String -NotMatch "^(Alias name|Comment|Members|The command completed successfully.)" | Select-Object -Skip 1
        
        New-Object -TypeName PSObject -Property @{
            Name    = $group
            Members = $members
        }
    }
}

$MemoryInfo = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object FreePhysicalMemory, TotalVisibleMemorySize | ConvertTo-Html -Fragment
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -As List -Property Version, Caption, BuildNumber, Manufacturer -Fragment
$ProcessInfo = Get-CimInstance -ClassName Win32_Processor | ConvertTo-Html -As List -Property DeviceID, Name, Caption, MaxClockSpeed, SocketDesignation, Manufacturer -Fragment
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS | ConvertTo-Html -As List -Property SMBIOSBIOSVersion, Manufacturer, Name, SerialNumber -Fragment
$DiskInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ConvertTo-Html -As List -Property DeviceID, DriveType, ProviderName, VolumeName, Size, FreeSpace -Fragment

$WindowsFeaturesInfo = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | Select-Object FeatureName | ConvertTo-Html -Property FeatureName -Fragment
$ServicesInfo = Get-CimInstance -ClassName Win32_Service | Select-Object -First 10  | ConvertTo-Html -Property Name, DisplayName, State -Fragment
$ServicesInfo = $ServicesInfo -replace '<td>Running</td>', '<td class="RunningStatus">Running</td>'
$ServicesInfo = $ServicesInfo -replace '<td>Stopped</td>', '<td class="StopStatus">Stopped</td>'
$ProcessesInfo = Get-CimInstance -ClassName Win32_Process | Select-Object -First 10 | ConvertTo-Html -Property Name, ProcessId, Priority -Fragment

$NetworkAdapterInfo = Get-CimInstance -ClassName Win32_NetworkAdapter | Select-Object -Property Name, Description, Manufacturer, MACAddress | ConvertTo-Html -Property Name, Description, Manufacturer, MACAddress -Fragment
$IPAddressInfo = Get-NetIPAddress | Select-Object InterfaceIndex, AddressFamily, IPAddress, PrefixLength | ConvertTo-Html -Property InterfaceIndex, AddressFamily, IPAddress, PrefixLength
$DNSCacheInfo = Get-DnsClientCache | ConvertTo-Html -Property Entry, TimeToLive, Data -Fragment
$ARPCacheInfo = Get-NetNeighbor | Select-Object -Property IPAddress, LinkLayerAddress | ConvertTo-Html -Property IPAddress, LinkLayerAddress -Fragment
$RoutingTableInfo = Get-NetRoute | Select-Object -Property DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, Protocol | ConvertTo-Html -Property DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, Protocol -Fragment
$HostEntriesInfo = Get-HostEntries

$FirewallRulesInfo = Get-NetFirewallRule | Select-Object -Property DisplayName, Enabled, Direction, Action | ConvertTo-Html -Property DisplayName, Enabled, Direction, Action -Fragment
$FirewallRulesInfo = $FirewallRulesInfo -replace '<td>False</td>', '<td class="FalseStatus">False</td>'
$FirewallRulesInfo = $FirewallRulesInfo -replace '<td>True</td>', '<td class="TrueStatus">True</td>'
$TCPPortInformation = .\tcpvcon64.exe -a -c /accepteula -nobanner | Out-String | ConvertFrom-Csv -Delimiter ',' -Header Protocol, Process, ID, State, Local, Remote | ConvertTo-Html -Fragment

$ProcessConnectionsInfo = Get-NetTCPConnection | ConvertTo-Html -Property OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State -Fragment

$StartupProcessesInfo = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -First 10 | ConvertTo-Html -Property Caption, Command, Location, User -Fragment
$ScheduledTasksInfo = Get-CimInstance -ClassName Win32_ScheduledJob | Select-Object -First 10 | ConvertTo-Html -Property Caption, Command, ScheduledStartTime, StartTime, Status -Fragment

$AutoRunInformation = .\autorunsc.exe -a * -m -c /accepteula | Select-Object -Skip 5 | ConvertFrom-Csv | Where-Object { $_.Entry -ne "" } | Select-Object "Entry", "Description", "Image Path", "Enabled" | ConvertTo-Html -Fragment

$USBDevicesInfo = Get-CimInstance -ClassName Win32_USBHub | Select-Object -First 10 | ConvertTo-Html -Property Caption, Description, DeviceID, Manufacturer, Name, SerialNumber -Fragment
$ModifiedFilesInfo = Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-7) } | Select-Object -First 10 | ConvertTo-Html -Property FullName, LastWriteTime, Length -Fragment
$HistoryInfo = Get-History | Select-Object -First 10 | ConvertTo-Html -Property Id, CommandLine, ExecutionStatus, ExecutionTime -Fragment
$PrefetchFilesInfo = Get-ChildItem -Path C:\Windows\Prefetch | Select-Object -First 10 | ConvertTo-Html -Property Name, LastWriteTime, Length -Fragment
$DLLFilesInfo = Get-ChildItem -Path C:\Windows\System32 -Filter "*.dll" | Select-Object -First 10 | ConvertTo-Html -Property Name, LastWriteTime, Length -Fragment
$KerberosSessionsInfo = klist sessions | Select-Object -Skip 2 | ConvertTo-Html -Property Session, Client, Server, Ticket, Renew -Fragment
$SMBSessionsInfo = Get-SmbSession | ConvertTo-Html -Property ClientUserName, ClientComputerName, ClientIpAddress, ConnectedTime, ShareName -Fragment
$SharedFoldersInfo = Get-WmiObject -Class Win32_Share | ConvertTo-Html -Property Name, Path, Description -Fragment
$DiskEncryptionInfo = Get-BitLockerVolume | Select-Object -Property MountPoint, EncryptionMethod, @{ Name = 'KeyProtector'; Expression = { $_.KeyProtector.KeyProtectorType } } | ConvertTo-Html -Property MountPoint, EncryptionMethod, KeyProtector -Fragment
$ShadowCopyInfo = Get-CimInstance -ClassName Win32_ShadowCopy | Select-Object ID, VolumeName, DeviceObject, InstallDate | ConvertTo-Html -Property ID, VolumeName, DeviceObject, InstallDate -Fragment
$GroupPolicyInfo = gpresult.exe /r | Out-String
$AuditPolicyInfo = auditpol /get /category:* | Out-String
$InstalledApplicationInfo = Get-CimInstance win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, Localpackage | ConvertTo-Html -Fragment

$LocalLogonInfo = .\psloggedon64.exe -accepteula -nobanner | Out-String
$LogonSessionInfo = .\logonsessions64.exe -c -accepteula -nobanner | ConvertFrom-Csv | ConvertTo-Html -Fragment
$OpenFilesByprocessInfo = .\handle.exe -v -accepteula | Select-Object -Skip 5 | ConvertFrom-Csv | ConvertTo-Html -Fragment
$OpenedExplorerWindowInfo = Get-Process | Where-Object { $_.mainWindowTitle } | Select-Object Id, Name, mainWindowtitle | ConvertTo-Html -Fragment

$EventLogs = wmic nteventlog list brief /format:csv | Where-Object { $_ -ne '' }
$EventLogsInfo = $EventLogs | ConvertFrom-Csv | Select-Object LogFileName, Name, NumberOfRecords, FileSize | ConvertTo-Html -Fragment

$WindowsDefenderQuarantineInfo = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; } | ConvertTo-Html -Fragment -Property TimeCreated, Message

$ApplicationEvents = Get-WinEvent -FilterHashtable @{ Logname = 'Application'; } -MaxEvents 25 | Sort-Object TimeCreated -Descending
$ApplicationEvents = $ApplicationEvents | ConvertTo-Html -Fragment -Property ID, Message, LevelDisplayName, TimeCreated

$SecurityEvents = Get-WinEvent -FilterHashtable @{ Logname = 'Security'; } -MaxEvents 25 | Sort-Object TimeCreated -Descending
$SecurityEvents = $SecurityEvents | ConvertTo-Html -Fragment -Property ID, Message, LevelDisplayName, TimeCreated

$SystemEvents = Get-WinEvent -FilterHashtable @{ Logname = 'System'; } -MaxEvents 25 | Sort-Object TimeCreated -Descending
$SystemEvents = $SystemEvents | ConvertTo-Html -Fragment -Property ID, Message, LevelDisplayName, TimeCreated

Set-Location ../../

$contentSets = @(
    @{ Title = "Computer Information"; Content = $ComputerInfo }
    @{ Title = "Memory Information"; Content = $MemoryInfo }
    @{ Title = "Operating System Information"; Content = $OSinfo }
    @{ Title = "Installed Application Information"; Content = $InstalledApplicationInfo }
    @{ Title = "Local Logon Information"; Content = "<pre>$LocalLogonInfo</pre>" }
    @{ Title = "Local User Information"; Content = "<pre>$LocalUserInfo</pre>" }
    @{ Title = "Local Groups Information"; Content = "<pre>$LocalGroupInfo</pre>" }
    @{ Title = "Logon Session Information"; Content = "<pre>$LogonSessionInfo</pre>" }
    @{ Title = "Processor Information"; Content = $ProcessInfo }
    @{ Title = "BIOS Information"; Content = $BiosInfo }
    @{ Title = "Disk Information"; Content = $DiskInfo }
    @{ Title = "Disk Encryption Information"; Content = $DiskEncryptionInfo }
    @{ Title = "Services Information"; Content = $ServicesInfo }
    @{ Title = "Process Information"; Content = $ProcessesInfo }
    @{ Title = "Enabled Windows Features"; Content = $WindowsFeaturesInfo }
    @{ Title = "Network Information"; Content = $NetworkAdapterInfo }
    @{ Title = "IP Address Information"; Content = $IPAddressInfo }
    @{ Title = "DNS Cache Information"; Content = $DNSCacheInfo }
    @{ Title = "ARP Cache Information"; Content = $ARPCacheInfo }
    @{ Title = "Routing Table Information"; Content = $RoutingTableInfo }  
    @{ Title = "Host Entry Information"; Content = $HostEntriesInfo }
    @{ Title = "Firewall Rules Information"; Content = $FirewallRulesInfo }
    @{ Title = "TCP View and Port Information"; Content = $TCPPortInformation }
    @{ Title = "Startup Processes"; Content = $StartupProcessesInfo }
    @{ Title = "Autorun Processes"; Content = "<pre>$AutoRunInformation</pre>" }
    @{ Title = "Scheduled Tasks"; Content = $ScheduledTasksInfo }
    @{ Title = "USB Device Information"; Content = $USBDevicesInfo }
    @{ Title = "Modified Files Information"; Content = $ModifiedFilesInfo }
    @{ Title = "Open Files by Process Information"; Content = "<pre>$OpenFilesByprocessInfo</pre>" }  
    @{ Title = "PowerShell History"; Content = $HistoryInfo }
    @{ Title = "Windows Prefetch Files Information"; Content = $PrefetchFilesInfo }
    @{ Title = "Windows DLLs"; Content = $DLLFilesInfo }
    @{ Title = "Kerberos Session Information"; Content = $KerberosSessionsInfo }
    @{ Title = "SMB Session Information"; Content = $SMBSessionsInfo }
    @{ Title = "Process Connection Information"; Content = $ProcessConnectionsInfo }
    @{ Title = "Shared Folder Information"; Content = $SharedFoldersInfo }
    @{ Title = "Shadow Copy Information"; Content = $ShadowCopyInfo }
    @{ Title = "Group Policy Information"; Content = "<pre>$GroupPolicyInfo</pre>" }
    @{ Title = "Audit Policy Information"; Content = "<pre>$AuditPolicyInfo</pre>" }
    @{ Title = "Current Opened Explorer Windows"; Content = $OpenedExplorerWindowInfo }
    @{ Title = "Event Logs Information"; Content = "<pre>$EventLogsInfo</pre>" }
    @{ Title = "Windows Defender Quarantine Information"; Content = $WindowsDefenderQuarantineInfo }
    @{ Title = "Application Event Log Entries"; Content = "<pre>$ApplicationEvents</pre>" }
    @{ Title = "Security Event Log Entries"; Content = "<pre>$SecurityEvents</pre>" }
    @{ Title = "System Event Log Entries"; Content = "<pre>$SystemEvents</pre>" }
)
New-HtmlDocument -FilePath "$reportLocation$reportName" -ContentSets $contentSets -Css $css -LogoPath $logoPath

Start-Process "$reportLocation$reportName"