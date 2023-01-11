###############
## Variables ##
###############

$remoteComputerName = "WIN2019"
[string]$remoteComputerUserName = "TRAINING\Administrator"
[string]$remoteComputerPassword = "bxSn9kGqPZNXwuA"
$remoteCodeFolderPath = "C:\Forensics\Code"
$remoteAssetsFolderPath = "C:\Forensics\Assets"
$remoteSession = $true


###########################
## Create Remote Session ##
###########################

function Invoke-RemoteSession {
    if ($remoteSession) {
        [securestring]$remoteSecureComputerPassword = ConvertTo-SecureString $remoteComputerPassword -AsPlainText -Force
        [pscredential]$remoteCredentials = New-Object System.Management.Automation.PSCredential ($remoteComputerUserName, $remoteSecureComputerPassword)

        $session = New-PSSession -ComputerName $remoteComputerName -Credential $remoteCredentials 
    }
    Write-Host "Session Created" -ForegroundColor Green
    return $session
}


#############################################
## Create Folder Structure and Copy Assets ##
#############################################

function New-FolderStructure {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]$Session
    )

    Invoke-Command -Session $Session -ScriptBlock {
        $startingLocation = "C:\"
        Push-Location $startingLocation
        $forensicDirectory = New-Item -Path $startingLocation -Name "Forensics" -ItemType Directory
        $assetsDirectory = New-Item -Path $forensicDirectory -Name "Assets" -ItemType Directory
        New-Item -Path $forensicDirectory -Name "Code" -ItemType Directory
        New-Item -Path $forensicDirectory -Name "Report" -ItemType Directory
        New-Item -Path $assetsDirectory -Name "Sysinternals" -ItemType Directory
    }
}

function Invoke-FolderStructure {
    $session = Invoke-RemoteSession

    New-FolderStructure -Session $session

    Copy-Item -LiteralPath "C:\Forensics\Code\Assets\Sysinternals\tcpvcon64.exe" -Destination "$remoteAssetsFolderPath\Sysinternals\tcpvcon64.exe" -ToSession $session -Force
    Copy-Item -LiteralPath "C:\Forensics\Code\Assets\Sysinternals\autorunsc.exe" -Destination "$remoteAssetsFolderPath\Sysinternals\autorunsc.exe" -ToSession $session -Force
    Copy-Item -LiteralPath "C:\Forensics\Code\Assets\Sysinternals\psloggedon64.exe" -Destination "$remoteAssetsFolderPath\Sysinternals\psloggedon64.exe" -ToSession $session -Force
    Copy-Item -LiteralPath "C:\Forensics\Code\Assets\Sysinternals\logonsessions64.exe" -Destination "$remoteAssetsFolderPath\Sysinternals\logonsessions64.exe" -ToSession $session -Force
    Copy-Item -LiteralPath "C:\Forensics\Code\Assets\Sysinternals\handle.exe" -Destination "$remoteAssetsFolderPath\Sysinternals\handle.exe" -ToSession $session -Force

    Copy-Item -LiteralPath "C:\Forensics\Code\Assets\Methodize-Logo-Small.png" -Destination "$remoteAssetsFolderPath\Methodize-Logo-Small.png" -ToSession $session
    Copy-Item -LiteralPath "C:\Forensics\Code\Methodize.ps1" -Destination "$remoteCodeFolderPath\Methodize.ps1" -ToSession $session
}

Invoke-FolderStructure