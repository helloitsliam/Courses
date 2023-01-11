# PowerShell Script to Retrieve Details about the Desktop
$Location = "C:\Users\Trainer\PSFolder"

# Retrieve Desktop Settings
$desktop = Get-CimInstance -ClassName Win32_Desktop

# Retrieve BIOS Information
$bios = Get-CimInstance -ClassName Win32_BIOS

# Retrieve Processor Information
$processor = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property SystemType

# Get Computer Manufacturer Details
$manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem

# Get Installed Hotfixes
$hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering

# Get Operating System Version Information
$operatingsystem = Get-CimInstance -ClassName Win32_OperatingSystem | `
    Select-Object -Property BuildNumber,BuildType,OSType,ServicePackMajorVersion,ServicePackMinorVersion

# Get Users and Owners
$usergroups = Get-CimInstance -ClassName Win32_OperatingSystem | `
    Select-Object -Property NumberOfLicensedUsers,NumberOfUsers,RegisteredUser

# Get Currently Logged-on User
$loggedon = Get-CimInstance -ClassName Win32_ComputerSystem -Property UserName

# Get All Services Status
$services = Get-CimInstance -ClassName Win32_Service | Select-Object -Property Status,Name,DisplayName


# Create File
$report = "$($Location)\Report.log"
New-Item $report -ItemType File -Value "Desktop Report"
Add-Content $report "********** Desktop Details **********"
Add-Content $report $desktop
Add-Content $report "********** Bios Details **********"
Add-Content $report $bios
Add-Content $report "********** Processor Details **********"
Add-Content $report $processor
Add-Content $report "********** Manufacturer Details **********"
Add-Content $report $manufacturer
Add-Content $report "********** Hotfix Details **********"
Add-Content $report $hotfixes
Add-Content $report "********** Operating System Details **********"
Add-Content $report $operatingsystem
Add-Content $report "********** Users and Groups Details **********"
Add-Content $report $usergroups
Add-Content $report "********** Logged On User Details **********"
Add-Content $report $loggedon
Add-Content $report "********** Services Details **********"
Add-Content $report $services





value = this.get("ds.LDAP(gram).memberOf"),
value == null ? "default" : value

groupCnOnly = new java.util.ArrayList(),
groups = this.get("memberof")!=null ? this.get("memberof").getValues() : {},
groups.{   
  group = this,   
  group = new javax.naming.ldap.LdapName(group),   
  cn = group.getRdn(group.size()).getValue().toString(), 
  groupCnOnly.add(cn)
},

this.get("memberof")!=null ? new org.sourceid.saml20.adapter.attribute.AttributeValue(groupCnOnly) : null


#memberof=#this.get("memberof").toString(),#idx=#memberOf.indexOf("GROUPNAME"), #result = #idx >= 0 ? "TRUE": "FALSE"

#memberof=#this.get("memberof").getRdn().getValue().toString()

#memberof=#this.get("memberof").getRdn().getValue().toString()

#memberof=#this.get("memberof").getRdn(#group.size() - 1).getValue().toString()



#groupCnOnly = new java.util.ArrayList(),
#groups = #this.get("memberof")!=null ? #this.get("memberof").getValues() : {},
#groups.{   
  #group = #this,   
  #group = new javax.naming.ldap.LdapName(#group),   
  #cn = #group.getRdn(#group.size() - 1).getValue().toString(), 
  #groupCnOnly.add(#cn)
},
 
#this.get("memberof")!=null ? new org.sourceid.saml20.adapter.attribute.AttributeValue(#groupCnOnly) : null