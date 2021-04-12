#PowewerShell - Final Exam
#Student Name: Dylen Stewart
#Course #: IT-154-900
#Date:4/4/2021
##########################################################

#Question #1
#No need to add scripts for this question


#region Question #2

# I used this on DC1,DC2,and Client1 since the firewall is enabled.
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False 

# I used this to test the conection from Client1. This can be modified to be used for the other machines.
Test-Connection -ComputerName DC1,DC2

# The DnsServerZone for DC1
Get-DnsServerZone -ComputerName DC1

#This is for getting the Dns Resource Record.
Get-DnsServerResourceRecord -ZoneName "ITNET-154.pri"

#submitted by Dylen Stewart
#date 4/4/2021


#endregion 


#region Question #3

#Used this on DC1
Add-WindowsFeature -IncludeManagementTools dhcp

#Used this to add some basic secruity groups
netsh dhcp add securitygroups

#Used this to authorize DHCP server
Add-DhcpServerInDC

#This gets rid of the DCHP notifaction 
Set-ItemProperty `
        –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
        –Name ConfigurationState `
        –Value 2
        
#Adding a Scope to the DHCP Server
Add-DhcpServerv4Scope `
        -Name “192.168.20.0” `
        -StartRange 192.168.20.240 `
        -EndRange 192.168.20.250 `
        -SubnetMask 255.255.255.0 `
        -ComputerName DC1 `
        -LeaseDuration 8:0:0:0 `
        -verbose

#Adding extra settings to the scope
Set-DhcpServerv4OptionValue  `
        -ScopeId 192.168.20.0 `
        -ComputerName DC1.ITNET-154.pri `
        -DnsServer 192.168.20.101 `
        -DnsDomain itnet-154.pri `
        -Router 192.168.20.1 `
        -Verbose

#Used this to change IP Address of Client1
#Remove IP address
$interface = Get-NetAdapter -Physical | Get-NetIPInterface -AddressFamily "IPv4"
#if DHCP is enabled there's nothing to do
#If DHCP is disabled (static IP address), remove the default gateway, remove DNS and then enable DHCP, which will delete static IP
If ($interface.Dhcp -eq "Disabled") {
 # Remove existing gateway
 If (($interface | Get-NetIPConfiguration).Ipv4DefaultGateway) { $interface | Remove-NetRoute -Confirm:$false }
 # Enable DHCP
 $interface | Set-NetIPInterface -DHCP Enabled
 # Configure the DNS Servers automatically
 $interface | Set-DnsClientServerAddress -ResetServerAddresses
}

#This and the next script are used to test the DHCP scope.

Get-DhcpServerv4Lease -ScopeId 192.168.20.0

Test-NetConnection 192.168.20.201

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #4

#This is used to make a new OU
New-ADOrganizationalUnit -Name DAs -Path "DC=ITNET-154, DC=pri"

#Since Domain Admins is already made, we just have to add the Domain admin users with this.
New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "DomainAdmin1" `
-Enabled $true `
-Path "OU=DAs, DC=ITNET-154, DC=pri" `
-SamAccountName DomainAdmin1 `
-UserPrincipalName ("Admin1@ITNET-154.pri")

New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "DomainAdmin20" `
-Enabled $true `
-Path "OU=DAs, DC=ITNET-154, DC=pri" `
-SamAccountName DomainAdmin20 `
-UserPrincipalName ("Admin2@ITNET-154.pri")

#Make the new users Domain Admins
Add-ADGroupMember -Identity 'Domain Admins' -Members 'DomainAdmin1','DomainAdmin20'

#Now to help show our work on DC2
(Get-CimInstance -ClassName Win32_ComputerSystem | select username).username

Get-LocalUser

#Show Domain Admins
Get-ADGroupMember "Domain Admins"

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #5

#Make OUs and sub OUs
New-ADOrganizationalUnit -Name Employees -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Workstations -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name "Member Servers" -Path "DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Employees, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Employees, DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Workstations, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Workstations, DC=ITNET-154, DC=pri"

#Now to show the OU are created
Get-ADOrganizationalUnit -Filter * | Select DistinguishedName | ft -auto

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #6 

#An OU Called Temp Employess
New-ADOrganizationalUnit -Name TempEmployees -Path "DC=ITNET-154, DC=pri"

#Create 50 Users. Gonna modify the script below

#The following script can be used to create bulk users
#Create 20 Users.ps1
#3/9/2019

#$DomainName set to your domain
$domainName = "ITNET-154.pri"

#$Path should be set to the distinguished name of the OU where users will be created
#The following will show Distinguished Names for all OUs
Get-ADOrganizationalUnit -Filter * | select-object name, distinguishedname

$path = "OU=TempEmployees,DC=ITNET-154,DC=pri"

#$total should be set to how many users you want to create
$total=50

#The following block of code will get executed multiple times (or whatever the value of $total is set to.
1..$total |foreach { 
$userName = "Worker$_"
Write-Host "Creating user $userName@$domainName.  User $_ of $total" 

New-ADUser -AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "$userName" `
-Enabled $true `
-Path $path `
-SamAccountName "$userName" `
-UserPrincipalName ($userName + "@" + $domainName)
}

Get-ADUser -Filter * -SearchBase $path

#Lastly show the Users are made
$path = "OU=TempEmployees,DC=ITNET-154,DC=pri"
Get-ADUser -Filter * -SearchBase $path

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #7 

#Create the Global Security Group
New-ADGroup -GroupScope Global -name "GG_Factory"

#Move Users to group
1..5 | foreach {Add-ADGroupMember -Identity "GG_Factory" -Members "Worker$_" }

#Double Check time
Get-ADGroupMember -Identity "GG_Factory"

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #8

#Create the Global Security Group, but with a new name.
New-ADGroup -GroupScope Global -name "GG_Office"

#Move Users to group...A cooler Group that is
6..10 | foreach {Add-ADGroupMember -Identity "GG_Office" -Members "Worker$_" }

#Double Check time... or is it? (It is).
Get-ADGroupMember -Identity "GG_Office"

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #9

#Move some workers to some OUs
$factory ="OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"
$office = "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"

1..5 | foreach { Get-aduser "Worker$_" | Move-ADObject -TargetPath $factory }

6..10 | foreach { Get-aduser "Worker$_" | Move-ADObject -TargetPath $office }

#Lets see how are Employee sub folder is looking like
Get-ADUser -Filter * -SearchBase $factory

Get-ADUser -Filter * -SearchBase $office

#submitted by Dylen Stewart
#date 4/11/2021

#endregion

#region Question #10

#Create a new global security Group
New-ADGroup -GroupScope Global -name "GG_AllEmployees"

#Add all Employee groups to the new Secruity Group
Add-ADGroupMember -Identity "GG_AllEmployees" -Members "GG_Factory" 

Add-ADGroupMember -Identity "GG_AllEmployees" -Members "GG_Office"

#Now show the groups members
Get-ADGroupMember -Identity "GG_AllEmployees"

#submitted by Dylen Stewart
#date 4/11/2021

#endregion 
