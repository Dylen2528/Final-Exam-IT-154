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
#submitted by
#date

#endregion

#region Question #6 
#submitted by
#date

#endregion

#region Question #7 
#submitted by
#date

#endregion

#region Question #8
#submitted by
#date

#endregion

#region Question #9
#submitted by
#date

#endregion

#region Question #10
#submitted by
#date

#endregion 
