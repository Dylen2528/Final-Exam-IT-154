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

#submitted by
#date


#endregion 


#region Question #3
#submitted by
#date

#endregion

#region Question #4
#submitted by
#date

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
