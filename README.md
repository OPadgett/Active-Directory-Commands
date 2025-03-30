# Active Directory PowerShell Commands Tutorial

## 1. Listing Active Directory Users
**Bash:**
net user /domain

**Powershell:**
Get-ADUser -Filter *
## 2. Creating New Users
**Bash:**
net user username password /add /domain

**Powershell:**
New-ADUser -SamAccountName "username" -UserPrincipalName "username@domain.com" -Name "Full Name" -GivenName "First" -Surname "Last" -DisplayName "Full Name" -PasswordNeverExpires $true -Enabled $true
## 3. Setting a User's Password
**Bash:**
net user username newpassword /domain

**Powershell:**
Set-ADAccountPassword -Identity "username" -NewPassword (ConvertTo-SecureString -AsPlainText "newpassword" -Force)
## 4. Unlocking a User Account
**Bash:**
net user username /active:yes /domain

**Powershell:**
Unlock-ADAccount -Identity "username"
## 5. Disabling a User Account
**Bash:**
net user username /active:no /domain

**Powershell:**
Disable-ADAccount -Identity "username"
## 6. Listing Groups in Active Directory
**Bash:**
net group /domain

**Powershell:**
Get-ADGroup -Filter *
## 7. Adding a User to a Group
**Bash:**
net group groupname username /add /domain

**Powershell:**
Add-ADGroupMember -Identity "groupname" -Members "username"
## 8. Removing a User from a Group
**Bash:**
net group groupname username /delete /domain

**Powershell:**
Remove-ADGroupMember -Identity "groupname" -Members "username" -Confirm:$false
## 9. Get a User's Group Memberships
**Bash:**
net user username /domain

**Powershell:**
Get-ADUser "username" | Get-ADUserMembership
## 10. Checking User Account Status
**Bash:**
net user username /domain

**Powershell:**
Get-ADUser "username" | Select-Object SamAccountName, Enabled
## 11. Get Domain Information
**Bash:**
net config workstation

**Powershell:**
Get-ADDomain
## 12. Finding Active Directory Computers
**Bash:**
net view /domain

**Powershell:**
Get-ADComputer -Filter *
