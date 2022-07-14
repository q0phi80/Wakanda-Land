# Join the Windows 10 to the domain
$domain = "first.local"
$password = ConvertTo-SecureString "Password@1" -asPlainText -Force
$username = "admin"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -NewName "Wkstn-1" -Credential $credential
Invoke-Command -Scriptblock {net localgroup "Remote Desktop Users" "first\domain users" /add}
Restart-Computer -Force