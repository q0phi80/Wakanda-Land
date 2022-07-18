# Join the Windows 10 to the domain
# Start-Sleep -Seconds 300
$domain = "first.local"
$password = ConvertTo-SecureString "Password@1" -asPlainText -Force
$username = "admin@first.local"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -NewName "WKSTN-001" -Credential $credential
Invoke-Command -Scriptblock {net localgroup "Remote Desktop Users" "first\domain users" /add}
Restart-Computer -Force