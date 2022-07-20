# Join the Windows 10 to the domain
Start-Sleep -Seconds 300
$domain = "bast.land"
$password = ConvertTo-SecureString "Password@1" -asPlainText -Force
$username = "tsankara@bast.land"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -NewName "Ramonda" -Credential $credential
Invoke-Command -Scriptblock {net localgroup "Remote Desktop Users" "bast\domain users" /add}
# Restart-Computer -Force