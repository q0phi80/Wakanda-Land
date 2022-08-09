# Join the Windows 10 to the domain

# First, wait for 3 minutes (you can manipulate this for give the host some briefing room after installing toolz)
Start-Sleep -Seconds 60
$domain = "bast.land"
$password = ConvertTo-SecureString "Password@1" -asPlainText -Force
$username = "tsankara@bast.land"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Add-Computer -DomainName $domain -NewName "Ramonda" -Credential $credential
Invoke-Command -Scriptblock {net localgroup "Remote Desktop Users" "bast\domain users" /add}
Invoke-Command -Scriptblock {net localgroup "Administrators" "bast\Wakandan" /add}