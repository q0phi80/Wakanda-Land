<powershell>
#Run as admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
{ 
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 
}

Set-ExecutionPolicy Bypass -Scope Process -Force;

Write-Output "Downloading Ansible Installation Script"

$url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$output = "$PSScriptRoot\ConfigureRemotingForAnsible.ps1"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $output)
(New-Object System.Net.WebClient).DownloadFile($url, $output)

Write-Output "Running Ansible Installation Script"

& $output
</powershell>