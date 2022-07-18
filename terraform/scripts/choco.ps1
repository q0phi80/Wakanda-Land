<powershell>
# Create a directory on the C drive to store tools
New-Item -Path 'C:\toolz' -ItemType Directory

# Set directory for installation - Chocolatey does not lock
# down the directory if not the default
$InstallDir='C:\ProgramData\chocoportable'
$env:ChocolateyInstall="$InstallDir"

# If your PowerShell Execution policy is restrictive, you may
# not be able to get around that. Try setting your session to
# Bypass.
Set-ExecutionPolicy Bypass -Scope Process -Force;

# All install options - offline, proxy, etc at
# https://chocolatey.org/install
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install some stuff
choco install git googlechrome processhacker python burp-suite-free-edition zap autopsy 7zip adobereader adexplorer apimonitor apktool netfx-4.8 cutter dnspy ghidra golang ida-free javadecompiler-gui -Y --force

</powershell>