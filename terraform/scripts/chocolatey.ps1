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
choco install git -y
choco install googlechrome -y
choco install processhacker -y
choco install python -y
choco install burp-suite-free-edition -y
choco install zap -y
choco install autopsy -y
choco install 7zip -y
choco install adobereader -y
choco install adexplorer -y
choco install apimonitor -y
choco install apktool -y
choco install netfx-4.8 -y
choco install cutter -y
choco install dnspy -y
choco install ghidra -y
choco install golang -y
choco install ida-free -y
choco install javadecompiler-gui -y

# Pause for 10 seconds
Start-Sleep -Seconds 10
git clone https://github.com/BloodHoundAD/SharpHound3.git C:\toolz\SharpHound3
git clone https://github.com/adrecon/ADRecon.git C:\toolz\ADRecon
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git C:\toolz\Ghostpack
git clone https://github.com/danielmiessler/SecLists.git C:\toolz\SecLists

#change the computer's name
Rename-Computer -NewName "WKSTN-001" -Restart -Force
</powershell>