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
choco install git googlechrome processhacker python burp-suite-free-edition zap autopsy 7zip adobereader adexplorer apimonitor apktool netfx-4.8 cutter dnspy ghidra golang ida-free javadecompiler-gui -y

# Pause for 10 seconds
Start-Sleep -Seconds 60
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git C:\toolz\Ghostpack
git clone https://github.com/danielmiessler/SecLists.git C:\toolz\SecLists

#change the computer's name
# Rename-Computer -NewName "WKSTN-001" -Restart -Force
</powershell>