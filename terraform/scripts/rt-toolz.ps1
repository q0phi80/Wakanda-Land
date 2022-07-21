# Create a directory on the C drive to store tools
New-Item -Path 'C:\toolz' -ItemType Directory

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install some stuff
choco install git googlechrome processhacker python burp-suite-free-edition zap autopsy 7zip adobereader adexplorer apimonitor apktool netfx-4.8 cutter dnspy ghidra golang ida-free javadecompiler-gui firefox wget -y

# Pause for 60 seconds
Start-Sleep -Seconds 60
Set-Location C:\toolz
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.zip
wget https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip
# git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git
# git clone https://github.com/danielmiessler/SecLists.git
