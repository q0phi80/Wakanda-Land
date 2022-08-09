# Create a directory on the C drive to store toolz
New-Item -Path 'C:\toolz' -ItemType Directory

# Install chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install some toolz
choco install git googlechrome processhacker python burp-suite-free-edition zap autopsy 7zip adobereader adexplorer apimonitor apktool netfx-4.8 cutter dnspy ghidra golang ida-free javadecompiler-gui firefox wget -y

# Download more toolz
Set-Location -Path "C:\toolz"
Invoke-WebRequest -Uri https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip -OutFile BloodHound.zip
