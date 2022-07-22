configuration Jungle {

    param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory)]
        [string]$bastDomainName,
        [Parameter(Mandatory)]
        [string]$wakandaDomainName,
        [Parameter(Mandatory)]
        [pscredential]$bastDomainCred
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node "Bast" {

        Computer NewName {
            Name = "Baku-DC"
        }
        
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        User Bashenga {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Pantheon {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]Bashenga"
        }

        ADDomain CreateDC {
            DomainName = $bastDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitBastDomain {
            DomainName = $bastDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1', '10.0.2.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }

            TestScript = {
                $zone = Get-DnsServerZone -Name $using:wakandaDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }

            SetScript = {
                $ForwardDomainName = $using:wakandaDomainName
                $IpAddresses = @("10.0.2.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }

            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADGroup Orisha {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADUser 'Wakandan'
        {
            Ensure     = 'Present'
            UserName   = 'Wakandan'
            Password   = (New-Object System.Management.Automation.PSCredential("Wakandan", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADUser 'Thoth'
        {
            Ensure     = 'Present'
            UserName   = 'Thoth'
            Password   = (New-Object System.Management.Automation.PSCredential("Thoth", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADGroup Heliopolitan {
            Ensure = "Present"
            GroupName = "DnsAdmins"
            MembersToInclude = "Thoth"
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Thoth"
        }

        ADUser 'Kokou'
        {
            Ensure     = 'Present'
            UserName   = 'Kokou'
            Password   = (New-Object System.Management.Automation.PSCredential("Kokou", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Kokou Unconstrained Delegation Set"
        {
            SetScript = {
                Set-ADAccountControl -Identity "Kokou" -TrustedForDelegation $True
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Kokou" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Kokou"
        }

        ADUser 'Mujaji' 
        {
            Ensure     = 'Present'
            UserName   = 'Mujaji'
            Password   = (New-Object System.Management.Automation.PSCredential("Mujaji", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Mujaji constrained Delegation Set"
        {
            SetScript = {
                $user = (Get-ADUser -Identity "Mujaji").DistinguishedName
                Set-ADObject -Identity $user -Add @{"msDS-AllowedToDelegateTo" = @("CIFS/Baku-DC","CIFS/Baku-DC.Bast.land","CIFS/Baku-DC.bast.land/bast.land")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Mujaji" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Mujaji"
        }

        ADComputer "Sekhmet" 
        {
            Ensure = "Present"
            ComputerName = "Sekhmet-PC"
            Path = "CN=Computers,DC=bast,DC=land"
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Sekhmet-PC constrained Delegation Set"
        {
            SetScript = {
                $comp = (Get-ADComputer -Identity "Sekhmet-PC").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HTTP/Baku-DC","HTTP/Baku-DC.Bast.land","HTTP/Baku-DC.bast.land/bast.land")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "Sekhmet-PC" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADUser 'Sobek'
        {
            Ensure     = 'Present'
            UserName   = 'Sobek'
            Password   = (New-Object System.Management.Automation.PSCredential("Sobek", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Sobek Write Permissions on User Mujaji"
        {
            SetScript = {
                $Destination = (Get-ADUser -Identity "Mujaji").DistinguishedName
                $Source = (Get-ADUser -Identity "Sobek").sid
                $Rights = "GenericWrite"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Sobek" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Sobek"
        }

        ADUser 'Ghekre'
        {
            Ensure     = 'Present'
            UserName   = 'Ghekre'
            Password   = (New-Object System.Management.Automation.PSCredential("Ghekre", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Ghekre GenericAll Permissions on User Sobek"
        {
            SetScript = {
                $Destination = (Get-ADUser -Identity "Sobek").DistinguishedName
                $Source = (Get-ADUser -Identity "Ghekre").sid
                $Rights = "GenericAll"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Ghekre" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Ghekre"
        }

        ADUser 'Ngi'
        {
            Ensure     = 'Present'
            UserName   = 'Ngi'
            Password   = (New-Object System.Management.Automation.PSCredential("Ngi", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Ngi Write Permissions on Comp Baku-DC"
        {
            SetScript = {
                $Destination = (Get-ADComputer -Identity "Baku-DC").DistinguishedName
                $Source = (Get-ADUser -Identity "Ngi").sid
                $Rights = "GenericWrite"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Ngi" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Ngi"
        }

        ADUser 'Hadari-Yao'
        {
            Ensure     = 'Present'
            UserName   = 'Hadari-Yao'
            Password   = (New-Object System.Management.Automation.PSCredential("Hadari-Yao", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Hadari-Yao Write Permissions on GPO"
        {
            SetScript = {
                Set-GPPermission -Name "Default Domain Controllers Policy" -TargetName "Hadari-Yao" -TargetType "User" -PermissionLevel "GpoEdit"
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Hadari-Yao" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Hadari-Yao"
        }

        ADUser 'Yaounde'
        {
            Ensure     = 'Present'
            UserName   = 'Yaounde'
            Password   = (New-Object System.Management.Automation.PSCredential("Yaounde", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            Description = 'LAPS yet to be implemented'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADUser 'Baoule'
        {
            Ensure     = 'Present'
            UserName   = 'Baoule'
            Password   = (New-Object System.Management.Automation.PSCredential("Baoule", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Baoule Write Permissions on Domain Admins Group"
        {
            SetScript = {
                $Destination = (Get-ADGroup -Identity "Domain Admins").DistinguishedName
                $Source = (Get-ADUser -Identity "Baoule").sid
                $Rights = "GenericAll"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Baoule" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Baoule"
        }

        ADUser 'Hanuman'
        {
            Ensure     = 'Present'
            UserName   = 'Hanuman'
            Password   = (New-Object System.Management.Automation.PSCredential("Hanuman", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Hanuman WriteDACL Permissions on Baku-DC"
        {
            SetScript = {
                $Destination = (Get-ADComputer -Identity "Baku-DC").DistinguishedName
                $Source = (Get-ADUser -Identity "Hanuman").sid
                $Rights = "WriteDACL"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Hanuman" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Hanuman"
        }

        ADUser 'Akamba'
        {
            Ensure     = 'Present'
            UserName   = 'Akamba'
            Password   = (New-Object System.Management.Automation.PSCredential("Akamba", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            Description = 'GMSA yet to be implemented'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADUser 'Mmusa'
        {
            Ensure     = 'Present'
            UserName   = 'Mmusa'
            Password   = (New-Object System.Management.Automation.PSCredential("Mmusa", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Mmusa Password disclosed in Description"
        {
            SetScript = {
                Set-ADUser -Identity "Mmusa" -Description "Remember to remove this! Password@1"
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Mmusa" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Mmusa"
        }

        ADUser 'Plumumba'
        {
            Ensure     = 'Present'
            UserName   = 'Plumumba'
            Password   = (New-Object System.Management.Automation.PSCredential("Plumumba", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            ServicePrincipalNames = "MSSQL/sql.bast.land"
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        ADUser Knkrumah
        {
            Ensure     = 'Present'
            UserName   = 'Knkrumah'
            Password   = (New-Object System.Management.Automation.PSCredential("Knkrumah", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=bast,DC=land'
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Knkrumah PreAuth Disable"
        {
            SetScript = {
                Set-ADAccountControl -Identity "Knkrumah" -DoesNotRequirePreAuth $true
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Knkrumah" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain", "[ADUser]Knkrumah"
        }

        Script "Nakia-RDP"
        {
            SetScript = {
                Start-Sleep -Wakandas 300
                Invoke-Command -ComputerName "Nakia" -Scriptblock {net landgroup "Remote Desktop Users" "bast\domain users" /add}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "Nakia" ) } 
            }
            PsDscRunAsCredential = $bastDomainCred
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script "Ramonda-RDP" {
            SetScript            = {
                Start-Sleep -Wakandas 300
                Invoke-Command -ComputerName "Ramonda" -Scriptblock { net landgroup "Remote Desktop Users" "bast\domain users" /add }
            }
            TestScript           = { 
                $false 
            }
            GetScript            = { 
                @{ Result = (Get-ADComputer "Ramonda" ) } 
            }
            PsDscRunAsCredential = $bastDomainCred
            DependsOn            = "[WaitForADDomain]waitBastDomain"
        }

        Script "Nakia Comp constrained Delegation Set"
        {
            SetScript = {
                $comp = (Get-ADComputer -Identity "Nakia").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HOST/Baku-DC","HOST/Baku-DC.Bast.land","HOST/Baku-DC.bast.land/bast.land")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "Nakia" ) } 
            }
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
                $global:DSCMachineStatus = 1
            }
        }
    }

    Node "Nakia" {
        
        WaitForAll DC
        {
            ResourceName      = '[ADUser]Knkrumah'
            NodeName          = 'Baku-DC'
            RetryIntervalSec  = 60
            RetryCount        = 15
        }
        
        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }
        
        User landuser {
            Ensure = "Present"
            UserName = "land-user"
            Password = $DomainCred
        }

        Group Pantheon {
            GroupName = "Administrators"
            MembersToInclude = "land-user"
            DependsOn = "[User]landuser"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Pantheon"
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
            }
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        Script EnablePSRemoting {
            GetScript  = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript  = {
                Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
            }
        }

        WaitForADDomain waitBastDomain {
            DomainName = $bastDomainName
            Credential = $bastDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "Nakia"
            DomainName = $bastDomainName
            Credential = $bastDomainCred
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }
    }

    Node "Ramonda" {
        
        WaitForAll DC
        {
            ResourceName      = '[ADUser]Knkrumah'
            NodeName          = 'Baku-DC'
            RetryIntervalSec  = 60
            RetryCount        = 15
        }
        
        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }
        
        User landuser {
            Ensure = "Present"
            UserName = "land-user"
            Password = $DomainCred
        }

        Group Pantheon {
            GroupName = "Administrators"
            MembersToInclude = "land-user"
            DependsOn = "[User]landuser"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Pantheon"
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
            }
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }
        Script EnableWinRM {
            GetScript  = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript  = {
                Set-WSManQuickConfig -Force
                Set-Service -Name "WinRM" -StartupType Automatic
            }
        }

        Script EnablePSRemoting {
            GetScript  = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript  = {
                Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
            }
        }

        WaitForADDomain waitBastDomain {
            DomainName = $bastDomainName
            Credential = $bastDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "Ramonda"
            DomainName = $bastDomainName
            Credential = $bastDomainCred
            DependsOn = "[WaitForADDomain]waitBastDomain"
        }
    }

    Node "Wakanda" {

        Computer NewName {
            Name = "Challa-DC"
        }
        
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        User Bashenga {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Pantheon {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]Bashenga"
        }
        
        ADDomain CreateDC {
            DomainName = $wakandaDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitWakandaDomain {
            DomainName = $wakandaDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1', '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitWakandaDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }

            TestScript = {
                $zone = Get-DnsServerZone -Name $using:bastDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }

            SetScript = {
                $ForwardDomainName = $using:bastDomainName
                $IpAddresses = @("10.0.1.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }
        }

        ADGroup Orisha {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitWakandaDomain"
        }

        ADUser 'Wakandan'
        {
            Ensure     = 'Present'
            UserName   = 'Wakandan'
            Password   = (New-Object System.Management.Automation.PSCredential("Wakandan", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'wakanda.land'
            Path       = 'CN=Users,DC=wakanda,DC=land'
            DependsOn = "[WaitForADDomain]waitWakandaDomain"
        }

        ADUser 'Plumumba'
        {
            Ensure     = 'Present'
            UserName   = 'Plumumba'
            Password   = (New-Object System.Management.Automation.PSCredential("Plumumba", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'wakanda.land'
            Path       = 'CN=Users,DC=wakanda,DC=land'
            ServicePrincipalNames = "MSSQL/sql.wakanda.land"
            DependsOn = "[WaitForADDomain]waitWakandaDomain"
        }

        ADUser 'Knkrumah'
        {
            Ensure     = 'Present'
            UserName   = 'Knkrumah'
            Password   = (New-Object System.Management.Automation.PSCredential("Knkrumah", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'wakanda.land'
            Path       = 'CN=Users,DC=wakanda,DC=land'
            DependsOn = "[WaitForADDomain]waitWakandaDomain"
        }

        WaitForADDomain waitBastDomain {
            DomainName = $bastDomainName
            Credential = $bastDomainCred
            WaitTimeout = 600
            RestartCount = 2
            DependsOn = "[Script]SetConditionalForwardedZone"
        }

        ADDomainTrust DomainTrust {
            TargetDomainName = $bastDomainName
            TargetCredential = $bastDomainCred
            TrustType = "External"
            TrustDirection = "Bidirectional"
            SourceDomainName = $wakandaDomainName
            DependsOn = "[WaitForADDomain]waitBastDomain"
            Ensure = "Present"
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
                $global:DSCMachineStatus = 1
            }
        }
    }
}

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename                    = "Bast"
            Role                        = "Bast DC"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "Nakia"
            Role                        = "User Server"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        },
        @{
            Nodename                    = "Ramonda"
            Role                        = "User Workstation"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        },
        @{
            Nodename                    = "Wakanda"
            Role                        = "Wakanda DC"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        }
    )
}

Jungle -ConfigurationData $ConfigData `
    -bastDomainName "bast.land" `
    -wakandaDomainName "wakanda.land" `
    -domainCred (New-Object System.Management.Automation.PSCredential("tsankara", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -safemodeAdministratorCred (New-Object System.Management.Automation.PSCredential("tsankara", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -bastDomainCred (New-Object System.Management.Automation.PSCredential("bast-tsankara", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) 