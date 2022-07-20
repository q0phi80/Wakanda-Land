configuration land {

    param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory)]
        [string]$firstDomainName,
        [Parameter(Mandatory)]
        [string]$secondDomainName,
        [Parameter(Mandatory)]
        [pscredential]$firstDomainCred
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -Module nx

    Node "First" {

        Computer NewName {
            Name = "baku-dc"
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

        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }

        ADDomain CreateDC {
            DomainName = $firstDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1', '10.0.2.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }

            TestScript = {
                $zone = Get-DnsServerZone -Name $using:secondDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }

            SetScript = {
                $ForwardDomainName = $using:secondDomainName
                $IpAddresses = @("10.0.2.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }

            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADGroup DomainAdmin {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'wakandan'
        {
            Ensure     = 'Present'
            UserName   = 'wakandan'
            Password   = (New-Object System.Management.Automation.PSCredential("wakandan", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'Thoth'
        {
            Ensure     = 'Present'
            UserName   = 'Thoth'
            Password   = (New-Object System.Management.Automation.PSCredential("Thoth", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADGroup DnsAdmin {
            Ensure = "Present"
            GroupName = "DnsAdmins"
            MembersToInclude = "Thoth"
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Thoth"
        }

        ADUser 'Kokou'
        {
            Ensure     = 'Present'
            UserName   = 'Kokou'
            Password   = (New-Object System.Management.Automation.PSCredential("Kokou", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Kokou"
        }

        ADUser 'Mujaji' 
        {
            Ensure     = 'Present'
            UserName   = 'Mujaji'
            Password   = (New-Object System.Management.Automation.PSCredential("Mujaji", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Mujaji constrained Delegation Set"
        {
            SetScript = {
                $user = (Get-ADUser -Identity "Mujaji").DistinguishedName
                Set-ADObject -Identity $user -Add @{"msDS-AllowedToDelegateTo" = @("CIFS/baku-dc","CIFS/baku-dc.bast.land","CIFS/baku-dc.bast.land/bast.land")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "Mujaji" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Mujaji"
        }

        ADComputer "Constrained.Computer" 
        {
            Ensure = "Present"
            ComputerName = "Suspicious-PC"
            Path = "CN=Computers,DC=first,DC=local"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Suspicious-PC constrained Delegation Set"
        {
            SetScript = {
                $comp = (Get-ADComputer -Identity "Suspicious-PC").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HTTP/baku-dc","HTTP/baku-dc.bast.land","HTTP/baku-dc.bast.land/bast.land")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "Suspicious-PC" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'Sobek'
        {
            Ensure     = 'Present'
            UserName   = 'Sobek'
            Password   = (New-Object System.Management.Automation.PSCredential("Sobek", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Sobek Write Permissions on User Node"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Sobek"
        }

        ADUser 'Ghekre'
        {
            Ensure     = 'Present'
            UserName   = 'Ghekre'
            Password   = (New-Object System.Management.Automation.PSCredential("Ghekre", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Ghekre GenericAll Permissions on User Node"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Ghekre"
        }

        ADUser 'Ngi'
        {
            Ensure     = 'Present'
            UserName   = 'Ngi'
            Password   = (New-Object System.Management.Automation.PSCredential("Ngi", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Ngi Write Permissions on Comp Node"
        {
            SetScript = {
                $Destination = (Get-ADComputer -Identity "baku-dc").DistinguishedName
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Ngi"
        }

        ADUser "Hadari-Yao"
        {
            Ensure     = 'Present'
            UserName   = 'Hadari-Yao'
            Password   = (New-Object System.Management.Automation.PSCredential("Hadari-Yao", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Hadari-Yao"
        }

        ADUser 'Yaounde'
        {
            Ensure     = 'Present'
            UserName   = 'Yaounde'
            Password   = (New-Object System.Management.Automation.PSCredential("Yaounde", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            Description = 'LAPS yet to be implemented'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'Baoule'
        {
            Ensure     = 'Present'
            UserName   = 'Baoule'
            Password   = (New-Object System.Management.Automation.PSCredential("Baoule", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Baoule Write Permissions on Group"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Baoule"
        }

        ADUser 'Hanuman'
        {
            Ensure     = 'Present'
            UserName   = 'Hanuman'
            Password   = (New-Object System.Management.Automation.PSCredential("Hanuman", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Hanuman WriteDACL Permissions on DC"
        {
            SetScript = {
                $Destination = (Get-ADComputer -Identity "baku-dc").DistinguishedName
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Hanuman"
        }

        ADUser 'Akamba'
        {
            Ensure     = 'Present'
            UserName   = 'Akamba'
            Password   = (New-Object System.Management.Automation.PSCredential("Akamba", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            Description = 'GMSA yet to be implemented'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'Mmusa'
        {
            Ensure     = 'Present'
            UserName   = 'Mmusa'
            Password   = (New-Object System.Management.Automation.PSCredential("Mmusa", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Mmusa Password in AD"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]Mmusa"
        }

        ADUser 'Plumumba'
        {
            Ensure     = 'Present'
            UserName   = 'Plumumba'
            Password   = (New-Object System.Management.Automation.PSCredential("Plumumba", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            ServicePrincipalNames = "MSSQL/sql.bast.land"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser asrep
        {
            Ensure     = 'Present'
            UserName   = 'Knkrumah'
            Password   = (New-Object System.Management.Automation.PSCredential("Knkrumah", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'bast.land'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
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
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]asrep"
        }

        Script "nakia-RDP"
        {
            SetScript = {
                Start-Sleep -Seconds 300
                Invoke-Command -ComputerName "nakia" -Scriptblock {net localgroup "Remote Desktop Users" "first\domain users" /add}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "nakia" ) } 
            }
            PsDscRunAsCredential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "ramonda-RDP" {
            SetScript            = {
                Start-Sleep -Seconds 300
                Invoke-Command -ComputerName "ramonda" -Scriptblock { net localgroup "Remote Desktop Users" "first\domain users" /add }
            }
            TestScript           = { 
                $false 
            }
            GetScript            = { 
                @{ Result = (Get-ADComputer "ramonda" ) } 
            }
            PsDscRunAsCredential = $firstDomainCred
            DependsOn            = "[WaitForADDomain]waitFirstDomain"
        }

        Script "nakia constrained Delegation Set"
        {
            SetScript = {
                $comp = (Get-ADComputer -Identity "nakia").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HOST/baku-dc","HOST/baku-dc.bast.land","HOST/baku-dc.bast.land/bast.land")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "nakia" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
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

    Node "UserServer" {
        
        WaitForAll DC
        {
            ResourceName      = '[ADUser]asrep'
            NodeName          = 'baku-dc'
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
        
        User localuser {
            Ensure = "Present"
            UserName = "local-user"
            Password = $DomainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = "local-user"
            DependsOn = "[User]localuser"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Administrators"
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

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "nakia"
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }
    }

    Node "UserWorkstation" {
        
        WaitForAll DC
        {
            ResourceName      = '[ADUser]asrep'
            NodeName          = 'baku-dc'
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
        
        User localuser {
            Ensure = "Present"
            UserName = "local-user"
            Password = $DomainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = "local-user"
            DependsOn = "[User]localuser"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Administrators"
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

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "ramonda"
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }
    }

    Node "Second" {

        Computer NewName {
            Name = "challa-dc"
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

        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }
        
        ADDomain CreateDC {
            DomainName = $secondDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitSecondDomain {
            DomainName = $secondDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1', '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }

            TestScript = {
                $zone = Get-DnsServerZone -Name $using:firstDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }

            SetScript = {
                $ForwardDomainName = $using:firstDomainName
                $IpAddresses = @("10.0.1.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }
        }

        ADGroup DomainAdmin {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'wakandan'
        {
            Ensure     = 'Present'
            UserName   = 'wakandan'
            Password   = (New-Object System.Management.Automation.PSCredential("wakandan", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'wakanda.land'
            Path       = 'CN=Users,DC=second,DC=local'
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'Plumumba'
        {
            Ensure     = 'Present'
            UserName   = 'Plumumba'
            Password   = (New-Object System.Management.Automation.PSCredential("Plumumba", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'wakanda.land'
            Path       = 'CN=Users,DC=second,DC=local'
            ServicePrincipalNames = "MSSQL/sql.wakanda.land"
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'Knkrumah'
        {
            Ensure     = 'Present'
            UserName   = 'Knkrumah'
            Password   = (New-Object System.Management.Automation.PSCredential("Knkrumah", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'wakanda.land'
            Path       = 'CN=Users,DC=second,DC=local'
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitTimeout = 600
            RestartCount = 2
            DependsOn = "[Script]SetConditionalForwardedZone"
        }

        ADDomainTrust DomainTrust {
            TargetDomainName = $firstDomainName
            TargetCredential = $firstDomainCred
            TrustType = "External"
            TrustDirection = "Bidirectional"
            SourceDomainName = $secondDomainName
            DependsOn = "[WaitForADDomain]waitFirstDomain"
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
            Nodename                    = "First"
            Role                        = "First DC"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "UserServer"
            Role                        = "User Server"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        },
        @{
            Nodename                    = "UserWorkstation"
            Role                        = "User Workstation"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        },
        @{
            Nodename                    = "Second"
            Role                        = "Second DC"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        }
    )
}

land -ConfigurationData $ConfigData `
    -firstDomainName "bast.land" `
    -secondDomainName "wakanda.land" `
    -domainCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -safemodeAdministratorCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -firstDomainCred (New-Object System.Management.Automation.PSCredential("first-admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) 

