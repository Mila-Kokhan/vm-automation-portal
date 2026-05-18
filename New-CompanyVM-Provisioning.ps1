param(
    # Single-VM mode
    [Parameter(Mandatory = $false)]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [int]$MemoryGB,

    [Parameter(Mandatory = $false)]
    [int]$DataDiskGB,

    # Backend calls this parameter
    [Parameter(Mandatory = $false)]
    [int]$CpuCount = 2,

    # Company/Bulk mode
    [Parameter(Mandatory = $false)]
    [string]$Prefix,

    [Parameter(Mandatory = $false)]
    [int]$Count,

    # Bulk naming: zero padding width
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 6)]
    [int]$PadWidth = 2,

    # Bulk behavior: continue on failure
    [Parameter(Mandatory = $false)]
    [switch]$ContinueOnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
$LogDir = "D:\HyperV\Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = Join-Path $LogDir ("provision-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
Start-Transcript -Path $LogFile -Force
Write-Host "Logging to: $LogFile"

# ------------------------------------------------------------
# Global configuration
# ------------------------------------------------------------
$BaseVhdPath          = "D:\HyperV\VMs\CompanyBaseFinal.vhdx"
$VmRoot               = "D:\HyperV\VMs"
$SwitchName           = "VM_Switch"
$Generation           = 2
$UnattendPath         = "D:\HyperV\Scripts\Unattend.xml"

$DomainName           = "Group3Server.local"
$DomainNetbiosName    = "GROUP3SERVER"
$DomainDnsServer      = "192.168.107.5"
$DomainControllerFqdn = ""
$DomJoinUser          = "GROUP3SERVER\Administrator"
$DomJoinPass          = "P@ssw0rd1"

$LocalAdminUser       = ".\companyuser"
$LocalAdminPass       = "Password1"

$PreferredPrefix      = "192.168.107."

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
function Test-IsAdministrator {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Assert-ComputerNameSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw "VM name / computer name cannot be empty."
    }

    if ($Name.Length -gt 15) {
        throw "VM name '$Name' is too long for a Windows computer name. Maximum allowed is 15 characters."
    }

    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw "VM name '$Name' contains invalid characters. Allowed: letters, numbers, hyphen. It must start with a letter or number."
    }
}

function Get-FirstFreeDriveLetter {
    $letters = @('Z','Y','X','W','V','U','T','S','R','Q','P','O','N','M','L','K','J','I','H','G','F','E','D')
    foreach ($letter in $letters) {
        if ($null -eq (Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue)) {
            return $letter
        }
    }
    return $null
}

function New-LocalCredential {
    $securePass = ConvertTo-SecureString $LocalAdminPass -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($LocalAdminUser, $securePass)
}

function Wait-PSDirect {
    param(
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential,
        [int]$MaxAttempts = 300,
        [int]$DelaySeconds = 3
    )

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            $test = Invoke-Command -VMName $VmName -Credential $Credential -ScriptBlock { "READY" } -ErrorAction Stop
            if ($test -eq "READY") {
                return $true
            }
        }
        catch {
        }

        Start-Sleep -Seconds $DelaySeconds
    }

    return $false
}

function Get-VMIPv4Address {
    param(
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [int]$MaxAttempts = 300,
        [int]$DelaySeconds = 3,
        [string]$PreferredPrefix = "192.168.107."
    )

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            if ($null -ne $Credential) {
                $guestIp = Invoke-Command -VMName $VmName -Credential $Credential -ScriptBlock {
                    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.IPAddress -match '^\d{1,3}(\.\d{1,3}){3}$' -and
                            $_.IPAddress -notlike '169.254.*' -and
                            $_.PrefixOrigin -ne 'WellKnown'
                        } |
                        Select-Object -ExpandProperty IPAddress

                    if ($null -ne $ips) {
                        $preferred = $ips | Where-Object { $_ -like '192.168.107.*' } | Select-Object -First 1
                        if ($null -ne $preferred) {
                            return $preferred
                        }

                        return ($ips | Select-Object -First 1)
                    }

                    return $null
                } -ErrorAction Stop

                if ($null -ne $guestIp) {
                    return $guestIp
                }
            }
        }
        catch {
        }

        try {
            $ips = (Get-VMNetworkAdapter -VMName $VmName -ErrorAction Stop).IPAddresses |
                Where-Object {
                    $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and
                    $_ -notlike '169.254.*'
                }

            if ($null -ne $ips) {
                $preferred = $ips | Where-Object { $_ -like "$PreferredPrefix*" } | Select-Object -First 1
                if ($null -ne $preferred) {
                    return $preferred
                }

                return ($ips | Select-Object -First 1)
            }
        }
        catch {
        }

        Start-Sleep -Seconds $DelaySeconds
    }

    return $null
}

function Remove-ExistingVmAndFiles {
    param(
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][string]$VmPath
    )

    $existingVm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if ($null -ne $existingVm) {
        Write-Host "WARNING: VM '$VmName' already exists in Hyper-V, removing it..." -ForegroundColor Yellow
        try { Stop-VM -Name $VmName -Force -TurnOff -ErrorAction SilentlyContinue | Out-Null } catch { }
        try { Remove-VM -Name $VmName -Force -ErrorAction Stop | Out-Null } catch {
            throw "Could not remove existing VM '$VmName'. Error: $($_.Exception.Message)"
        }
    }

    if (Test-Path $VmPath) {
        Write-Host "WARNING: VM path already exists, deleting old folder..." -ForegroundColor Yellow
        try { Remove-Item -Recurse -Force $VmPath -ErrorAction Stop } catch {
            throw "Could not delete existing VM folder at '$VmPath'. Error: $($_.Exception.Message)"
        }
    }
}

function Cleanup-FailedProvision {
    param(
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][string]$VmPath
    )

    Write-Host "Running cleanup for failed VM '$VmName'..." -ForegroundColor Yellow

    try { Stop-VM -Name $VmName -Force -TurnOff -ErrorAction SilentlyContinue | Out-Null } catch { }
    try { Remove-VM -Name $VmName -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
    try {
        if (Test-Path $VmPath) {
            Remove-Item -Recurse -Force $VmPath -ErrorAction SilentlyContinue
        }
    }
    catch {
    }
}

function New-PaddedName {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][int]$PadWidth
    )

    $num = $Index.ToString().PadLeft($PadWidth, '0')
    return "$Prefix-$num"
}

# ------------------------------------------------------------
# Phase 1: create VM shell only
# ------------------------------------------------------------
function New-VMOnly {
    param(
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][int]$MemoryGB,
        [Parameter(Mandatory = $true)][int]$DataDiskGB,
        [Parameter(Mandatory = $true)][int]$CpuCount
    )

    Write-Host "=== VM Creation Started for '$Username' ==="

    $MemoryBytes   = $MemoryGB * 1GB
    $DataDiskBytes = $DataDiskGB * 1GB

    $VmName       = "VM-$Username"
    $VmPath       = Join-Path $VmRoot $VmName
    $OsDiskPath   = Join-Path $VmPath "$VmName-os.vhdx"
    $DataDiskPath = Join-Path $VmPath "$VmName-data.vhdx"

    if ($false -eq (Test-IsAdministrator)) {
        throw "This script must be run in an elevated PowerShell session as Administrator."
    }

    Assert-ComputerNameSafe -Name $VmName

    if ($MemoryGB -lt 1 -or $MemoryGB -gt 64) {
        throw "MemoryGB must be between 1 and 64."
    }

    if ($DataDiskGB -lt 10 -or $DataDiskGB -gt 2048) {
        throw "DataDiskGB must be between 10 and 2048."
    }

    if ($CpuCount -lt 1 -or $CpuCount -gt 16) {
        throw "CpuCount must be between 1 and 16."
    }

    if (-not (Test-Path $BaseVhdPath)) {
        throw "Base image not found at $BaseVhdPath"
    }

    if (-not (Test-Path $UnattendPath)) {
        throw "Unattend file not found at $UnattendPath"
    }

    if (-not (Test-Path $VmRoot)) {
        throw "VM root path not found at $VmRoot"
    }

    $switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if ($null -eq $switch) {
        throw "Hyper-V switch '$SwitchName' does not exist."
    }

    Remove-ExistingVmAndFiles -VmName $VmName -VmPath $VmPath

    try {
        New-Item -ItemType Directory -Path $VmPath -Force | Out-Null

        Write-Host "Using base image: $BaseVhdPath"
        Write-Host "VM Name: $VmName"
        Write-Host "Memory: $MemoryGB GB"
        Write-Host "Extra disk: $DataDiskGB GB"
        Write-Host "CPU Count: $CpuCount"
        Write-Host "Switch: $SwitchName"

        Write-Host "Creating differencing OS disk..."
        New-VHD -Path $OsDiskPath -ParentPath $BaseVhdPath -Differencing -ErrorAction Stop | Out-Null

        Write-Host "Injecting Unattend.xml..."
        try {
            $mountedVhd = Mount-VHD -Path $OsDiskPath -Passthru -ErrorAction Stop
            Start-Sleep -Seconds 2

            $diskNumber = ($mountedVhd | Get-Disk).Number
            $windowsDrive = $null

            $partitions = Get-Partition -DiskNumber $diskNumber | Sort-Object PartitionNumber

            foreach ($partition in $partitions) {
                $letter = $partition.DriveLetter

                if ($null -eq $letter) {
                    try {
                        $freeLetter = Get-FirstFreeDriveLetter
                        if ($null -ne $freeLetter) {
                            $partition | Set-Partition -NewDriveLetter $freeLetter -ErrorAction Stop
                            $letter = $freeLetter
                        }
                    }
                    catch {
                        continue
                    }
                }

                if (($null -ne $letter) -and (Test-Path "$letter`:\Windows")) {
                    $windowsDrive = $letter
                    break
                }
            }

            if ($null -eq $windowsDrive) {
                throw "Could not locate Windows partition inside $OsDiskPath"
            }

            $pantherPath         = "$windowsDrive`:\Windows\Panther"
            $pantherUnattendPath = "$windowsDrive`:\Windows\Panther\Unattend"

            New-Item -ItemType Directory -Path $pantherPath -Force | Out-Null
            New-Item -ItemType Directory -Path $pantherUnattendPath -Force | Out-Null

            Copy-Item -Path $UnattendPath -Destination "$pantherPath\Unattend.xml" -Force -ErrorAction Stop
            Copy-Item -Path $UnattendPath -Destination "$pantherUnattendPath\Unattend.xml" -Force -ErrorAction Stop
        }
        finally {
            try { Dismount-VHD -Path $OsDiskPath -ErrorAction SilentlyContinue } catch { }
        }

        Write-Host "Creating data disk..."
        New-VHD -Path $DataDiskPath -SizeBytes $DataDiskBytes -Dynamic -ErrorAction Stop | Out-Null

        Write-Host "Creating VM..."
        New-VM -Name $VmName `
               -MemoryStartupBytes $MemoryBytes `
               -Generation $Generation `
               -VHDPath $OsDiskPath `
               -Path $VmPath `
               -SwitchName $SwitchName `
               -ErrorAction Stop | Out-Null

        Set-VMProcessor -VMName $VmName -Count $CpuCount -ErrorAction Stop | Out-Null
        Add-VMHardDiskDrive -VMName $VmName -Path $DataDiskPath -ErrorAction Stop | Out-Null

        Write-Host "VM shell created: $VmName"
    }
    catch {
        Cleanup-FailedProvision -VmName $VmName -VmPath $VmPath
        throw
    }
}

# ------------------------------------------------------------
# Phase 2: start and configure existing VM
# ------------------------------------------------------------
function Start-AndConfigureVM {
    param(
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][int]$MemoryGB,
        [Parameter(Mandatory = $true)][int]$DataDiskGB,
        [Parameter(Mandatory = $true)][int]$CpuCount
    )

    $VmName = "VM-$Username"
    $LocalCred = New-LocalCredential

    Write-Host "Starting VM..."
    Start-VM -Name $VmName -ErrorAction Stop | Out-Null

    Write-Host "Waiting for guest IPv4 as early boot signal..."
    $bootIp = $null
    for ($i = 1; $i -le 120; $i++) {
        $bootIp = (Get-VMNetworkAdapter -VMName $VmName).IPAddresses |
            Where-Object {
                $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and
                $_ -notlike '169.254.*' -and
                $_ -like '192.168.107.*'
            } |
            Select-Object -First 1

        if ($null -ne $bootIp) {
            Write-Host "Guest boot IP detected: $bootIp"
            break
        }

        Start-Sleep -Seconds 2
    }

    Write-Host "Allowing guest boot to settle before PowerShell Direct..."
    Start-Sleep -Seconds 120

    Write-Host "Waiting for PowerShell Direct..."
    $PSReady = Wait-PSDirect -VmName $VmName -Credential $LocalCred -MaxAttempts 300 -DelaySeconds 3
    if ($false -eq $PSReady) {
        throw "Could not establish PowerShell Direct into VM. Check VM boot, integration services, and local template credentials."
    }

    Write-Host "PowerShell Direct connected."
    Write-Host "Waiting for first boot stabilization..."
    Start-Sleep -Seconds 10

    Write-Host "Waiting for guest IPv4 before DNS configuration..."
    $guestIpReady = $false
    $currentIp = $null

    for ($attempt = 1; $attempt -le 90; $attempt++) {
        $currentIp = Get-VMIPv4Address -VmName $VmName -Credential $LocalCred -MaxAttempts 1 -DelaySeconds 1

        if (($null -ne $currentIp) -and ($currentIp -like '192.168.107.*')) {
            Write-Host "Guest IPv4 detected: $currentIp"
            $guestIpReady = $true
            break
        }

        Start-Sleep -Seconds 2
    }

    if ($false -eq $guestIpReady) {
        throw "Guest did not obtain an IPv4 address in time."
    }

    Write-Host "Configuring DNS inside guest..."
    Invoke-Command -VMName $VmName -Credential $LocalCred -ScriptBlock {
        param($DomainDnsServer)

        $ErrorActionPreference = "Stop"

        $nic = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        if ($null -eq $nic) {
            $nic = Get-NetAdapter | Select-Object -First 1
        }

        if ($null -eq $nic) {
            throw "No network adapter found."
        }

        Write-Host "Setting DNS on $($nic.Name)..."
        Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses $DomainDnsServer

        Start-Sleep -Seconds 10
        Write-Host "DNS configuration completed."
    } -ArgumentList $DomainDnsServer

    Write-Host "Verifying DNS resolution inside guest..."
    $dnsReady = $false

    for ($attempt = 1; $attempt -le 8; $attempt++) {
        try {
            Invoke-Command -VMName $VmName -Credential $LocalCred -ScriptBlock {
                param($DomainName, $DomainDnsServer)

                $ErrorActionPreference = "Stop"
                Resolve-DnsName $DomainName -Server $DomainDnsServer -ErrorAction Stop | Out-Null
                "DNS_OK"
            } -ArgumentList $DomainName, $DomainDnsServer | Out-Null

            $dnsReady = $true
            Write-Host "DNS resolution check passed."
            break
        }
        catch {
            Write-Host "DNS resolution not ready yet. Attempt $attempt of 8..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
        }
    }

    if ($false -eq $dnsReady) {
        throw "DNS resolution for '$DomainName' via '$DomainDnsServer' did not succeed in time."
    }

    Write-Host "Joining domain with final computer name..."
    Invoke-Command -VMName $VmName -Credential $LocalCred -ScriptBlock {
        param(
            $DomainName,
            $DomainUser,
            $DomainPass,
            $FinalComputerName,
            $DomainControllerFqdn
        )

        $ErrorActionPreference = "Stop"

        $securePass = ConvertTo-SecureString $DomainPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($DomainUser, $securePass)

        $joinParams = @{
            DomainName  = $DomainName
            Credential  = $cred
            NewName     = $FinalComputerName
            Force       = $true
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($DomainControllerFqdn)) {
            $joinParams['Server'] = $DomainControllerFqdn
        }

        Add-Computer @joinParams
    } -ArgumentList $DomainName, $DomJoinUser, $DomJoinPass, $VmName, $DomainControllerFqdn

    Write-Host "Restarting guest after domain join..."
    try {
        Invoke-Command -VMName $VmName -Credential $LocalCred -ScriptBlock {
            Restart-Computer -Force
        } -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Restart command disconnected as expected."
    }

    Write-Host "Waiting for PowerShell Direct after domain join restart..."
    Start-Sleep -Seconds 30

    $PSReadyAfterJoin = Wait-PSDirect -VmName $VmName -Credential $LocalCred -MaxAttempts 300 -DelaySeconds 3
    if ($false -eq $PSReadyAfterJoin) {
        throw "VM restarted after domain join, but PowerShell Direct did not reconnect in time."
    }

    Start-Sleep -Seconds 20

    Write-Host "Verifying domain join after restart..."
    Invoke-Command -VMName $VmName -Credential $LocalCred -ScriptBlock {
        param($DomainName, $FinalComputerName)

        $ErrorActionPreference = "Stop"
        $cs = Get-CimInstance Win32_ComputerSystem

        if ($false -eq $cs.PartOfDomain) {
            throw "Computer is not joined to a domain."
        }

        if ($cs.Domain -ine $DomainName) {
            throw "Computer joined wrong domain: $($cs.Domain). Expected: $DomainName"
        }

        if ($env:COMPUTERNAME -ine $FinalComputerName) {
            throw "Computer name is not correct after join. Current name: $env:COMPUTERNAME. Expected: $FinalComputerName"
        }
    } -ArgumentList $DomainName, $VmName

    Write-Host "Waiting for post-join stabilization..."
    Start-Sleep -Seconds 8

    Write-Host "Verifying domain join and enabling domain user access..."
    Invoke-Command -VMName $VmName -Credential $LocalCred -ScriptBlock {
        param($DomainName, $DomainNetbiosName)

        $ErrorActionPreference = "Stop"
        $cs = Get-CimInstance Win32_ComputerSystem

        if ($false -eq $cs.PartOfDomain) {
            throw "VM is not joined to a domain."
        }

        if ($cs.Domain -notlike $DomainName) {
            throw "VM is joined to '$($cs.Domain)' instead of '$DomainName'."
        }

        $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $winlogon -Name "AutoAdminLogon" -Value "0" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $winlogon -Name "DefaultUserName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $winlogon -Name "DefaultPassword" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $winlogon -Name "DefaultDomainName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $winlogon -Name "AutoLogonCount" -ErrorAction SilentlyContinue

        $rdpGroupMember = "$DomainNetbiosName\Domain Users"

        try {
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $rdpGroupMember -ErrorAction Stop
        }
        catch {
            & net localgroup "Remote Desktop Users" $rdpGroupMember /add | Out-Null
        }

        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Out-Null
    } -ArgumentList $DomainName, $DomainNetbiosName

    Write-Host "Waiting for VM IPv4 address..."
    $vmIp = $null
    $maxAttempts = 60

    for ($i = 1; $i -le $maxAttempts; $i++) {
        $vmIp = (Get-VMNetworkAdapter -VMName $VmName).IPAddresses |
            Where-Object {
                $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and
                $_ -like '192.168.107.*'
            } |
            Select-Object -First 1

        if ($null -ne $vmIp) {
            break
        }

        Start-Sleep -Seconds 2
    }

    Write-Host ""
    Write-Host "=== VM '$VmName' successfully created and joined to domain ===" -ForegroundColor Green
    Write-Host "CPU: $CpuCount | RAM: $MemoryGB GB | DataDisk: $DataDiskGB GB" -ForegroundColor Green

    if ($null -ne $vmIp) {
        Write-Host "IP Address: $vmIp" -ForegroundColor Green
        Write-Output $vmIp
    }
    else {
        Write-Host "IP Address: not detected yet" -ForegroundColor Yellow
    }
}

function Invoke-ProvisionOne {
    param(
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][int]$MemoryGB,
        [Parameter(Mandatory = $true)][int]$DataDiskGB,
        [Parameter(Mandatory = $true)][int]$CpuCount
    )

    try {
        New-VMOnly -Username $Username -MemoryGB $MemoryGB -DataDiskGB $DataDiskGB -CpuCount $CpuCount
        Start-AndConfigureVM -Username $Username -MemoryGB $MemoryGB -DataDiskGB $DataDiskGB -CpuCount $CpuCount
    }
    catch {
        $vmName = "VM-$Username"
        $vmPath = Join-Path "D:\HyperV\VMs" $vmName
        Cleanup-FailedProvision -VmName $vmName -VmPath $vmPath
        throw
    }
}

# ------------------------------------------------------------
# MODE SELECTION
# ------------------------------------------------------------
try {
    $bulkMode = (-not [string]::IsNullOrWhiteSpace($Prefix)) -and ($null -ne $Count) -and ($Count -gt 0)

    if ($bulkMode) {
        if ($null -eq $MemoryGB -or $null -eq $DataDiskGB -or $null -eq $CpuCount) {
            throw "Bulk mode requires -MemoryGB, -DataDiskGB, and -CpuCount in addition to -Prefix and -Count."
        }

        Write-Host "=== Company/Bulk VM Provisioning Started ==="
        Write-Host "Prefix: $Prefix"
        Write-Host "Count:  $Count"
        Write-Host "RAM:    $MemoryGB GB"
        Write-Host "Disk:   $DataDiskGB GB"
        Write-Host "CPU:    $CpuCount"
        Write-Host "Pad:    $PadWidth"
        Write-Host ""

        $results = @()
        $failures = 0
        $createdNames = @()

        Write-Host "=== Phase 1: Creating all VM shells ==="

        for ($i = 1; $i -le $Count; $i++) {
            $name = New-PaddedName -Prefix $Prefix -Index $i -PadWidth $PadWidth

            try {
                New-VMOnly -Username $name -MemoryGB $MemoryGB -DataDiskGB $DataDiskGB -CpuCount $CpuCount
                $createdNames += $name

                $results += [pscustomobject]@{
                    username = $name
                    ok       = $true
                    phase    = "created"
                }
            }
            catch {
                $failures++
                $msg = $_.Exception.Message
                Write-Host "ERROR creating '$name': $msg" -ForegroundColor Red

                $results += [pscustomobject]@{
                    username = $name
                    ok       = $false
                    phase    = "create"
                    error    = $msg
                }

                if ($false -eq $ContinueOnError.IsPresent) {
                    Write-Host "Stopping batch creation because -ContinueOnError was not set." -ForegroundColor Yellow
                    break
                }
            }

            Write-Host ""
        }

        Write-Host "=== Phase 2: Starting and configuring created VMs ==="

        foreach ($name in $createdNames) {
            try {
                Start-AndConfigureVM -Username $name -MemoryGB $MemoryGB -DataDiskGB $DataDiskGB -CpuCount $CpuCount

                $results += [pscustomobject]@{
                    username = $name
                    ok       = $true
                    phase    = "started-configured"
                }
            }
            catch {
                $failures++
                $msg = $_.Exception.Message
                Write-Host "ERROR starting/configuring '$name': $msg" -ForegroundColor Red

                $results += [pscustomobject]@{
                    username = $name
                    ok       = $false
                    phase    = "start-configure"
                    error    = $msg
                }

                if ($false -eq $ContinueOnError.IsPresent) {
                    Write-Host "Stopping batch start/configuration because -ContinueOnError was not set." -ForegroundColor Yellow
                    break
                }
            }

            Write-Host ""
        }

        Write-Host "=== Bulk Summary ==="
        Write-Host "Total requested: $Count"
        Write-Host "Failures:       $failures"
        Write-Host "Successes:      $($results | Where-Object { $_.ok } | Measure-Object | Select-Object -ExpandProperty Count)"

        if ($failures -gt 0) {
            exit 1
        }
        else {
            exit 0
        }
    }

    if ([string]::IsNullOrWhiteSpace($Username)) {
        throw "Single mode requires -Username. Bulk mode requires -Prefix and -Count."
    }

    if ($null -eq $MemoryGB -or $null -eq $DataDiskGB -or $null -eq $CpuCount) {
        throw "Single mode requires -MemoryGB, -DataDiskGB, and -CpuCount."
    }

    Invoke-ProvisionOne -Username $Username -MemoryGB $MemoryGB -DataDiskGB $DataDiskGB -CpuCount $CpuCount
    exit 0
}
finally {
    try { Stop-Transcript } catch { }
}