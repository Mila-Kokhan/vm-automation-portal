param(
    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [string]$Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $DomainController = "192.168.107.5"
    $DomainName       = "Group3Server.local"
    $UserPath         = "CN=Users,DC=Group3Server,DC=local"

    $DomainAdminUser = "GROUP3SERVER\Administrator"
    $DomainAdminPass = "P@ssw0rd1"

    $SecureDomainAdminPass = ConvertTo-SecureString $DomainAdminPass -AsPlainText -Force
    $DomainCredential = New-Object System.Management.Automation.PSCredential($DomainAdminUser, $SecureDomainAdminPass)

    if ([string]::IsNullOrWhiteSpace($Username)) {
        throw "Username cannot be empty."
    }

    if ([string]::IsNullOrWhiteSpace($Password)) {
        throw "Password cannot be empty."
    }

    if ($Username -notmatch '^[A-Za-z0-9._-]{3,30}$') {
        throw "Invalid username. Use 3-30 characters: letters, numbers, dot, dash, underscore."
    }

    $existing = Get-ADUser `
        -Server $DomainController `
        -Credential $DomainCredential `
        -Filter "SamAccountName -eq '$Username'" `
        -ErrorAction Stop

    if ($existing) {
        throw "AD user already exists: $Username"
    }

    $SecureUserPassword = ConvertTo-SecureString $Password -AsPlainText -Force

    New-ADUser `
        -Server $DomainController `
        -Credential $DomainCredential `
        -Name $Username `
        -SamAccountName $Username `
        -UserPrincipalName "$Username@$DomainName" `
        -AccountPassword $SecureUserPassword `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -ChangePasswordAtLogon $false `
        -Path $UserPath `
        -ErrorAction Stop

    Write-Output "AD user created successfully: $Username"
    exit 0
}
catch {
    Write-Error ("AD user creation failed: " + $_.Exception.Message)
    if ($_.ScriptStackTrace) {
        Write-Error $_.ScriptStackTrace
    }
    exit 1
}