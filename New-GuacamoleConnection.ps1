param(
    [Parameter(Mandatory = $true)]
    [string]$VmName,

    [Parameter(Mandatory = $true)]
    [string]$VmIp,

    [Parameter(Mandatory = $true)]
    [string]$AssignedUser
)

$ErrorActionPreference = "Stop"

$GuacBaseUrl = "http://127.0.0.1:8081/guacamole"
$GuacAdminUser = "guacadmin"
$GuacAdminPassword = "guacadmin"

$DomainNetbios = "GROUP3SERVER"
$TempGuacUserPassword = "TempLocalOnly123!"

function UrlEncode {
    param([string]$Value)
    return [System.Uri]::EscapeDataString($Value)
}

$encodedAdminUser = UrlEncode $GuacAdminUser
$encodedAdminPass = UrlEncode $GuacAdminPassword
$loginBody = "username=$encodedAdminUser`&password=$encodedAdminPass"

$tokenResponse = Invoke-RestMethod `
    -Method POST `
    -Uri "$GuacBaseUrl/api/tokens" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $loginBody

$token = $tokenResponse.authToken
$dataSource = $tokenResponse.dataSource

if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Failed to obtain Guacamole auth token."
}

Write-Host "Authenticated to Guacamole. Data source: $dataSource"

$encodedUser = UrlEncode $AssignedUser
$userExists = $false

try {
    Invoke-RestMethod `
        -Method GET `
        -Uri "$GuacBaseUrl/api/session/data/$dataSource/users/$encodedUser`?token=$token" `
        -ErrorAction Stop | Out-Null

    $userExists = $true
    Write-Host "Guacamole user already exists: $AssignedUser"
}
catch {
    $userExists = $false
}

if (-not $userExists) {
    Write-Host "Creating Guacamole user record: $AssignedUser"

    $userBody = @{
        username = $AssignedUser
        password = $TempGuacUserPassword
        attributes = @{
            disabled = ""
            expired = ""
            "access-window-start" = ""
            "access-window-end" = ""
            "valid-from" = ""
            "valid-until" = ""
            timezone = ""
            "guac-full-name" = $AssignedUser
            "guac-organization" = ""
            "guac-organizational-role" = ""
        }
    } | ConvertTo-Json -Depth 10

    Invoke-RestMethod `
        -Method POST `
        -Uri "$GuacBaseUrl/api/session/data/$dataSource/users`?token=$token" `
        -ContentType "application/json" `
        -Body $userBody | Out-Null

    Write-Host "Created Guacamole user record: $AssignedUser"
}

$connectionBody = @{
    parentIdentifier = "ROOT"
    name = $VmName
    protocol = "rdp"
    parameters = @{
        hostname = $VmIp
        port = "3389"
        domain = $DomainNetbios
        security = "any"
        "ignore-cert" = "true"
        "enable-drive" = "false"
        "enable-wallpaper" = "true"
    }
    attributes = @{
        "max-connections" = ""
        "max-connections-per-user" = ""
        weight = ""
        "failover-only" = ""
        "guacd-port" = ""
        "guacd-encryption" = ""
        "guacd-hostname" = ""
    }
} | ConvertTo-Json -Depth 10

$connection = Invoke-RestMethod `
    -Method POST `
    -Uri "$GuacBaseUrl/api/session/data/$dataSource/connections`?token=$token" `
    -ContentType "application/json" `
    -Body $connectionBody

$connectionId = $connection.identifier

if ([string]::IsNullOrWhiteSpace($connectionId)) {
    throw "Guacamole connection was created but no connection ID was returned."
}

Write-Host "Created Guacamole connection: $VmName"
Write-Host "Connection ID: $connectionId"

$permissionPatch = @(
    @{
        op = "add"
        path = "/connectionPermissions/$connectionId"
        value = "READ"
    }
)

$permissionPatchJson = ConvertTo-Json -InputObject $permissionPatch -Depth 10 -Compress

Invoke-RestMethod `
    -Method PATCH `
    -Uri "$GuacBaseUrl/api/session/data/$dataSource/users/$encodedUser/permissions`?token=$token" `
    -ContentType "application/json" `
    -Body $permissionPatchJson | Out-Null

Write-Host "Granted '$AssignedUser' access to '$VmName'."

try {
    Invoke-RestMethod `
        -Method DELETE `
        -Uri "$GuacBaseUrl/api/tokens/$token" | Out-Null
}
catch {
}

Write-Output "Guacamole connection created and assigned successfully."