[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('create','modify','disable','enable','reset-secret')][string]$Action,
    [Parameter(Mandatory)][ValidateSet('privileged-account','non-human-identity','security-group')][string]$EntityType,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory, ParameterSetName='DryRun')][switch]$DryRun,
    [Parameter(Mandatory, ParameterSetName='Execute')][switch]$Execute,
    [string]$Provider = $env:IAM_PROVIDER,
    [string]$Caller = $(if ($env:IAM_CALLER) { $env:IAM_CALLER } else { 'automation-runner' }),
    [string]$TicketId = $(if ($env:IAM_TICKET_ID) { $env:IAM_TICKET_ID } else { 'UNKNOWN' }),
    [string]$Attributes
)

Import-Module (Join-Path $PSScriptRoot 'IamAutomation.psm1') -Force

$attrMap = @{}
if ($Attributes) {
    foreach ($entry in $Attributes.Split(',')) {
        $parts = $entry.Split('=', 2)
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0])) {
            throw "Invalid attribute entry: $entry"
        }
        $attrMap[$parts[0].Trim()] = $parts[1].Trim()
    }
}

if ($DryRun) {
    $result = Invoke-IamRequest -Action $Action -EntityType $EntityType -Target $Target -DryRun -Provider $Provider -Caller $Caller -TicketId $TicketId -Attributes $attrMap
}
else {
    $result = Invoke-IamRequest -Action $Action -EntityType $EntityType -Target $Target -Execute -Provider $Provider -Caller $Caller -TicketId $TicketId -Attributes $attrMap
}
$result | ConvertTo-Json -Depth 5 -Compress | Write-Output
