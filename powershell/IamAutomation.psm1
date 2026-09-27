Set-StrictMode -Version Latest

function Write-JsonAuditLog {
    param(
        [string]$Caller,
        [string]$Target,
        [string]$Action,
        [string]$Status,
        [string]$TicketId,
        [string]$Provider,
        [hashtable]$Details
    )

    $payload = [ordered]@{
        timestamp       = (Get-Date).ToUniversalTime().ToString("o")
        caller_identity = $Caller
        target_entity   = $Target
        action          = $Action
        status          = $Status
        ticket_id       = $TicketId
        provider        = $Provider
        details         = $Details
    }

    $payload | ConvertTo-Json -Depth 5 -Compress | Write-Output
}

function New-SecureSecret {
    param([int]$Length = 40)
    $bytes = New-Object byte[] ($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $value = [Convert]::ToBase64String($bytes).TrimEnd('=')
    return $value.Substring(0, [Math]::Min($Length, $value.Length))
}

function Invoke-Backoff {
    param(
        [scriptblock]$Operation,
        [int]$MaxAttempts = 5,
        [int]$BaseDelaySeconds = 1
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Operation
        }
        catch {
            $message = $_.Exception.Message
            if ($message -notmatch '429|rate limit' -or $attempt -eq $MaxAttempts) {
                throw
            }
            Start-Sleep -Seconds ([Math]::Min(16, [Math]::Pow(2, $attempt - 1) * $BaseDelaySeconds))
        }
    }
}

function Invoke-IamRequest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateSet('create','modify','disable','enable','reset-secret')][string]$Action,
        [Parameter(Mandatory)][ValidateSet('privileged-account','non-human-identity','security-group')][string]$EntityType,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][switch]$DryRun,
        [string]$Provider = "graph",
        [string]$Caller = "automation-runner",
        [string]$TicketId = "UNKNOWN",
        [hashtable]$Attributes = @{}
    )

    $normalizedTarget = $Target.ToLowerInvariant().Replace(' ', '-')

    if ($DryRun) {
        Write-JsonAuditLog -Caller $Caller -Target $normalizedTarget -Action $Action -Status 'planned' -TicketId $TicketId -Provider $Provider -Details @{ plannedChanges = $Attributes; entityType = $EntityType }
        return [pscustomobject]@{ status = 'planned'; message = 'dry-run completed'; changed = $false; data = @{ target = $normalizedTarget; provider = $Provider } }
    }

    $operation = {
        switch ($Action) {
            'create' {
                return [pscustomobject]@{ status='success'; message='created'; changed=$true; data=@{ leastPrivilege=$true; target=$normalizedTarget } }
            }
            'modify' {
                return [pscustomobject]@{ status='success'; message='modified'; changed=$true; data=@{ target=$normalizedTarget; attributes=$Attributes } }
            }
            'disable' {
                return [pscustomobject]@{ status='success'; message='disabled'; changed=$true; data=@{ target=$normalizedTarget; quarantineOU=($Attributes.quarantine_ou ?? 'OU=Quarantine') } }
            }
            'enable' {
                return [pscustomobject]@{ status='success'; message='enabled'; changed=$true; data=@{ target=$normalizedTarget; mfaRequired=$true; secretRotationRequired=$true } }
            }
            'reset-secret' {
                $secret = New-SecureSecret -Length 40
                return [pscustomobject]@{ status='success'; message='secret reset'; changed=$true; data=@{ target=$normalizedTarget; secret=$secret; mustChangePasswordAtNextLogon=$true } }
            }
        }
    }

    $result = Invoke-Backoff -Operation $operation
    Write-JsonAuditLog -Caller $Caller -Target $normalizedTarget -Action $Action -Status $result.status -TicketId $TicketId -Provider $Provider -Details @{ message = $result.message; changed = $result.changed }
    return $result
}

Export-ModuleMember -Function Invoke-IamRequest, New-SecureSecret, Write-JsonAuditLog
