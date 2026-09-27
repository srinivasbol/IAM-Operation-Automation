# IAM-Operation-Automation

Production-ready IAM automation scaffolding for enterprise request fulfillment across Active Directory / Entra ID and Linux/OpenSSH.

## Python automation CLI

Run with required dry-run or execute mode:

```bash
python -m python.iamautomation.cli \
  --action create \
  --entity-type non-human-identity \
  --target "svc-app-01" \
  --provider entra \
  --ticket-id INC-1001 \
  --caller iam-runner \
  --attributes "name_prefix=svc,owner=platform" \
  --dry-run
```

### Supported actions/entities

- Actions: `create`, `modify`, `disable`, `enable`, `reset-secret`
- Entity types: `privileged-account`, `non-human-identity`, `security-group`
- Providers: `ad`, `entra`, `linux`, and `mock` (default for tests/local validation)

### Architecture

- `python/iamautomation/core.py`: idempotent request orchestration, naming policy, and audit event emission
- `python/iamautomation/providers/*`: provider adapters (`ldap3`, `msal`, `azure-identity` package via `azure.identity` module hooks) isolated from business logic
- `python/iamautomation/retry.py`: exponential backoff for 429/rate-limit resilience
- Structured JSON audit logs include timestamp, caller identity, target entity, action, status, provider, and ticket ID

## PowerShell module

```powershell
pwsh ./powershell/invoke-iam.ps1 -Action disable -EntityType privileged-account -Target bg-admin-01 -TicketId INC-1010 -Attributes "quarantine_ou=OU=Quarantine" -DryRun
```

- `powershell/IamAutomation.psm1` exposes `Invoke-IamRequest` with mandatory run mode (`-DryRun` or `-Execute`)
- Uses modular functions for secure secret generation, exponential backoff, and structured JSON audit logs
- Designed for extension with `Microsoft.Graph` and `ActiveDirectory` cmdlets in provider-specific logic blocks

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```
