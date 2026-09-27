from __future__ import annotations

import argparse
import json
import os
from typing import Dict

from .core import IAMAutomationService
from .models import Action, EntityType, IAMRequest
from .providers.ad_adapter import ActiveDirectoryConfig, ActiveDirectoryProvider
from .providers.base import InMemoryDirectoryProvider
from .providers.entra_adapter import EntraConfig, EntraIDProvider
from .providers.linux_ssh_adapter import LinuxSSHConfig, LinuxSSHProvider


def parse_kv_pairs(raw: str | None) -> Dict[str, str]:
    if not raw:
        return {}
    pairs: Dict[str, str] = {}
    for item in raw.split(","):
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"Invalid attribute entry: {item}")
        pairs[key.strip()] = value.strip()
    return pairs


def provider_from_name(provider_name: str):
    if provider_name == "ad":
        return ActiveDirectoryProvider(
            ActiveDirectoryConfig(
                server=os.getenv("AD_SERVER", "ldaps://localhost"),
                bind_dn=os.getenv("AD_BIND_DN", "CN=automation"),
                bind_password=os.getenv("AD_BIND_PASSWORD", ""),
                base_dn=os.getenv("AD_BASE_DN", "DC=example,DC=com"),
            )
        )
    if provider_name == "entra":
        return EntraIDProvider(
            EntraConfig(
                tenant_id=os.getenv("ENTRA_TENANT_ID", "tenant"),
                client_id=os.getenv("ENTRA_CLIENT_ID", "client"),
                client_secret=os.getenv("ENTRA_CLIENT_SECRET", ""),
            )
        )
    if provider_name == "linux":
        return LinuxSSHProvider(
            LinuxSSHConfig(
                host=os.getenv("LINUX_SSH_HOST", "localhost"),
                ssh_user=os.getenv("LINUX_SSH_USER", "root"),
            )
        )
    return InMemoryDirectoryProvider(provider_name)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IAM automation CLI")
    parser.add_argument("--action", required=True, choices=[a.value for a in Action])
    parser.add_argument("--entity-type", required=True, choices=[e.value for e in EntityType])
    parser.add_argument("--target", required=True)
    parser.add_argument("--provider", default=os.getenv("IAM_PROVIDER", "mock"))
    parser.add_argument("--caller", default=os.getenv("IAM_CALLER", "automation-runner"))
    parser.add_argument("--ticket-id", default=os.getenv("IAM_TICKET_ID", "UNKNOWN"))
    parser.add_argument(
        "--attributes",
        default=os.getenv("IAM_ATTRIBUTES"),
        help="comma-separated key=value list",
    )
    dry_run_group = parser.add_mutually_exclusive_group(required=True)
    dry_run_group.add_argument("--dry-run", action="store_true", help="Plan only")
    dry_run_group.add_argument("--execute", action="store_true", help="Apply changes")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    provider = provider_from_name(args.provider)
    service = IAMAutomationService(provider)
    request = IAMRequest(
        action=Action(args.action),
        entity_type=EntityType(args.entity_type),
        target=args.target,
        provider=args.provider,
        caller=args.caller,
        ticket_id=args.ticket_id,
        dry_run=bool(args.dry_run),
        attributes=parse_kv_pairs(args.attributes),
    )
    result = service.execute(request)
    print(
        json.dumps(
            {
                "status": result.status,
                "message": result.message,
                "changed": result.changed,
                "data": result.data,
            },
            sort_keys=True,
        )
    )
    return 0 if result.status in {"success", "noop", "planned"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
