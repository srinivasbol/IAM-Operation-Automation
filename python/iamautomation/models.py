from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Action(str, Enum):
    CREATE = "create"
    MODIFY = "modify"
    DISABLE = "disable"
    ENABLE = "enable"
    RESET_SECRET = "reset-secret"


class EntityType(str, Enum):
    PRIVILEGED_ACCOUNT = "privileged-account"
    NON_HUMAN_IDENTITY = "non-human-identity"
    SECURITY_GROUP = "security-group"


@dataclass(slots=True)
class IAMRequest:
    action: Action
    entity_type: EntityType
    target: str
    provider: str
    caller: str
    ticket_id: str
    dry_run: bool
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class OperationResult:
    status: str
    message: str
    changed: bool
    data: Optional[Dict[str, Any]] = None


@dataclass(slots=True)
class AuditEvent:
    timestamp: str
    caller_identity: str
    target_entity: str
    action: str
    status: str
    ticket_id: str
    provider: str
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        caller: str,
        target: str,
        action: Action,
        status: str,
        ticket_id: str,
        provider: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            caller_identity=caller,
            target_entity=target,
            action=action.value,
            status=status,
            ticket_id=ticket_id,
            provider=provider,
            details=details or {},
        )
