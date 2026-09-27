from __future__ import annotations

import re
from typing import Callable, Dict

from .logger import build_logger
from .models import Action, AuditEvent, IAMRequest, OperationResult
from .providers.base import DirectoryProvider
from .retry import run_with_exponential_backoff


class IAMAutomationService:
    def __init__(self, provider: DirectoryProvider):
        self.provider = provider
        self.logger = build_logger()

    @staticmethod
    def normalize_name(action: Action, target: str, prefix: str | None = None) -> str:
        normalized = re.sub(r"[^a-zA-Z0-9-]", "-", target.strip().lower())
        if action == Action.CREATE and prefix and not normalized.startswith(prefix.lower()):
            normalized = f"{prefix.lower()}-{normalized}"
        return normalized

    def execute(self, request: IAMRequest) -> OperationResult:
        target = self.normalize_name(
            request.action, request.target, request.attributes.get("name_prefix")
        )
        access = self.provider.validate_access(request.entity_type, target)
        if access.status not in {"ok", "success", "noop"}:
            self._audit(request, access, target)
            return access

        if request.dry_run:
            result = OperationResult(
                status="planned",
                message="dry-run completed",
                changed=False,
                data={
                    "provider": self.provider.name,
                    "target": target,
                    "action": request.action.value,
                    "entityType": request.entity_type.value,
                    "plannedChanges": request.attributes,
                },
            )
            self._audit(request, result, target)
            return result

        operation_map: Dict[Action, Callable[[], OperationResult]] = {
            Action.CREATE: lambda: self.provider.create_entity(
                request.entity_type, target, request.attributes
            ),
            Action.MODIFY: lambda: self.provider.modify_entity(
                request.entity_type, target, request.attributes
            ),
            Action.DISABLE: lambda: self.provider.disable_entity(
                request.entity_type, target, request.attributes
            ),
            Action.ENABLE: lambda: self.provider.enable_entity(
                request.entity_type, target, request.attributes
            ),
            Action.RESET_SECRET: lambda: self.provider.reset_secret(
                request.entity_type, target, request.attributes
            ),
        }

        result = run_with_exponential_backoff(operation_map[request.action])
        self._audit(request, result, target)
        return result

    def _audit(self, request: IAMRequest, result: OperationResult, normalized_target: str) -> None:
        event = AuditEvent.create(
            caller=request.caller,
            target=normalized_target,
            action=request.action,
            status=result.status,
            ticket_id=request.ticket_id,
            provider=self.provider.name,
            details={"message": result.message, "changed": result.changed},
        )
        self.logger.info(
            "iam_operation",
            extra={
                "extra_fields": {
                    "timestamp": event.timestamp,
                    "caller_identity": event.caller_identity,
                    "target_entity": event.target_entity,
                    "action": event.action,
                    "status": event.status,
                    "ticket_id": event.ticket_id,
                    "provider": event.provider,
                    "details": event.details,
                }
            },
        )
