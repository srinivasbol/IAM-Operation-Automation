from __future__ import annotations

from abc import ABC, abstractmethod
import importlib
from secrets import token_urlsafe
from typing import Any, Dict, Optional

from ..models import Action, EntityType, OperationResult


class DirectoryProvider(ABC):
    name: str

    @abstractmethod
    def validate_access(self, entity_type: EntityType, target: str) -> OperationResult:
        raise NotImplementedError

    @abstractmethod
    def create_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        raise NotImplementedError

    @abstractmethod
    def modify_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        raise NotImplementedError

    @abstractmethod
    def disable_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        raise NotImplementedError

    @abstractmethod
    def enable_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        raise NotImplementedError

    @abstractmethod
    def reset_secret(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        raise NotImplementedError

    def is_retry_safe(self, action: Action) -> bool:
        return action == Action.MODIFY

    def generate_secret(self, length: int = 40) -> str:
        secret = ""
        while len(secret) < length:
            secret += token_urlsafe(length)
        return secret[:length]


class InMemoryDirectoryProvider(DirectoryProvider):
    """Deterministic provider for local testing and dry-runs."""

    def __init__(self, name: str = "mock") -> None:
        self.name = name
        self._entities: Dict[str, Dict[str, Any]] = {}

    def _key(self, entity_type: EntityType, target: str) -> str:
        return f"{entity_type.value}:{target.lower()}"

    def validate_access(self, entity_type: EntityType, target: str) -> OperationResult:
        return OperationResult(status="ok", message="validated", changed=False)

    def create_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        key = self._key(entity_type, target)
        if key in self._entities:
            return OperationResult(
                status="noop",
                message=f"{target} already exists",
                changed=False,
                data=self._entities[key],
            )
        normalized = dict(attributes)
        normalized.setdefault("displayName", target)
        normalized.setdefault("enabled", True)
        normalized.setdefault("leastPrivilege", True)
        self._entities[key] = normalized
        return OperationResult(status="success", message="created", changed=True, data=normalized)

    def modify_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        key = self._key(entity_type, target)
        if key not in self._entities:
            return OperationResult(status="error", message=f"{target} not found", changed=False)
        current = self._entities[key]
        changed = False
        for k, v in attributes.items():
            if current.get(k) != v:
                current[k] = v
                changed = True
        if not changed:
            return OperationResult(status="noop", message="no changes detected", changed=False, data=current)
        return OperationResult(status="success", message="modified", changed=True, data=current)

    def disable_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        key = self._key(entity_type, target)
        if key not in self._entities:
            return OperationResult(status="error", message=f"{target} not found", changed=False)
        current = self._entities[key]
        if current.get("enabled") is False and current.get("quarantine") is True:
            return OperationResult(status="noop", message="already disabled", changed=False, data=current)
        current.update(
            {
                "enabled": False,
                "sessionsRevoked": True,
                "tokenExpired": True,
                "passwordExpired": True,
                "quarantine": True,
                "quarantineOU": attributes.get("quarantine_ou", "OU=Quarantine"),
            }
        )
        return OperationResult(status="success", message="disabled", changed=True, data=current)

    def enable_entity(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        key = self._key(entity_type, target)
        if key not in self._entities:
            return OperationResult(status="error", message=f"{target} not found", changed=False)
        current = self._entities[key]
        if current.get("enabled") is True:
            return OperationResult(status="noop", message="already enabled", changed=False, data=current)
        current.update(
            {
                "enabled": True,
                "quarantine": False,
                "mfaRequired": True,
                "secretRotationRequired": True,
            }
        )
        return OperationResult(status="success", message="enabled", changed=True, data=current)

    def reset_secret(
        self, entity_type: EntityType, target: str, attributes: Dict[str, Any]
    ) -> OperationResult:
        key = self._key(entity_type, target)
        if key not in self._entities:
            return OperationResult(status="error", message=f"{target} not found", changed=False)
        try:
            secret_length = int(attributes.get("secret_length", 40))
        except (TypeError, ValueError):
            return OperationResult(
                status="error",
                message="secret_length must be a positive integer",
                changed=False,
            )
        if secret_length <= 0:
            return OperationResult(
                status="error",
                message="secret_length must be a positive integer",
                changed=False,
            )
        _ = self.generate_secret(secret_length)
        current = self._entities[key]
        current.update(
            {
                "mustChangePasswordAtNextLogon": True,
                "secretRotationRequired": True,
                "secretSet": True,
            }
        )
        return OperationResult(
            status="success",
            message="secret reset",
            changed=True,
            data={
                "secretRedacted": True,
                "secureDeliveryRequired": True,
                "mustChangePasswordAtNextLogon": True,
            },
        )


def safe_import(module_name: str) -> Optional[object]:
    try:
        return importlib.import_module(module_name)
    except Exception:
        return None
