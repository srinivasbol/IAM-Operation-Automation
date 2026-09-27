from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .base import InMemoryDirectoryProvider, safe_import


@dataclass(slots=True)
class EntraConfig:
    tenant_id: str
    client_id: str
    client_secret: str


class EntraIDProvider(InMemoryDirectoryProvider):
    """Entra ID adapter scaffold with msal/azure-identity compatibility hooks."""

    def __init__(self, config: EntraConfig) -> None:
        super().__init__(name="entra-id")
        self.config = config
        self.msal = safe_import("msal")
        self.azure_identity = safe_import("azure.identity")

    def connection_metadata(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.config.tenant_id,
            "client_id": self.config.client_id,
            "msal_available": bool(self.msal),
            "azure_identity_available": bool(self.azure_identity),
        }
