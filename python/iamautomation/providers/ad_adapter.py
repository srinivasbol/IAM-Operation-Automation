from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .base import InMemoryDirectoryProvider, safe_import


@dataclass(slots=True)
class ActiveDirectoryConfig:
    server: str
    bind_dn: str
    bind_password: str
    base_dn: str


class ActiveDirectoryProvider(InMemoryDirectoryProvider):
    """AD adapter scaffold with ldap3 compatibility hooks."""

    def __init__(self, config: ActiveDirectoryConfig) -> None:
        super().__init__(name="active-directory")
        self.config = config
        self.ldap3 = safe_import("ldap3")

    def connection_metadata(self) -> Dict[str, Any]:
        return {
            "server": self.config.server,
            "base_dn": self.config.base_dn,
            "ldap3_available": bool(self.ldap3),
        }
