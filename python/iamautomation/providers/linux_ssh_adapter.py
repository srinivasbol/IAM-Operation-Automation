from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .base import InMemoryDirectoryProvider


@dataclass(slots=True)
class LinuxSSHConfig:
    host: str
    ssh_user: str


class LinuxSSHProvider(InMemoryDirectoryProvider):
    """Linux/OpenSSH provider scaffold."""

    def __init__(self, config: LinuxSSHConfig) -> None:
        super().__init__(name="linux-ssh")
        self.config = config

    def connection_metadata(self) -> Dict[str, Any]:
        return {"host": self.config.host, "ssh_user": self.config.ssh_user}
