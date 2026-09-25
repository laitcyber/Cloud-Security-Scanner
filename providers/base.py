from abc import ABC, abstractmethod


class Provider(ABC):
    name = "base"

    @abstractmethod
    def authenticate(self) -> None:
        """Effettua il login. Solleva RuntimeError se fallisce."""

    @abstractmethod
    def list_storage_resources(self) -> list[dict]:
        """Ritorna [{'name': str, 'public': bool}, ...]"""