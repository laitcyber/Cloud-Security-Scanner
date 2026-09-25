from abc import ABC, abstractmethod

from core.finding import Finding


class Plugin(ABC):
    name = "plugin"
    description = ""

    @abstractmethod
    def run(self, provider) -> list[Finding]:
        """Usa il provider per enumerare risorse e restituisce i Finding."""