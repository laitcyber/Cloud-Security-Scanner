from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    severity: Severity
    resource: str
    description: str
    remediation: str

    def to_dict(self):
        return {
            "severity": self.severity.value,
            "resource": self.resource,
            "description": self.description,
            "remediation": self.remediation,
        }