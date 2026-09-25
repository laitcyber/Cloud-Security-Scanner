"""
plugins/azure/iam_overprivileged.py

Plugin per il rilevamento di permessi IAM eccessivi (overprivileged) su Azure.
Identifica l'assegnazione di ruoli critici (es. Owner, Contributor) a livello
di Subscription o Resource Group.
"""

from core.finding import Finding
from core.plugin import Plugin


class IAMOverprivilegedPlugin(Plugin):
    """
    Plugin che analizza le assegnazioni di ruoli (Role Assignments) su Azure
    per individuare identità con ruoli ad alto privilegio su ambiti estesi.
    """

    # Ruoli considerati ad alto rischio/sovra-privilegiati
    CRITICAL_ROLES = {
        "owner": "CRITICAL",
        "contributor": "HIGH",
        "user access administrator": "HIGH",
    }

    def __init__(self):
        super().__init__(
            name="Azure IAM Overprivileged Check",
            description="Rileva assegnazioni di ruoli ad alto privilegio (Owner, Contributor) su Subscription o Resource Group.",
        )

    def run(self, provider) -> list:
        """
        Esegue la scansione dei Role Assignment tramite il provider Azure.
        """
        findings = []

        # Recupera la lista delle assegnazioni di ruolo dal provider
        assignments = provider.list_iam_resources()

        for assignment in assignments:
            role_name = str(assignment.get("role_name", "")).strip()
            role_name_lower = role_name.lower()

            # Controlla se il ruolo rientra tra quelli critici
            if role_name_lower in self.CRITICAL_ROLES:
                severity = self.CRITICAL_ROLES[role_name_lower]
                scope = assignment.get("scope", "")
                principal_id = assignment.get("principal_id", "Sconosciuto")
                principal_type = assignment.get("principal_type", "User/Group/SP")

                # Identifica il tipo di ambito (Subscription vs Resource Group)
                scope_type = "Subscription" if scope.count("/") <= 2 else "Resource Group"

                description = (
                    f"Identificata un'assegnazione di ruolo sovra-privilegiata: l'entità '{principal_id}' "
                    f"({principal_type}) possiede il ruolo '{role_name}' assegnato a livello di {scope_type} "
                    f"(Scope: '{scope}')."
                )

                remediation = (
                    f"Applicare il principio del minimo privilegio (Least Privilege): "
                    f"rimuovere il ruolo '{role_name}' dallo scope esteso e assegnare ruoli con permessi "
                    f"più specifici (Custom Role) limitati alle sole risorse strettamente necessarie."
                )

                finding = Finding(
                    title=f"Assegnazione ruolo critico ({role_name}) su scope esteso",
                    description=description,
                    severity=severity,
                    resource_id=assignment.get("id", f"/providers/Microsoft.Authorization/roleAssignments/{principal_id}"),
                    remediation=remediation,
                )
                findings.append(finding)

        return findings