"""
plugins/azure/iam_overprivileged.py

Plugin per il rilevamento di permessi IAM eccessivi (overprivileged) su Azure.
Identifica l'assegnazione di ruoli critici (es. Owner, Contributor) a livello
di Subscription o Resource Group.
"""

from core.finding import Finding, Severity
from core.plugin import Plugin


class IAMOverprivilegedPlugin(Plugin):
    """
    Plugin che analizza le assegnazioni di ruoli (Role Assignments) su Azure
    per individuare identità con ruoli ad alto privilegio su ambiti estesi.
    """

    name = "Azure IAM Overprivileged Check"
    description = "Rileva assegnazioni di ruoli ad alto privilegio (Owner, Contributor) su Subscription o Resource Group."

    # Ruoli considerati ad alto rischio/sovra-privilegiati (nome in minuscolo -> Severity)
    CRITICAL_ROLES = {
        "owner": Severity.CRITICAL,
        "contributor": Severity.HIGH,
        "user access administrator": Severity.HIGH,
    }

    def run(self, provider) -> list[Finding]:
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

                findings.append(
                    Finding(
                        severity=severity,
                        resource=f"Role Assignment: {role_name} -> {principal_id} ({scope_type})",
                        description=(
                            f"Assegnazione di ruolo sovra-privilegiata: l'entità "
                            f"'{principal_id}' ({principal_type}) possiede il ruolo "
                            f"'{role_name}' a livello di {scope_type} (Scope: '{scope}')."
                        ),
                        remediation=(
                            f"Applicare il principio del minimo privilegio: rimuovere il "
                            f"ruolo '{role_name}' dallo scope esteso e assegnare ruoli più "
                            "specifici (Custom Role) limitati alle sole risorse necessarie."
                        ),
                    )
                )

        return findings
