from core.plugin import Plugin
from core.finding import Finding, Severity

# Policy AWS gestite note per concedere privilegi ampi o totali
OVERPRIVILEGED_POLICIES = {
    "AdministratorAccess": {
        "severity": Severity.CRITICAL,
        "description": "L'utente possiede accesso amministrativo totale a tutti i servizi e risorse dell'account (*:*)."
    },
    "PowerUserAccess": {
        "severity": Severity.HIGH,
        "description": "L'utente ha accesso a quasi tutte le risorse e servizi AWS, escluse solo le funzioni amministrative IAM."
    },
    "IAMFullAccess": {
        "severity": Severity.HIGH,
        "description": "L'utente ha controllo totale su IAM, permettendo potenziale privilege escalation creando credenziali con pieni poteri."
    }
}

class IAMOverprivilegedPlugin(Plugin):
    """
    Plugin per il rilevamento di utenti IAM con policy overprivileged
    direttamente collegate (Attached Managed Policies).
    """
    def __init__(self):
        super().__init__()
        self.name = "AWS IAM Overprivileged Users"

    def run(self, provider) -> list[Finding]:
        """
        Interroga il provider per ottenere gli utenti e le loro policy,
        generando finding per ogni policy con permessi eccessivi.
        """
        findings = []

        # Recupera gli utenti con le relative policy tramite il metodo in AWSProvider
        users_data = provider.list_iam_users_with_policies()

        for user in users_data:
            username = user.get("UserName", "Unknown-User")
            user_arn = user.get("Arn", username)
            attached_policies = user.get("Policies", [])

            for policy in attached_policies:
                policy_name = policy.get("PolicyName", "")

                if policy_name in OVERPRIVILEGED_POLICIES:
                    policy_info = OVERPRIVILEGED_POLICIES[policy_name]
                    
                    findings.append(
                        Finding(
                            severity=policy_info["severity"],
                            resource=f"IAM User: {username} ({user_arn})",
                            description=f"Policy rischiosa associata: '{policy_name}'. {policy_info['description']}",
                            remediation=(
                                f"Rimuovere '{policy_name}' dall'utente '{username}'. "
                                "Applicare il principio del minimo privilegio creando una policy su misura "
                                "limitata solo alle azioni e alle risorse strettamente necessarie."
                            )
                        )
                    )

        return findings