"""
l'Instance Metadata Service richiede già l'header 'Metadata: true' e rifiuta
le richieste con X-Forwarded-For, ma non ha una modalità "token obbligatorio".
La protezione più vicina è il Metadata Security Protocol (proxy agent), che
può far rispettare il controllo di accesso sull'IMDS in modalità 'Enforce'.
"""
 
from core.finding import Finding, Severity
from core.plugin import Plugin
 
 
class IMDSProtectionPlugin(Plugin):
    name = "Azure VM Metadata Service Protection"
    description = (
        "Rileva VM senza Metadata Security Protocol in modalità Enforce "
        "sull'IMDS"
    )
 
    def run(self, provider) -> list[Finding]:
        findings = []
 
        vms = provider.list_vm_metadata_settings()
        unsupported_reported = False
 
        for vm in vms:
            name = vm["name"]
            resource_group = vm["resource_group"]
            status = vm["imds_protection"]
 
            if status == "Unsupported":
                if not unsupported_reported:
                    print(
                        "[Azure] Controllo IMDS saltato: la versione di "
                        "azure-mgmt-compute non supporta il proxy agent."
                    )
                    unsupported_reported = True
                continue
 
            # Non protetta: l'IMDS risponde a qualsiasi processo della VM
            if status == "Disabled":
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        resource=f"Azure VM: {name} (RG: {resource_group})",
                        description=(
                            f"La VM '{name}' non ha il Metadata Security "
                            f"Protocol attivo: in caso di SSRF o codice "
                            f"compromesso sulla VM, un attaccante può leggere "
                            f"dall'IMDS i token della managed identity."
                        ),
                        remediation=(
                            "Abilita il proxy agent sulla VM e imposta "
                            "l'IMDS in modalità 'Enforce' (Proprietà della VM > "
                            "Sicurezza > Metadata Security Protocol), "
                            "preferibilmente con un profilo di controllo "
                            "di accesso."
                        ),
                    )
                )
 
            # Attiva ma solo in audit: registra gli accessi ma non li blocca
            elif status == "Audit":
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        resource=f"Azure VM: {name} (RG: {resource_group})",
                        description=(
                            f"La VM '{name}' ha il Metadata Security Protocol in "
                            f"modalità 'Audit': gli accessi all'IMDS vengono "
                            f"registrati ma non bloccati."
                        ),
                        remediation=(
                            "Dopo aver verificato i log, passa l'IMDS dalla "
                            "modalità 'Audit' alla modalità 'Enforce'."
                        ),
                    )
                )
 
        return findings