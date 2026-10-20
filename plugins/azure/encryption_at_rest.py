"""
plugins/azure/encryption_at_rest.py

gestiti sono SEMPRE cifrati a riposo con chiavi gestite da Microsoft e la
cifratura non si può disattivare. Il check segnala quindi le risorse che non
usano chiavi gestite dal cliente (CMK), come richiesto dalle raccomandazioni
CIS Azure Foundations di livello 2 per i dati critici.
"""
 
from core.finding import Finding, Severity
from core.plugin import Plugin
 
 
class EncryptionAtRestPlugin(Plugin):
    name = "Azure Encryption At Rest"
    description = (
        "Rileva storage account e dischi gestiti che non usano chiavi "
        "gestite dal cliente (CMK)"
    )
 
    def run(self, provider) -> list[Finding]:
        findings = []
 
        # ------------------------------------------------------------------
        # 1) Storage account: origine della chiave di cifratura
        # ------------------------------------------------------------------
        for account in provider.list_storage_encryption_settings():
            name = account["name"]
            resource_group = account["resource_group"]
 
            # "Microsoft.Keyvault" = chiave del cliente; "Microsoft.Storage" = chiave Microsoft
            if account["key_source"] != "Microsoft.Keyvault":
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        resource=f"azure-storage://{name}",
                        description=(
                            f"Lo storage account '{name}' (Resource Group: "
                            f"'{resource_group}') è cifrato a riposo con chiavi "
                            f"gestite da Microsoft e non con chiavi gestite dal "
                            f"cliente (CMK): il cliente non controlla rotazione "
                            f"e revoca della chiave."
                        ),
                        remediation=(
                            "Per dati critici, configura la cifratura con chiave "
                            "gestita dal cliente: Account di archiviazione > "
                            "Crittografia > Chiavi gestite dal cliente, con una "
                            "chiave in Azure Key Vault."
                        ),
                    )
                )
 
        # ------------------------------------------------------------------
        # 2) Dischi gestiti: tipo di cifratura
        # ------------------------------------------------------------------
        for disk in provider.list_disk_encryption_settings():
            name = disk["name"]
            resource_group = disk["resource_group"]
 
            if disk["encryption_type"] == "EncryptionAtRestWithPlatformKey":
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        resource=f"Managed Disk: {name} (RG: {resource_group})",
                        description=(
                            f"Il disco gestito '{name}' è cifrato a riposo solo "
                            f"con chiave gestita dalla piattaforma (nessuna CMK "
                            f"e nessun Disk Encryption Set)."
                        ),
                        remediation=(
                            "Crea un Disk Encryption Set collegato a una chiave "
                            "in Azure Key Vault e associalo al disco "
                            "(Disco > Crittografia > Chiave gestita dal cliente)."
                        ),
                    )
                )
 
        return findings