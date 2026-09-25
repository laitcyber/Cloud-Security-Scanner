from core.finding import Finding, Severity
from core.plugin import Plugin


class PublicStoragePlugin(Plugin):
    name = "azure_public_storage"
    description = "Rileva storage account esposti pubblicamente su Azure"

    def run(self, provider) -> list[Finding]:
        findings = []
        resources = provider.list_storage_resources()

        for resource in resources:
            if resource["public"]:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        resource=f"azure-storage://{resource['name']}",
                        description=(
                            f"Lo storage account '{resource['name']}' consente "
                            f"l'accesso pubblico ai blob (allowBlobPublicAccess "
                            f"abilitato, con almeno un container configurato "
                            f"come pubblico)."
                        ),
                        remediation=(
                            "Disabilita 'Allow Blob public access' a livello "
                            "di storage account dal portale Azure (o con "
                            "az storage account update --allow-blob-public-access false), "
                            "e imposta il livello di accesso pubblico dei "
                            "container su 'Private' anziché 'Blob' o 'Container'."
                        ),
                    )
                )

        return findings