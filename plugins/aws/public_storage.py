from core.finding import Finding, Severity
from core.plugin import Plugin


class PublicStoragePlugin(Plugin):
    name = "aws_public_storage"
    description = "Rileva bucket S3 esposti pubblicamente su AWS"

    def run(self, provider) -> list[Finding]:
        findings = []
        resources = provider.list_storage_resources()

        for resource in resources:
            if resource["public"]:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        resource=f"s3://{resource['name']}",
                        description=(
                            f"Il bucket S3 '{resource['name']}' è accessibile "
                            f"pubblicamente (ACL, Public Access Block o bucket "
                            f"policy permette l'accesso a chiunque)."
                        ),
                        remediation=(
                            "Abilita il Block Public Access a livello di bucket "
                            "e/o account, rimuovi eventuali grant ACL verso "
                            "'AllUsers'/'AuthenticatedUsers' e rivedi la bucket "
                            "policy per rimuovere Principal: '*' non necessari."
                        ),
                    )
                )

        return findings