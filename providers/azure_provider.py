"""
providers/azure_provider.py

Implementazione Azure dell'interfaccia astratta Provider (vedi providers/base.py).
Rispetta lo stesso contratto di providers/aws_provider.py: list_storage_resources()
restituisce una lista di dict con almeno le chiavi "name" e "public" (booleano),
esattamente come fa la versione AWS per i bucket S3.
"""

from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import SubscriptionClient

from providers.base import Provider  # interfaccia astratta comune


class AzureProvider(Provider):
    """
    Provider Azure: gestisce autenticazione ed enumeration delle risorse
    tramite azure-identity / azure-mgmt-*. Il core non vede mai
    direttamente l'SDK Azure: tutto passa da qui.
    """

    def __init__(self, subscription_id: str = None):
        # DefaultAzureCredential usa in automatico le credenziali già
        # presenti sulla macchina dopo "az login".
        self.credential = DefaultAzureCredential()

        if subscription_id is None:
            sub_client = SubscriptionClient(self.credential)
            subscription_id = next(sub_client.subscriptions.list()).subscription_id

        self.subscription_id = subscription_id

        self.storage_client = StorageManagementClient(
            self.credential, self.subscription_id
        )

    def list_storage_resources(self) -> list[dict]:
        """
        Enumera gli storage account della sottoscrizione e determina,
        per ciascuno, se è effettivamente esposto pubblicamente.

        Un account è considerato "public" solo se:
          1. allow_blob_public_access è True a livello di account, E
          2. almeno un container al suo interno ha public_access
             diverso da "None" (cioè "Blob" o "Container")

        Se manca il permesso di leggere i container di un account (es.
        problemi di ruolo/permessi), il container viene semplicemente
        saltato nel controllo, senza far fallire l'intero scan.
        """
        resources = []

        for account in self.storage_client.storage_accounts.list():
            resource_group = account.id.split("/")[4]

            account_allows_public = bool(
                getattr(account, "allow_blob_public_access", False)
            )

            is_public = False
            public_containers = []

            if account_allows_public:
                try:
                    containers = self.storage_client.blob_containers.list(
                        resource_group_name=resource_group,
                        account_name=account.name,
                    )
                    for container in containers:
                        # public_access può essere "None", "Blob" o "Container"
                        access = getattr(container, "public_access", None)
                        if access and str(access) != "None":
                            is_public = True
                            public_containers.append(container.name)
                except Exception:
                    # Niente accesso ai container: non possiamo confermare,
                    # quindi non lo segniamo come pubblico per evitare
                    # falsi positivi.
                    pass

            resources.append({
                "provider": "azure",
                "resource_type": "storage_account",
                "name": account.name,
                "resource_group": resource_group,
                "location": account.location,
                "public": is_public,
                # utile per debug/report, non richiesto dal contratto minimo
                "public_containers": public_containers,
            })

        return resources


if __name__ == "__main__":
    # Test manuale: python providers/azure_provider.py
    provider = AzureProvider()
    for resource in provider.list_storage_resources():
        print(resource)