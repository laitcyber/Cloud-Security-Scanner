"""
providers/azure_provider.py

Implementazione Azure dell'interfaccia astratta Provider (vedi providers/base.py).
Struttura allineata a providers/aws_provider.py: authenticate() esplicito,
poi list_storage_resources() e list_network_resources() richiamabili solo
dopo l'autenticazione.

NB: list_storage_resources() qui restituisce dict con "name" e "public",
ma aws_provider.py attuale restituisce solo nomi (stringhe) per i bucket S3,
senza stato "public". Il contratto tra i due provider va allineato con
Walid prima di collegare i plugin definitivamente.
"""

from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient

from providers.base import Provider  # interfaccia astratta comune


class AzureProvider(Provider):
    """
    Provider Azure: gestisce autenticazione ed enumeration delle risorse
    tramite azure-identity / azure-mgmt-*. Il core non vede mai
    direttamente l'SDK Azure: tutto passa da qui.
    """

    def __init__(self):
        # Nessuna autenticazione qui: come in AWSProvider, i client
        # vengono creati solo dopo authenticate().
        self.credential = None
        self.subscription_id = None
        self.storage_client = None
        self.network_client = None

    def authenticate(self):
        """
        Autentica lo scanner usando le credenziali locali Azure (quelle
        create con 'az login'). Restituisce True/False come in AWSProvider.
        """
        try:
            self.credential = DefaultAzureCredential()

            # Recupera la prima sottoscrizione disponibile, come test
            # rapido di autenticazione (equivalente a sts.get_caller_identity())
            sub_client = SubscriptionClient(self.credential)
            subscription = next(sub_client.subscriptions.list())
            self.subscription_id = subscription.subscription_id

            print(f"[Azure] Autenticazione riuscita. Sottoscrizione: {subscription.display_name} ({self.subscription_id})")

            self.storage_client = StorageManagementClient(
                self.credential, self.subscription_id
            )
            self.network_client = NetworkManagementClient(
                self.credential, self.subscription_id
            )
            return True

        except Exception as e:
            print(f"[Azure] Errore di autenticazione: {e}")
            return False

    def list_storage_resources(self):
        """
        Recupera la lista degli storage account, con stato "public".

        ATTENZIONE: da confermare con Walid se il formato deve restare
        un dict {"name": ..., "public": ...} o allinearsi a una lista
        di soli nomi come fa attualmente aws_provider.py.
        """
        if not self.storage_client:
            raise Exception("Provider Azure non autenticato. Chiama authenticate() per primo.")

        resources = []
        try:
            for account in self.storage_client.storage_accounts.list():
                resource_group = account.id.split("/")[4]

                account_allows_public = bool(
                    getattr(account, "allow_blob_public_access", False)
                )
                is_public = False

                if account_allows_public:
                    try:
                        containers = self.storage_client.blob_containers.list(
                            resource_group_name=resource_group,
                            account_name=account.name,
                        )
                        for container in containers:
                            access = getattr(container, "public_access", None)
                            if access and str(access) != "None":
                                is_public = True
                                break
                    except Exception:
                        pass

                resources.append({
                    "name": account.name,
                    "resource_group": resource_group,
                    "public": is_public,
                })

        except Exception as e:
            print(f"[Azure] Errore nel recupero degli storage account: {e}")

        return resources

    def list_network_resources(self):
        """
        Recupera la lista dei Network Security Group con le loro regole.
        Verrà chiamato dal plugin open_network.py.
        """
        if not self.network_client:
            raise Exception("Provider Azure non autenticato. Chiama authenticate() per primo.")

        try:
            nsgs = list(self.network_client.network_security_groups.list_all())
            return nsgs
        except Exception as e:
            print(f"[Azure] Errore nel recupero dei Network Security Group: {e}")
            return []


if __name__ == "__main__":
    provider = AzureProvider()
    if provider.authenticate():
        print(provider.list_storage_resources())