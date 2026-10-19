"""
providers/azure_provider.py
 
Implementazione Azure dell'interfaccia astratta Provider (vedi providers/base.py).
Struttura allineata a providers/aws_provider.py: authenticate() esplicito,
poi list_storage_resources() e list_network_resources() richiamabili solo
dopo l'autenticazione.
"""
 
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient
 
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
        self.authorization_client = None
 
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
 
            print(
                f"[Azure] Autenticazione riuscita. Sottoscrizione: {subscription.display_name} ({self.subscription_id})"
            )
 
            self.storage_client = StorageManagementClient(
                self.credential, self.subscription_id
            )
            self.network_client = NetworkManagementClient(
                self.credential, self.subscription_id
            )
            self.authorization_client = AuthorizationManagementClient(
                self.credential, self.subscription_id
            )
            return True
 
        except Exception as e:
            print(f"[Azure] Errore di autenticazione: {e}")
            return False
 
    def list_storage_resources(self):
        """
        Recupera la lista degli storage account, con stato "public".
        """
        if not self.storage_client:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )
 
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
                        containers = (
                            self.storage_client.blob_containers.list(
                                resource_group_name=resource_group,
                                account_name=account.name,
                            )
                        )
                        for container in containers:
                            access = getattr(
                                container, "public_access", None
                            )
                            if access and str(access) != "None":
                                is_public = True
                                break
                    except Exception:
                        pass
 
                resources.append(
                    {
                        "name": account.name,
                        "resource_group": resource_group,
                        "public": is_public,
                    }
                )
 
        except Exception as e:
            print(
                f"[Azure] Errore nel recupero degli storage account: {e}"
            )
 
        return resources
 
    def list_network_resources(self):
        """
        Recupera la lista dei Network Security Group (NSG) estraendo
        esplicitamente le regole di sicurezza Inbound.
        """
        if not self.network_client:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )
 
        resources = []
        try:
            nsgs = self.network_client.network_security_groups.list_all()
            for nsg in nsgs:
                resource_group = nsg.id.split("/")[4]
                rules = []
 
                # Estraggono e strutturano soltanto le regole Inbound
                if nsg.security_rules:
                    for rule in nsg.security_rules:
                        if (
                            rule.direction
                            and str(getattr(rule.direction, "value", rule.direction)).lower() == "inbound"
                        ):
                            rules.append(
                                {
                                    "name": rule.name,
                                    # FIX: l'SDK restituisce un enum; il plugin confronta str(access).lower() con "allow",
                                    # quindi va convertito nella stringa semplice ('Allow' o 'Deny')
                                    "access": getattr(rule.access, "value", rule.access),
                                    "protocol": rule.protocol,  # 'Tcp', 'Udp', '*', etc.
                                    "source_address_prefix": rule.source_address_prefix,
                                    "source_address_prefixes": rule.source_address_prefixes,
                                    "destination_port_range": rule.destination_port_range,
                                    "destination_port_ranges": rule.destination_port_ranges,
                                }
                            )
 
                resources.append(
                    {
                        "id": nsg.id,
                        "name": nsg.name,
                        "resource_group": resource_group,
                        "rules": rules,
                    }
                )
 
        except Exception as e:
            print(
                f"[Azure] Errore nel recupero dei Network Security Group: {e}"
            )
 
        return resources
 
    def list_iam_resources(self):
        """
        Recupera i Role Assignment a livello di sottoscrizione,
        risolvendo i Role Definition Name per identificare ruoli sovra-privilegiati.
        """
        if not self.authorization_client:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )
 
        resources = []
        try:
            # Mappa cache per evitare chiamate ridondanti alle Role Definition
            role_definitions = {}
 
            # Scope a livello di Subscription
            scope = f"/subscriptions/{self.subscription_id}"
            assignments = self.authorization_client.role_assignments.list_for_scope(scope)
 
            for assignment in assignments:
                role_def_id = assignment.role_definition_id
 
                # Risoluzione del nome leggibile del ruolo (es. 'Owner', 'Contributor')
                if role_def_id not in role_definitions:
                    try:
                        role_def = self.authorization_client.role_definitions.get_by_id(role_def_id)
                        role_definitions[role_def_id] = role_def.role_name
                    except Exception:
                        role_definitions[role_def_id] = "Unknown"
 
                role_name = role_definitions[role_def_id]
 
                resources.append(
                    {
                        "id": assignment.id,
                        "name": assignment.name,
                        "principal_id": assignment.principal_id,
                        "principal_type": getattr(assignment, "principal_type", "Unknown"),
                        "role_definition_id": role_def_id,
                        "role_name": role_name,
                        "scope": assignment.scope,
                    }
                )
 
        except Exception as e:
            print(
                f"[Azure] Errore nel recupero dei Role Assignment IAM: {e}"
            )
 
        return resources
 
 
if __name__ == "__main__":
    provider = AzureProvider()
    if provider.authenticate():
        print("--- STORAGE RESOURCES ---")
        print(provider.list_storage_resources())
        print("\n--- NETWORK RESOURCES ---")
        print(provider.list_network_resources())
        print("\n--- IAM RESOURCES ---")
        print(provider.list_iam_resources())