"""
providers/azure_provider.py
 
Implementazione Azure dell'interfaccia astratta Provider (vedi providers/base.py).
"""
 
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
 
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
 
    @staticmethod
    def _plain(value):
        # Gli enum dell'SDK vanno convertiti in stringa semplice
        return getattr(value, "value", value)

    def list_activity_log_settings(self):
        """
        Recupera le impostazioni di diagnostica dell'Activity Log della
        sottoscrizione. Restituisce None in caso di errore, così il plugin
        non genera falsi positivi.
        Verrà chiamato dal plugin activity_log_audit.py.
        """
        if not self.credential:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )

        try:
            client = MonitorManagementClient(self.credential, self.subscription_id)
            scope = f"/subscriptions/{self.subscription_id}"
            result = client.diagnostic_settings.list(scope)
            # Le versioni vecchie dell'SDK restituiscono un oggetto con .value
            items = getattr(result, "value", result)

            settings = []
            for s in items:
                categories = [
                    log.category
                    for log in (s.logs or [])
                    if log.enabled and log.category
                ]
                has_destination = bool(
                    s.workspace_id
                    or s.storage_account_id
                    or s.event_hub_authorization_rule_id
                )
                settings.append(
                    {
                        "name": s.name,
                        "has_destination": has_destination,
                        "enabled_categories": categories,
                    }
                )
            return settings

        except Exception as e:
            print(f"[Azure] Errore nel recupero delle diagnostic settings: {e}")
            return None

    def list_storage_encryption_settings(self):
        """
        Recupera l'origine della chiave di cifratura di ogni storage account.
        Verrà chiamato dal plugin encryption_at_rest.py.
        """
        if not self.storage_client:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )

        resources = []
        try:
            for account in self.storage_client.storage_accounts.list():
                encryption = getattr(account, "encryption", None)
                key_source = self._plain(getattr(encryption, "key_source", None))
                resources.append(
                    {
                        "name": account.name,
                        "resource_group": account.id.split("/")[4],
                        "key_source": key_source,
                    }
                )
        except Exception as e:
            print(f"[Azure] Errore nel recupero della cifratura degli storage: {e}")

        return resources

    def list_disk_encryption_settings(self):
        """
        Recupera il tipo di cifratura dei dischi gestiti.
        Verrà chiamato dal plugin encryption_at_rest.py.
        """
        if not self.credential:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )

        resources = []
        try:
            compute = ComputeManagementClient(self.credential, self.subscription_id)
            for disk in compute.disks.list():
                encryption = getattr(disk, "encryption", None)
                resources.append(
                    {
                        "name": disk.name,
                        "resource_group": disk.id.split("/")[4],
                        "encryption_type": self._plain(
                            getattr(encryption, "type", None)
                        ),
                    }
                )
        except Exception as e:
            print(f"[Azure] Errore nel recupero dei dischi gestiti: {e}")

        return resources

    def list_vm_metadata_settings(self):
        """
        Recupera lo stato del Metadata Security Protocol (proxy agent) sulle VM.
        Valori di imds_protection: 'Disabled', 'Audit', 'Enforce',
        'Unknown' o 'Unsupported' (SDK troppo vecchio).
        Verrà chiamato dal plugin imds_check.py.
        """
        if not self.credential:
            raise Exception(
                "Provider Azure non autenticato. Chiama authenticate() per primo."
            )

        resources = []
        try:
            from azure.mgmt.compute.models import SecurityProfile

            # L'SDK supporta la funzione solo se il modello ha questo attributo
            supported = hasattr(SecurityProfile(), "proxy_agent_settings")

            compute = ComputeManagementClient(self.credential, self.subscription_id)
            for vm in compute.virtual_machines.list_all():
                status = "Unsupported"

                if supported:
                    profile = getattr(vm, "security_profile", None)
                    agent = getattr(profile, "proxy_agent_settings", None)

                    if agent is None or not getattr(agent, "enabled", False):
                        status = "Disabled"
                    else:
                        # Le versioni più recenti separano le impostazioni IMDS
                        imds = getattr(agent, "imds", None)
                        mode = getattr(imds, "mode", None) or getattr(
                            agent, "mode", None
                        )
                        status = self._plain(mode) or "Unknown"

                resources.append(
                    {
                        "name": vm.name,
                        "resource_group": vm.id.split("/")[4],
                        "imds_protection": status,
                    }
                )
        except Exception as e:
            print(f"[Azure] Errore nel recupero delle VM: {e}")

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