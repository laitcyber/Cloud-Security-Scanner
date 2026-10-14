"""
plugins/azure/open_network.py

Plugin per il rilevamento di Network Security Group (NSG) su Azure
con regole Inbound aperte verso Internet (*, 0.0.0.0/0, Internet).
"""

from core.finding import Finding, Severity
from core.plugin import Plugin


class OpenNetworkPlugin(Plugin):
    """
    Plugin che analizza le regole di sicurezza dei Network Security Group (NSG)
    per individuare esposizioni di rete non sicure.
    """

    name = "Azure Open Network Check"
    description = "Rileva Network Security Group (NSG) con regole Inbound aperte verso Internet."

    # Prefissi sorgente considerati "aperti a tutti"
    OPEN_SOURCE_PREFIXES = ["*", "0.0.0.0/0", "internet"]

    # Porte ad alto rischio da segnalare con severità HIGH
    HIGH_RISK_PORTS = {
        "22": "SSH",
        "3389": "RDP",
        "23": "Telnet",
        "1433": "MSSQL",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "27017": "MongoDB",
        "6379": "Redis",
    }

    def run(self, provider) -> list[Finding]:
        """
        Esegue la scansione dei Network Security Group del provider Azure.
        """
        findings = []

        # Recupera la lista dei NSG tramite il metodo del provider
        nsgs = provider.list_network_resources()

        for nsg in nsgs:
            nsg_name = nsg.get("name")
            resource_group = nsg.get("resource_group")
            rules = nsg.get("rules", [])

            for rule in rules:
                # Controlliamo solo le regole che permettono il traffico (Allow)
                if str(rule.get("access", "")).lower() != "allow":
                    continue

                # Estrazione e normalizzazione dei sorgenti
                sources = []
                if rule.get("source_address_prefix"):
                    sources.append(str(rule["source_address_prefix"]).lower())
                if rule.get("source_address_prefixes"):
                    sources.extend(
                        [str(s).lower() for s in rule["source_address_prefixes"]]
                    )

                # Verifica se la regola permette l'accesso da qualsiasi fonte
                is_open = any(src in self.OPEN_SOURCE_PREFIXES for src in sources)

                if is_open:
                    # Estrazione e normalizzazione delle porte di destinazione
                    ports = []
                    if rule.get("destination_port_range"):
                        ports.append(str(rule["destination_port_range"]))
                    if rule.get("destination_port_ranges"):
                        ports.extend(
                            [str(p) for p in rule["destination_port_ranges"]]
                        )

                    port_str = ", ".join(ports) if ports else "Tutte"

                    # Determinazione della severità in base alle porte esposte
                    severity, risk_desc = self._evaluate_severity(ports)

                    findings.append(
                        Finding(
                            severity=severity,
                            resource=f"NSG: {nsg_name} (RG: {resource_group}) / rule: {rule['name']}",
                            description=(
                                f"Il Network Security Group '{nsg_name}' (Resource Group: "
                                f"'{resource_group}') ha la regola Inbound '{rule['name']}' "
                                f"aperta verso Internet ({', '.join(sources)}). "
                                f"Porte interessate: {port_str} ({risk_desc})."
                            ),
                            remediation=(
                                f"Restringere la regola '{rule['name']}' nel NSG '{nsg_name}' "
                                "limitando 'source_address_prefix' a IP/CIDR specifici e "
                                "fidati invece di wildcard/Internet."
                            ),
                        )
                    )

        return findings

    def _evaluate_severity(self, ports: list) -> tuple:
        """
        Calcola la severità in base alle porte esposte.
        Restituisce (Severity, descrizione del rischio).
        """
        # Se è aperta qualsiasi porta (*)
        if "*" in ports:
            return Severity.CRITICAL, "Tutte le porte aperte"

        # Porte ad alto rischio
        for port in ports:
            if port in self.HIGH_RISK_PORTS:
                service = self.HIGH_RISK_PORTS[port]
                return Severity.HIGH, f"Servizio critico esposto: {service} (porta {port})"

        # Porte generiche (es. 80, 443 o custom)
        return Severity.MEDIUM, "Porte generiche aperte"
