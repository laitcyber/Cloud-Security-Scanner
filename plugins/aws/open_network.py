from core.finding import Finding, Severity

# Dizionario delle porte critiche che non dovrebbero mai essere esposte al pubblico
CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    23: "Telnet",
    21: "FTP",
    3306: "MySQL",
    5432: "PostgreSQL"
}

class OpenNetworkPlugin:
    """
    Plugin per il rilevamento di Security Group con regole Ingress aperte a 0.0.0.0/0.
    """
    def __init__(self, provider):
        # Riceve l'istanza di AWSProvider inizializzata dall'engine
        self.provider = provider

    def run(self):
        findings = []
        
        # Chiama il metodo definito in AWSProvider per ottenere i Security Group
        security_groups = self.provider.list_network_resources()

        for sg in security_groups:
            sg_id = sg.get("GroupId", "Unknown-SG")
            sg_name = sg.get("GroupName", "Unknown-Name")

            # Itera sulle regole del traffico in entrata (IpPermissions)
            for rule in sg.get("IpPermissions", []):
                ip_protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                # Verifica se tra i range IPv4 c'è l'apertura totale (0.0.0.0/0)
                is_open_to_all = any(
                    ip_range.get("CidrIp") == "0.0.0.0/0" 
                    for ip_range in rule.get("IpRanges", [])
                )

                if is_open_to_all:
                    # Caso 1: Tutto il traffico consentito su ogni porta (protocollo -1)
                    if ip_protocol == "-1":
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                resource=f"{sg_name} ({sg_id})",
                                description="Security Group con tutto il traffico in ingresso aperto verso 0.0.0.0/0.",
                                remediation="Limitare il traffico in ingresso solo ai protocolli e agli IP strettamente necessari."
                            )
                        )
                    # Caso 2: Intervalli o porte specifiche aperte a tutti
                    elif from_port is not None and to_port is not None:
                        # Controlla se il range include una delle porte critiche definite sopra
                        flagged_ports = [
                            f"{p} ({name})" 
                            for p, name in CRITICAL_PORTS.items() 
                            if from_port <= p <= to_port
                        ]

                        if flagged_ports:
                            sev = Severity.HIGH
                            details = f"Porte esposte: {', '.join(flagged_ports)}"
                        else:
                            sev = Severity.MEDIUM
                            details = f"Porta/Range esposto: {from_port}-{to_port}/{ip_protocol}"

                        findings.append(
                            Finding(
                                severity=sev,
                                resource=f"{sg_name} ({sg_id})",
                                description=f"Regola Ingress aperta a 0.0.0.0/0. {details}.",
                                remediation=f"Restringere l'accesso CIDR per la porta {from_port} a IP o subnet fidate."
                            )
                        )

        return findings