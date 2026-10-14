from botocore.exceptions import ClientError
from core.plugin import Plugin
from core.finding import Finding, Severity


class CloudTrailAuditPlugin(Plugin):
    """
    Plugin per verificare la visibilità del control plane tramite CloudTrail.

    CloudTrail registra le chiamate API dell'account: è il pilastro del
    rilevamento (lo stesso logging che ha permesso al Blue Team di intercettare
    l'attività del redteam-scanner). Se il logging è assente, spento o non
    multi-region, le azioni malevole non lasciano traccia.
    Il check segnala: nessun trail, trail con logging spento, assenza di un
    trail multi-region attivo.
    Eredita da core.plugin.Plugin per essere caricato dinamicamente da Engine.
    """
    name = "AWS CloudTrail Logging"
    description = "Verifica presenza, stato e copertura multi-region di CloudTrail"

    def run(self, provider) -> list[Finding]:
        findings = []

        # Usa la regione della sessione oppure forza Francoforte (eu-central-1),
        # coerentemente con il resto del provider.
        target_region = provider.session.region_name or 'eu-central-1'
        ct = provider.session.client('cloudtrail', region_name=target_region)

        try:
            # describe_trails elenca i trail visibili dalla regione corrente
            trails = ct.describe_trails(includeShadowTrails=False).get('trailList', [])

            # Caso 1: nessun trail configurato -> cecità totale sul control plane
            if not trails:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        resource=f"CloudTrail ({target_region})",
                        description=(
                            "Nessun trail CloudTrail configurato: le chiamate API "
                            "dell'account non vengono registrate (nessuna visibilità "
                            "per il rilevamento e l'incident response)."
                        ),
                        remediation=(
                            "Creare un trail multi-region con logging attivo, "
                            "integrato con CloudWatch Logs e con un bucket S3 "
                            "dedicato e protetto."
                        ),
                    )
                )
                return findings

            # Caso 2: esaminare ogni trail (stato logging + copertura multi-region)
            any_multiregion_logging = False

            for trail in trails:
                name = trail.get('Name', 'Unknown-Trail')
                trail_arn = trail.get('TrailARN', name)
                is_multiregion = trail.get('IsMultiRegionTrail', False)

                # get_trail_status dice se il trail sta effettivamente loggando
                try:
                    status = ct.get_trail_status(Name=trail_arn)
                    is_logging = status.get('IsLogging', False)
                except ClientError:
                    is_logging = False

                if not is_logging:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            resource=f"CloudTrail: {name}",
                            description=(
                                f"Il trail '{name}' esiste ma il logging è DISATTIVATO "
                                f"(IsLogging = False): non sta registrando alcun evento."
                            ),
                            remediation=(
                                f"Riattivare il logging sul trail '{name}' "
                                "(aws cloudtrail start-logging --name <trail>)."
                            ),
                        )
                    )

                if is_multiregion and is_logging:
                    any_multiregion_logging = True

            # Caso 3: esistono trail attivi ma nessuno copre tutte le region
            if not any_multiregion_logging:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        resource=f"CloudTrail ({target_region})",
                        description=(
                            "Nessun trail multi-region attivo: eventuali attività in "
                            "region non coperte non vengono registrate."
                        ),
                        remediation=(
                            "Configurare almeno un trail con IsMultiRegionTrail = True "
                            "e logging attivo per coprire tutte le region."
                        ),
                    )
                )

        except ClientError as e:
            print(f"[AWS] Errore nel recupero dei trail CloudTrail: {e}")

        return findings
