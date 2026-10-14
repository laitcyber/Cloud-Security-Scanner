from botocore.exceptions import ClientError
from core.plugin import Plugin
from core.finding import Finding, Severity


class IMDSv2Plugin(Plugin):
    """
    Plugin per rilevare istanze EC2 che consentono ancora IMDSv1.

    L'Instance Metadata Service v1 risponde a 169.254.169.254 senza token di
    sessione: in presenza di una SSRF un attaccante può leggere le credenziali
    temporanee del ruolo IAM dell'istanza. IMDSv2 richiede un token (HTTP PUT),
    mitigando il vettore. Il check segnala le istanze con HttpTokens = 'optional'.
    Eredita da core.plugin.Plugin per essere caricato dinamicamente da Engine.
    """
    name = "AWS EC2 IMDSv1 Enabled"
    description = "Rileva istanze EC2 che permettono ancora IMDSv1 (HttpTokens optional)"

    def run(self, provider) -> list[Finding]:
        findings = []

        # Usa la regione della sessione oppure forza Francoforte (eu-central-1),
        # coerentemente con il resto del provider.
        target_region = provider.session.region_name or 'eu-central-1'
        ec2 = provider.session.client('ec2', region_name=target_region)

        try:
            paginator = ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance.get('InstanceId', 'Unknown-Instance')
                        state = instance.get('State', {}).get('Name', 'unknown')

                        # Il blocco MetadataOptions descrive la configurazione IMDS
                        metadata = instance.get('MetadataOptions', {})
                        http_tokens = metadata.get('HttpTokens', 'optional')

                        # 'optional' = IMDSv1 ancora accettato -> vulnerabile a SSRF
                        if http_tokens == 'optional':
                            findings.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    resource=f"EC2 Instance: {instance_id} ({target_region})",
                                    description=(
                                        f"L'istanza '{instance_id}' (stato: {state}) permette "
                                        f"IMDSv1 (HttpTokens = 'optional'): in caso di SSRF un "
                                        f"attaccante può esfiltrare le credenziali del ruolo IAM."
                                    ),
                                    remediation=(
                                        "Imporre IMDSv2 impostando HttpTokens = 'required' "
                                        "(aws ec2 modify-instance-metadata-options "
                                        f"--instance-id {instance_id} --http-tokens required "
                                        "--http-endpoint enabled)."
                                    ),
                                )
                            )

        except ClientError as e:
            print(f"[AWS] Errore nel recupero delle istanze EC2: {e}")

        return findings
