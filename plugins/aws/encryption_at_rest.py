from botocore.exceptions import ClientError
from core.plugin import Plugin
from core.finding import Finding, Severity


class EncryptionAtRestPlugin(Plugin):
    """
    Plugin per rilevare la cifratura a riposo (At-Rest Encryption) mancante.
    Controlla due superfici:
      - Bucket S3 senza Server-Side Encryption (SSE) di default.
      - Volumi EBS con Encrypted = False.
    Dati non cifrati a riposo violano le baseline CIS/NIST e sono esposti
    in caso di furto/condivisione di snapshot o backup.
    Eredita da core.plugin.Plugin per essere caricato dinamicamente da Engine.
    """
    name = "AWS Encryption At Rest"
    description = "Rileva bucket S3 e volumi EBS privi di cifratura a riposo"

    def run(self, provider) -> list[Finding]:
        findings = []

        # ------------------------------------------------------------------
        # 1) S3: verifica la cifratura di default (SSE-S3 o SSE-KMS)
        # ------------------------------------------------------------------
        bucket_names = provider.list_storage_resources()

        if bucket_names:
            s3 = provider.session.client('s3')

            for bucket in bucket_names:
                try:
                    # Se il bucket NON ha una regola di cifratura di default,
                    # AWS solleva l'errore 'ServerSideEncryptionConfigurationNotFoundError'
                    s3.get_bucket_encryption(Bucket=bucket)
                    # Nessuna eccezione = cifratura presente, nessun finding.

                except ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                resource=f"s3://{bucket}",
                                description=(
                                    f"Il bucket S3 '{bucket}' non ha una cifratura "
                                    f"a riposo di default (SSE-S3 o SSE-KMS) configurata."
                                ),
                                remediation=(
                                    "Abilitare la Default Encryption sul bucket "
                                    "(SSE-S3 o preferibilmente SSE-KMS) e, se richiesto "
                                    "dalla baseline, imporla via bucket policy "
                                    "(deny su s3:PutObject senza header di cifratura)."
                                ),
                            )
                        )
                    # Altri errori (es. AccessDenied) vengono ignorati per non
                    # bloccare la scansione sugli altri bucket.

        # ------------------------------------------------------------------
        # 2) EBS: verifica i singoli volumi (Encrypted) e il default regionale
        # ------------------------------------------------------------------
        # Usa la regione della sessione oppure forza Francoforte (eu-central-1),
        # coerentemente con il resto del provider.
        target_region = provider.session.region_name or 'eu-central-1'
        ec2 = provider.session.client('ec2', region_name=target_region)

        try:
            # Controllo del flag "cifratura EBS di default" a livello di account/regione
            default_enc = ec2.get_ebs_encryption_by_default().get('EbsEncryptionByDefault', False)
            if not default_enc:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        resource=f"EBS Default Encryption ({target_region})",
                        description=(
                            f"La cifratura EBS di default NON è attiva nella regione "
                            f"'{target_region}': i nuovi volumi possono essere creati in chiaro."
                        ),
                        remediation=(
                            "Attivare 'EBS encryption by default' nella regione "
                            "(EC2 > Impostazioni > Cifratura di default dei dati)."
                        ),
                    )
                )
        except ClientError:
            # Se l'API non è disponibile o manca il permesso, si prosegue coi volumi.
            pass

        try:
            # Controllo dei singoli volumi EBS esistenti
            paginator = ec2.get_paginator('describe_volumes')
            for page in paginator.paginate():
                for vol in page.get('Volumes', []):
                    if not vol.get('Encrypted', False):
                        vol_id = vol.get('VolumeId', 'Unknown-Volume')
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                resource=f"EBS Volume: {vol_id} ({target_region})",
                                description=(
                                    f"Il volume EBS '{vol_id}' non è cifrato a riposo "
                                    f"(Encrypted = False)."
                                ),
                                remediation=(
                                    "Creare uno snapshot, copiarlo con cifratura KMS "
                                    "abilitata e ricreare il volume dallo snapshot cifrato "
                                    "(i volumi EBS non si cifrano in-place)."
                                ),
                            )
                        )
        except ClientError as e:
            print(f"[AWS] Errore nel recupero dei volumi EBS: {e}")

        return findings
