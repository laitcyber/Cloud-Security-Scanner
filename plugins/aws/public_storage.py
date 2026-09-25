from botocore.exceptions import ClientError
from core.finding import Finding, Severity
from core.plugin import Plugin

class PublicStoragePlugin(Plugin):
    # Metadati del plugin usati dall'engine per il log e il report
    name = "aws_public_storage"
    description = "Rileva bucket S3 esposti pubblicamente su AWS"

    def run(self, provider) -> list[Finding]:
        # Inizializza la lista vuota che conterrà le vulnerabilità trovate
        findings = []
        
        # Chiama il metodo del provider AWS per farsi dare la lista dei nomi dei bucket
        bucket_names = provider.list_storage_resources()
        
        # Se non ci sono bucket sull'account, termina subito e restituisce la lista vuota
        if not bucket_names:
            return findings
            
        # Inizializza un client specifico per il servizio S3 sfruttando la sessione già autenticata del provider
        s3 = provider.session.client('s3')

        # Cicla su ogni bucket trovato nell'account
        for bucket in bucket_names:
            is_public = False
            
            try:
                # Chiede ad AWS la configurazione del "Block Public Access" per questo specifico bucket
                pab = s3.get_public_access_block(Bucket=bucket)
                conf = pab['PublicAccessBlockConfiguration']
                
                # Se anche solo uno dei 4 blocchi di sicurezza è disattivato (False), il bucket è considerato a rischio
                if not (conf.get('BlockPublicAcls') and conf.get('IgnorePublicAcls') and 
                        conf.get('BlockPublicPolicy') and conf.get('RestrictPublicBuckets')):
                    is_public = True
                    
            except ClientError as e:
                # Se AWS risponde con 'NoSuchPublicAccessBlock', significa che le impostazioni di 
                # blocco pubblico non sono mai state configurate, quindi di default il bucket è esposto
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlock':
                    is_public = True

            # Se i controlli precedenti hanno stabilito che il bucket è pubblico, crea un Finding
            if is_public:
                findings.append(
                    Finding(
                        severity=Severity.HIGH, # Usa l'enum che hai definito nel core
                        resource=f"s3://{bucket}",
                        description=(
                            f"Il bucket S3 '{bucket}' è accessibile "
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

        # Restituisce all'engine tutti i problemi trovati su tutti i bucket controllati
        return findings