import boto3
from botocore.exceptions import ClientError
from providers.base import Provider  # Importa l'interfaccia base astratta comune ai provider

class AWSProvider(Provider):
    """
    Implementazione del Provider per AWS.
    Utilizza boto3 per gestire l'autenticazione ed esporre metodi di interrogazione 
    standardizzati per risorse Storage (S3), Rete (Security Group) e Identità (IAM).
    """
    def __init__(self):
        # Inizializza la sessione a None; verrà popolata all'avvio in authenticate()
        self.session = None

    def authenticate(self):
        """
        Autentica lo scanner leggendo le credenziali e la regione configurate 
        nell'ambiente locale (es. variabili d'ambiente o profilo AWS CLI attivo).
        """
        try:
            # Crea una sessione boto3. Se è impostato export AWS_PROFILE=redteam,
            # boto3 userà in automatico quel profilo e la sua regione predefinita.
            self.session = boto3.Session()
            
            # Inizializza il client STS per validare l'identità attiva
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            print(f"[AWS] Autenticazione riuscita. Connesso come ARN: {identity['Arn']}")
            return True
            
        except ClientError as e:
            # Cattura errori di chiavi mancanti, errate o scadute
            print(f"[AWS] Errore di autenticazione: {e}")
            return False

    def list_storage_resources(self):
        """
        Recupera la lista dei nomi di tutti i bucket S3 presenti sull'account.
        Viene interrogato dal plugin di analisi storage (es. s3_public.py).
        """
        if not self.session:
            raise Exception("Provider AWS non autenticato. Chiama authenticate() per primo.")
        
        try:
            # S3 ha un endpoint globale: non richiede specifica rigida della regione per list_buckets
            s3 = self.session.client('s3')
            response = s3.list_buckets()
            
            # Estrae la lista dei nomi dei bucket
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            return buckets
            
        except ClientError as e:
            print(f"[AWS] Errore nel recupero dei bucket S3: {e}")
            return []

    def list_network_resources(self):
        """
        Recupera tutti i Security Group presenti nella regione configurata.
        Viene interrogato dal plugin open_network.py per analizzare le regole Ingress.
        """
        if not self.session:
            raise Exception("Provider AWS non autenticato. Chiama authenticate() per primo.")
            
        try:
            # Inizializza il client EC2. Se la sessione ha una regione (es. eu-central-1), usa quella
            region = self.session.region_name or 'eu-central-1'
            ec2 = self.session.client('ec2', region_name=region)
            
            # Recupera tutti i Security Group della regione
            response = ec2.describe_security_groups()
            return response.get('SecurityGroups', [])
            
        except ClientError as e:
            print(f"[AWS] Errore nel recupero dei Security Group: {e}")
            return []

    def list_iam_users_with_policies(self):
        """
        Enumera gli utenti IAM dell'account e recupera per ciascuno le managed policy allegate.
        Fornisce i dati grezzi necessari a plugins/aws/iam_overprivileged.py.
        """
        if not self.session:
            raise Exception("Provider AWS non autenticato. Chiama authenticate() per primo.")

        try:
            # IAM è un servizio globale in AWS
            iam = self.session.client('iam')
            users_data = []

            # 1. Recupera la lista di tutti gli utenti IAM
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    username = user['UserName']
                    
                    # 2. Recupera le Managed Policies direttamente allegate all'utente
                    attached_policies_resp = iam.list_attached_user_policies(UserName=username)
                    attached_policies = attached_policies_resp.get('AttachedPolicies', [])
                    
                    # 3. Struttura i dati per l'elaborazione del plugin
                    users_data.append({
                        "UserName": username,
                        "Arn": user['Arn'],
                        "Policies": attached_policies  # Contiene [{'PolicyName': '...', 'PolicyArn': '...'}]
                    })

            return users_data

        except ClientError as e:
            # In caso di permessi limitati o errori API, registra l'errore senza bloccare lo scanner
            print(f"[AWS] Errore nel recupero degli utenti/policy IAM: {e}")
            return []