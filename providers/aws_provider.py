import boto3
from botocore.exceptions import ClientError
from providers.base import Provider  # Importa l'interfaccia base

class AWSProvider(Provider):
    """
    Implementazione del Provider per AWS.
    Usa boto3 per autenticarsi ed estrarre le risorse cloud.
    """
    def __init__(self):
        # Inizializza la sessione a None. Verrà popolata in authenticate()
        self.session = None

    def authenticate(self):
        """
        Autentica lo scanner usando le credenziali locali AWS (es. quelle
        configurate con 'aws configure').
        """
        try:
            # Crea una nuova sessione boto3 usando le credenziali di default
            self.session = boto3.Session()
            # Inizializza il client STS (Security Token Service) per verificare le credenziali
            sts = self.session.client('sts')
            
            # get_caller_identity() serve come test rapido: se funziona, siamo loggati
            identity = sts.get_caller_identity()
            print(f"[AWS] Autenticazione riuscita. Connesso come ARN: {identity['Arn']}")
            return True
            
        except ClientError as e:
            # Se le credenziali sono errate o non configurate, cattura l'errore
            print(f"[AWS] Errore di autenticazione: {e}")
            return False

    def list_storage_resources(self):
        """
        Recupera la lista dei bucket S3 presenti sull'account.
        Questo metodo verrà chiamato dal plugin public_storage.py.
        """
        if not self.session:
            raise Exception("Provider AWS non autenticato. Chiama authenticate() per primo.")
        
        try:
            # Crea un client per il servizio S3
            s3 = self.session.client('s3')
            # Richiede ad AWS la lista di tutti i bucket
            response = s3.list_buckets()
            
            # Estrae solo i nomi dei bucket dalla risposta dell'API
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            return buckets
            
        except ClientError as e:
            print(f"[AWS] Errore nel recupero dei bucket S3: {e}")
            return []

    def list_network_resources(self):
        """
        Recupera la lista dei Security Group.
        Questo metodo verrà chiamato dal plugin open_network.py.
        """
        if not self.session:
            raise Exception("Provider AWS non autenticato. Chiama authenticate() per primo.")
            
        try:
            # Crea un client per il servizio EC2, che gestisce i Security Group
            ec2 = self.session.client('ec2', region_name='eu-central-1') # Puoi cambiare la regione se serve
            
            # Richiede ad AWS la lista dei Security Group
            response = ec2.describe_security_groups()
            
            # Ritorna la lista completa dei Security Group con tutte le loro regole
            return response.get('SecurityGroups', [])
            
        except ClientError as e:
            print(f"[AWS] Errore nel recupero dei Security Group: {e}")
            return []