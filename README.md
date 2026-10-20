# Cloud-Security-Scanner

Scanner di sicurezza cloud scritto in Python, con un core generico e indipendente dal
provider ed estendibile tramite plugin. L'obiettivo non è replicare tool già pronti come
Prowler o ScoutSuite, ma progettare da zero un'architettura software pulita applicata a un
problema reale: enumerare le risorse di un account cloud, rilevare le misconfigurazioni più
comuni e produrre un report strutturato.

Lo stesso core funziona sia su **AWS** che su **Azure**: cambia solo il provider e i plugin
caricati.

Progetto sviluppato come project work del corso di cybersecurity (ITS Umbria Academy).

---

## Idea di fondo

La maggior parte degli incidenti cloud non nasce da bug della piattaforma, ma da
**configurazioni sbagliate** di chi la usa (bucket lasciati pubblici, permessi IAM troppo
larghi, porte aperte a tutti, dati non cifrati). Questo tool cerca proprio quelle
configurazioni.

## Architettura

Il core non sa cosa sia AWS o Azure: sa solo caricare una lista di plugin e chiamare il loro
metodo `run()`, ricevendo in cambio oggetti `Finding` standard (severità, risorsa,
descrizione, remediation). Ogni plugin usa l'SDK del provider (`boto3` per AWS,
`azure-sdk` per Azure), mentre il Provider astrae l'autenticazione e le chiamate API comuni.

| Componente | Ruolo |
|---|---|
| `core/engine.py` | Carica dinamicamente i plugin da una cartella e li esegue |
| `core/finding.py` | Classe standard per i risultati (severity, resource, description, remediation) |
| `core/plugin.py` | Interfaccia astratta comune a tutti i plugin |
| `core/report.py` | Stampa a tabella e salvataggio del report JSON |
| `providers/base.py` | Interfaccia astratta comune ai cloud provider |
| `providers/aws_provider.py` | Autenticazione e chiamate API AWS (boto3) |
| `providers/azure_provider.py` | Autenticazione e chiamate API Azure |
| `plugins/aws/*.py` | Check specifici AWS |
| `plugins/azure/*.py` | Check specifici Azure |

I plugin vengono scoperti in automatico: basta aggiungere un file nella cartella
`plugins/<provider>/` con una classe che eredita da `Plugin`. Non serve registrarlo da
nessuna parte.

## Check implementati (AWS)

| Plugin | Cosa rileva | Severità |
|---|---|---|
| `public_storage.py` | Bucket S3 esposti pubblicamente | HIGH |
| `iam_overprivileged.py` | Utenti IAM con policy troppo potenti (AdministratorAccess, PowerUserAccess, IAMFullAccess) | HIGH / CRITICAL |
| `open_network.py` | Security Group con regole Ingress aperte a `0.0.0.0/0` (SSH, RDP, DB...) | MEDIUM / HIGH / CRITICAL |
| `encryption_at_rest.py` | Bucket S3 e volumi EBS privi di cifratura a riposo | MEDIUM / HIGH |
| `imds_check.py` | Istanze EC2 che permettono ancora IMDSv1 (esposte a SSRF) | HIGH |
| `cloudtrail_audit.py` | CloudTrail assente, spento o senza copertura multi-region | MEDIUM / HIGH |

## Check implementati (Azure)

Stesso core, servizi Azure. Ogni controllo ha un diretto corrispettivo AWS.

| Plugin | Cosa rileva | Equivalente AWS | Severità |
|---|---|---|---|
| `public_storage.py` | Storage account con accesso pubblico ai blob | S3 pubblici | HIGH |
| `iam_overprivileged.py` | Ruoli Owner / Contributor su scope troppo ampi (Subscription / Resource Group) | IAM overprivileged | HIGH / CRITICAL |
| `open_network.py` | Network Security Group (NSG) con regole Inbound aperte a Internet (`*`, `0.0.0.0/0`) su porte critiche | Security Group aperti | MEDIUM / HIGH / CRITICAL |
| `encryption_at_rest.py` | Storage account e dischi gestiti che non usano chiavi gestite dal cliente (CMK) | Cifratura a riposo | MEDIUM |
| `imds_check.py` | VM senza Metadata Security Protocol in modalità *Enforce* sull'IMDS | IMDSv2 | MEDIUM / HIGH |
| `activity_log_audit.py` | Activity Log della subscription non esportato o senza le categorie di sicurezza | CloudTrail | MEDIUM / HIGH |

> Nota: su Azure la cifratura a riposo di base è sempre attiva (chiavi Microsoft); il check
> segnala le risorse che non usano chiavi gestite dal cliente (CMK), come richiesto dalle
> baseline CIS per i dati critici.

## Requisiti

- Python 3.12 (vedi `.python-version`)
- Le dipendenze in `requirements.txt` (`boto3` per AWS, gli SDK Azure, `flask` per la web UI)
- AWS CLI e/o Azure CLI configurate con un profilo valido

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Utilizzo (CLI)

Lo scanner legge le credenziali dal profilo cloud attivo (non le gestisce lui).

### AWS

```bash
export AWS_PROFILE=<tuo-profilo>
export AWS_DEFAULT_REGION=eu-central-1
python main.py --provider aws
```

### Azure

```bash
az login
python main.py --provider azure
```

Al termine viene stampata una tabella riassuntiva e salvato un `report.json` con tutti i
dettagli e le remediation.

### Esempio di output

```
================================================================================
SEVERITY   | RISORSA                        | DESCRIZIONE
================================================================================
MEDIUM     | EBS Default Encryption (eu-central-1) | La cifratura EBS di default NON è a...
HIGH       | EBS Volume: vol-0ecede8a287d4f51f (eu-central-1) | Il volume EBS 'vol-0ece...
CRITICAL   | IAM User: dev-troppi-permessi  | Policy rischiosa associata: 'Admini...
HIGH       | EC2 Instance: i-0685dacf627dffe5b | L'istanza permette ancora IMDSv1...
HIGH       | honeypot-sg (sg-0b6ea68776528e688) | Regola Ingress aperta a 0.0.0.0/0...
================================================================================

[*] Report dettagliato salvato in report.json
```

## Interfaccia web (locale)

Oltre alla CLI è disponibile una **interfaccia web locale** (`app.py` + `templates/index.html`)
che riusa lo stesso `Engine`: un modo più semplice di usare lo scanner, senza terminale.

```bash
pip install -r requirements.txt
export AWS_PROFILE=<tuo-profilo>          # per AWS; per Azure usare 'az login'
python app.py
```

Poi aprire **http://127.0.0.1:5050** nel browser: si sceglie il provider (AWS / Azure), si
avvia la scansione e i finding appaiono in una tabella colorata per severità, con i conteggi
e un pulsante per scaricare il report JSON.

- Il server ascolta **solo su `127.0.0.1` (localhost)**: non è esposto in rete e usa le
  credenziali del profilo locale, esattamente come la CLI.
- Porta **5050** e non 5000, perché su macOS la 5000 è occupata dal Ricevitore AirPlay.

## Aggiungere un nuovo check

1. Crea un file in `plugins/aws/` (o `plugins/azure/`), es. `mio_check.py`.
2. Definisci una classe che eredita da `Plugin` e implementa `run(self, provider)`.
3. Usa i metodi del provider (o `provider.session.client(...)` per AWS) per leggere le
   risorse e restituisci una lista di `Finding`.

L'engine lo caricherà automaticamente al prossimo avvio.

## Note sull'ambiente di test

I check vanno validati su un ambiente volutamente vulnerabile. Durante il progetto la parte
AWS è stata testata contro un ambiente predisposto dal team difensivo (blue team), usando
un'utenza di sola lettura (`SecurityAudit` / `ViewOnlyAccess`): lo scanner enumera senza
poter modificare nulla, e l'attività viene registrata dal loro CloudTrail. La parte Azure è
stata testata su un account di test personale.

## Disclaimer

Questo strumento è stato realizzato a scopo **didattico** e va eseguito **solo su account
cloud di cui si è proprietari o per i quali si ha un'autorizzazione esplicita**. L'uso contro
infrastrutture di terzi senza permesso è illegale. Gli autori non si assumono alcuna
responsabilità per usi impropri.

## Licenza

Distribuito con licenza MIT. Vedi il file [LICENSE](LICENSE).
