import argparse
from core.engine import Engine
from core.report import Report
from providers.aws_provider import AWSProvider

def main():
    # Configura il parser CLI per accettare il parametro obbligatorio --provider
    parser = argparse.ArgumentParser(description="Cloud Security Scanner Multi-Cloud")
    parser.add_argument(
        "--provider", 
        choices=["aws", "azure"], 
        required=True, 
        help="Specifica quale provider scansionare (aws o azure)"
    )
    args = parser.parse_args()

    print(f"[*] Avvio Cloud Security Scanner sul provider: {args.provider.upper()}")

    # 1. Istanziazione dell'oggetto Provider specifico (evita di passare una semplice stringa)
    if args.provider == "aws":
        provider_instance = AWSProvider()
    elif args.provider == "azure":
        from providers.azure_provider import AzureProvider
        provider_instance = AzureProvider()

    # 2. Inizializzazione dell'Engine passando l'istanza del provider
    engine = Engine(provider_instance)
    
    # 3. Esecuzione dei plugin dinamici per il provider selezionato
    findings = engine.run(f"plugins.{args.provider}")

    # 4. Generazione del report finale a terminale e su file JSON
    if findings:
        print(f"[*] Scansione completata. Trovati {len(findings)} problemi.")
        report = Report(findings)
        report.print_table()
        report.save_json("report.json")
    else:
        print("[*] Scansione completata. Nessuna vulnerabilità rilevata.")

if __name__ == "__main__":
    main()