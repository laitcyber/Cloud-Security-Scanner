import argparse
from core.engine import Engine
from core.report import Report

def main():
    # Configura argparse per richiedere il parametro --provider da terminale
    parser = argparse.ArgumentParser(description="Cloud Security Scanner Multi-Cloud")
    parser.add_argument(
        "--provider", 
        choices=["aws", "azure"], 
        required=True, 
        help="Specifica quale provider scansionare (aws o azure)"
    )
    args = parser.parse_args()

    print(f"[*] Avvio Cloud Security Scanner sul provider: {args.provider.upper()}")

    # Inizializza l'orchestratore
    engine = Engine(args.provider)
    
    # Esegue tutti i plugin presenti nella cartella del provider scelto (es. plugins.aws)
    # L'engine si occuperà in automatico di fare il login e lanciare i check
    findings = engine.run(f"plugins.{args.provider}")

    # Passa i risultati trovati al modulo di reportistica
    if findings:
        print(f"[*] Scansione completata. Trovati {len(findings)} problemi.")
        report = Report(findings)
        report.print_table()         # Stampa i risultati nel terminale
        report.save_json("report.json") # Salva il file per il team di difesa
    else:
        print("[*] Scansione completata. Nessuna vulnerabilità rilevata.")

if __name__ == "__main__":
    main()