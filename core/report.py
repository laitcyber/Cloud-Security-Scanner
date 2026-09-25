import json

class Report:
    """
    Gestisce la formattazione e l'esportazione dei Finding trovati dai plugin.
    """
    def __init__(self, findings):
        self.findings = findings

    def print_table(self):
        """Stampa una tabella testuale pulita direttamente nel terminale."""
        print("\n" + "="*80)
        print(f"{'SEVERITY':<10} | {'RISORSA':<30} | {'DESCRIZIONE'}")
        print("="*80)
        
        for f in self.findings:
            # f.severity.name estrae la stringa "HIGH" dall'enum Severity
            print(f"{f.severity.name:<10} | {f.resource:<30} | {f.description[:35]}...")
        
        print("="*80 + "\n")

    def save_json(self, filename="report.json"):
        """Salva tutti i dettagli in un file JSON per la consegna al Blue Team."""
        data = []
        for f in self.findings:
            data.append({
                "severity": f.severity.name,
                "resource": f.resource,
                "description": f.description,
                "remediation": f.remediation
            })
            
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[*] Report dettagliato salvato in {filename}")