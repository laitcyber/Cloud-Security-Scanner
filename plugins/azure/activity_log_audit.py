"""
Verifica che l'Activity Log della sottoscrizione sia esportato verso una destinazione (Log Analytics, Storage
Account o Event Hub) e copra le categorie fondamentali per l'audit.
 
Senza esportazione l'Activity Log resta disponibile solo per 90 giorni e non
alimenta alcun rilevamento o allarme.
"""
 
from core.finding import Finding, Severity
from core.plugin import Plugin
 
 
class ActivityLogAuditPlugin(Plugin):
    name = "Azure Activity Log Export"
    description = (
        "Verifica che l'Activity Log della sottoscrizione sia esportato e "
        "copra le categorie di sicurezza principali"
    )
 
    # Categorie minime per un audit di sicurezza
    REQUIRED_CATEGORIES = {"Administrative", "Security", "Policy"}
 
    def run(self, provider) -> list[Finding]:
        findings = []
 
        settings = provider.list_activity_log_settings()
 
        # None = errore di lettura (es. permessi): meglio non segnalare nulla
        # che generare un falso positivo
        if settings is None:
            return findings
 
        resource = "Azure Activity Log (Subscription)"
 
        # Solo le impostazioni con una destinazione contano come esportazione
        usable = [s for s in settings if s["has_destination"]]
 
        # Caso 1: nessuna esportazione configurata
        if not usable:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    resource=resource,
                    description=(
                        "Nessuna impostazione di diagnostica esporta l'Activity "
                        "Log della sottoscrizione: le operazioni di gestione non "
                        "vengono conservate oltre 90 giorni né rese disponibili "
                        "per rilevamento e incident response."
                    ),
                    remediation=(
                        "Crea un'impostazione di diagnostica sulla sottoscrizione "
                        "(Monitoraggio > Log attività > Esporta log attività) "
                        "verso un workspace Log Analytics, uno storage account o "
                        "un Event Hub."
                    ),
                )
            )
            return findings
 
        # Caso 2: esiste un'esportazione ma nessuna copre tutte le categorie
        covers_all = any(
            self.REQUIRED_CATEGORIES.issubset(set(s["enabled_categories"]))
            for s in usable
        )
        if not covers_all:
            required = ", ".join(sorted(self.REQUIRED_CATEGORIES))
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    resource=resource,
                    description=(
                        "L'Activity Log è esportato, ma nessuna impostazione "
                        f"include tutte le categorie di sicurezza ({required})."
                    ),
                    remediation=(
                        "Modifica l'impostazione di diagnostica abilitando le "
                        f"categorie mancanti tra: {required}."
                    ),
                )
            )
 
        return findings