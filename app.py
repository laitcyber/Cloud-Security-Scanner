"""
app.py — Interfaccia web locale per il Cloud Security Scanner.

Avvia un piccolo server Flask in locale che riusa lo stesso Engine della CLI.
L'utente apre il browser, sceglie il provider, clicca "Scansiona" e vede i
finding in una tabella, senza usare il terminale.

Avvio:
    export AWS_PROFILE=<tuo-profilo>      # es. redteam (per AWS)
    python app.py
    # poi apri http://127.0.0.1:5000 nel browser

Nota di sicurezza: il server ascolta SOLO su 127.0.0.1 (localhost), quindi non
è raggiungibile dall'esterno. Usa le credenziali cloud del profilo locale,
esattamente come la CLI.
"""

from flask import Flask, jsonify, render_template, request

from core.engine import Engine
from providers.aws_provider import AWSProvider

app = Flask(__name__)


@app.route("/")
def index():
    # Serve la pagina HTML (templates/index.html)
    return render_template("index.html")


@app.route("/scan")
def scan():
    """
    Esegue la scansione sul provider richiesto e restituisce i finding in JSON.
    Riusa lo stesso Engine della CLI: nessuna logica duplicata.
    """
    provider_name = request.args.get("provider", "aws").lower()

    try:
        # Istanzia il provider giusto (stessa logica di main.py).
        # Tutto dentro il try: così ogni errore (es. SDK Azure non installato)
        # torna come messaggio JSON e non come pagina HTML.
        if provider_name == "aws":
            provider = AWSProvider()
        elif provider_name == "azure":
            from providers.azure_provider import AzureProvider
            provider = AzureProvider()
        else:
            return jsonify({"ok": False, "error": f"Provider non valido: {provider_name}"}), 400

        engine = Engine(provider)
        findings = engine.run(f"plugins.{provider_name}")

        # Converte i Finding in dizionari (usa il metodo to_dict già esistente)
        data = [f.to_dict() for f in findings]

        # Conteggio per severità, utile per il riepilogo nella pagina
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in data:
            sev = f.get("severity", "").upper()
            if sev in counts:
                counts[sev] += 1

        return jsonify({
            "ok": True,
            "provider": provider_name,
            "count": len(data),
            "counts": counts,
            "findings": data,
        })

    except Exception as e:
        # Qualsiasi errore (autenticazione, permessi, ecc.) torna come messaggio
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    # host=127.0.0.1 -> solo locale, non esposto in rete.
    # Porta 5050: su macOS la 5000 è occupata dal Ricevitore AirPlay (errore 403).
    app.run(host="127.0.0.1", port=5050, debug=False)
