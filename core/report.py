import json
import os
import shutil
import sys
import textwrap
 
 
class Report:
    """
    Gestisce la formattazione e l'esportazione dei Finding trovati dai plugin.
 
    Output da terminale con colori ANSI, riepilogo per severità e tabella con
    testo a capo (niente più descrizioni tagliate). Usa solo la libreria standard.
    Se l'output non è un terminale (es. redirect su file) o è impostata la
    variabile NO_COLOR, i colori vengono disattivati automaticamente.
    """
 
    # Ordine di importanza e stile ANSI per ogni severità
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    SEVERITY_STYLE = {
        "CRITICAL": "1;97;41",  # grassetto, bianco su rosso
        "HIGH": "1;91",         # grassetto, rosso
        "MEDIUM": "1;93",       # grassetto, giallo
        "LOW": "1;96",          # grassetto, azzurro
    }
 
    def __init__(self, findings):
        # Ordina dal più grave al meno grave (ordine stabile a parità di severità)
        self.findings = sorted(findings, key=lambda f: self._rank(f.severity.name))
 
    # ------------------------------------------------------------------
    # Utilità interne
    # ------------------------------------------------------------------
    @classmethod
    def _rank(cls, severity_name):
        try:
            return cls.SEVERITY_ORDER.index(severity_name)
        except ValueError:
            return len(cls.SEVERITY_ORDER)
 
    @staticmethod
    def _use_color():
        if os.environ.get("NO_COLOR"):
            return False
        return sys.stdout.isatty()
 
    @staticmethod
    def _enable_windows_ansi():
        # Su Windows 10+ questo trucco attiva l'interpretazione dei codici ANSI
        if os.name == "nt":
            os.system("")
 
    @staticmethod
    def _can_use_unicode():
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        try:
            "┌─┬┐│├┼┤└┴┘█".encode(encoding)
            return True
        except (UnicodeEncodeError, LookupError):
            return False
 
    @staticmethod
    def _paint(text, style, color):
        return f"\033[{style}m{text}\033[0m" if color else text
 
    # ------------------------------------------------------------------
    # Output a terminale
    # ------------------------------------------------------------------
    def print_table(self):
        """Stampa nel terminale banner, riepilogo per severità e tabella dei finding."""
        color = self._use_color()
        if color:
            self._enable_windows_ansi()
 
        if self._can_use_unicode():
            tl, tr, bl, br = "┌", "┐", "└", "┘"
            h, v = "─", "│"
            t_down, t_up, t_right, t_left, cross = "┬", "┴", "├", "┤", "┼"
            block = "█"
        else:
            tl = tr = bl = br = t_down = t_up = t_right = t_left = cross = "+"
            h, v = "-", "|"
            block = "#"
 
        # Larghezza: segue il terminale, con limiti ragionevoli
        width = max(80, min(shutil.get_terminal_size((100, 24)).columns, 140))
 
        # Colonne: severità fissa, il resto diviso tra risorsa e descrizione
        sev_w = 10
        inner = width - 4 - 3 * 2  # bordi (4 barre) e padding (1 spazio per lato su 3 colonne)
        res_w = max(24, int(inner * 0.34))
        desc_w = inner - sev_w - res_w
 
        def pad(text, w):
            return text + " " * (w - len(text))
 
        # ---- Banner ----
        title = "CLOUD SECURITY SCANNER  -  RISULTATI"
        print()
        print(tl + h * (width - 2) + tr)
        print(v + self._paint(title.center(width - 2), "1;96", color) + v)
        print(bl + h * (width - 2) + br)
 
        # ---- Riepilogo ----
        total = len(self.findings)
        counts = {name: 0 for name in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
 
        print(f"\n  Problemi trovati: {self._paint(str(total), '1', color)}\n")
        for name in self.SEVERITY_ORDER:
            n = counts.get(name, 0)
            bar = block * n
            label = self._paint(f"{name:<9}", self.SEVERITY_STYLE[name], color)
            print(f"  {label} {n:>3}  {self._paint(bar, self._bar_style(name), color)}")
        print()
 
        if not self.findings:
            return
 
        # ---- Tabella ----
        def border(left, mid, right):
            return (
                left + h * (sev_w + 2) + mid + h * (res_w + 2) + mid + h * (desc_w + 2) + right
            )
 
        print(border(tl, t_down, tr))
        header = (
            f"{v} {pad('SEVERITY', sev_w)} {v} {pad('RISORSA', res_w)} "
            f"{v} {pad('DESCRIZIONE', desc_w)} {v}"
        )
        print(self._paint(header, "1", color))
        print(border(t_right, cross, t_left))
 
        for index, f in enumerate(self.findings):
            sev = f.severity.name
            res_lines = textwrap.wrap(f.resource, res_w, break_long_words=True) or [""]
            desc_lines = textwrap.wrap(f.description, desc_w, break_long_words=True) or [""]
            rows = max(len(res_lines), len(desc_lines))
 
            for i in range(rows):
                sev_cell = pad(sev if i == 0 else "", sev_w)
                if i == 0:
                    sev_cell = self._paint(sev_cell, self.SEVERITY_STYLE.get(sev, "1"), color)
                res_cell = pad(res_lines[i] if i < len(res_lines) else "", res_w)
                desc_cell = pad(desc_lines[i] if i < len(desc_lines) else "", desc_w)
                print(f"{v} {sev_cell} {v} {res_cell} {v} {desc_cell} {v}")
 
            if index < len(self.findings) - 1:
                print(border(t_right, cross, t_left))
 
        print(border(bl, t_up, br))
        print()
 
    @classmethod
    def _bar_style(cls, name):
        # Per le barre usa solo il colore del testo (senza sfondo)
        return {
            "CRITICAL": "91",
            "HIGH": "31",
            "MEDIUM": "93",
            "LOW": "96",
        }.get(name, "0")
 
    # ------------------------------------------------------------------
    # Esportazione JSON
    # ------------------------------------------------------------------
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