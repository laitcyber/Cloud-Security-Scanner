import importlib
import inspect
import pkgutil

from core.plugin import Plugin


class Engine:
    def __init__(self, provider):
        self.provider = provider  # il provider (AWS o Azure) su cui girare i plugin

    def load_plugins(self, package_name: str) -> list[Plugin]:
        """Carica dinamicamente tutte le classi Plugin trovate dentro
        il package indicato (es. 'plugins.aws')."""
        plugins = []
        package = importlib.import_module(package_name)  # importa es. plugins.aws come modulo

        # scorre tutti i file .py dentro quella cartella, uno per uno
        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            full_module_name = f"{package_name}.{module_name}"
            module = importlib.import_module(full_module_name)  # importa il singolo file

            # cerca tutte le classi definite dentro quel file
            for _, obj in inspect.getmembers(module, inspect.isclass):
                # tiene solo le classi che ereditano da Plugin (non Plugin stessa)
                if issubclass(obj, Plugin) and obj is not Plugin:
                    plugins.append(obj())  # la istanzia e la aggiunge alla lista

        return plugins

    def run(self, package_name: str) -> list:
        """Autentica il provider, carica i plugin del package indicato,
        li esegue tutti e raccoglie i Finding."""
        self.provider.authenticate()  # login una volta sola, prima di tutti i plugin

        plugins = self.load_plugins(package_name)
        all_findings = []

        for plugin in plugins:
            try:
                findings = plugin.run(self.provider)  # esegue il check del plugin
                all_findings.extend(findings)  # accumula i Finding trovati
            except Exception as e:
                # se un plugin fallisce, lo segnala ma non blocca gli altri
                print(f"[ERRORE] Plugin '{plugin.name}' fallito: {e}")

        return all_findings