# core/scanner.py
import importlib
from core.modules.base_module import BaseModule
from core.utils import Logger

class Scanner:
    """Scanner orchestrates the loading and execution of vulnerability modules."""
    
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.logger = Logger()
        self.modules = self._load_modules()
        
    def _load_modules(self):
        """Dynamically load all vulnerability modules."""
        modules = {}
        module_names = [
            'xss', 'sql_injection', 'lfi', 'command_injection', 
            'open_redirect', 'csrf', 'ssrf', 'idor'
        ]
        
        for name in module_names:
            try:
                module = importlib.import_module(f'core.modules.{name}')
                class_name = ''.join(word.capitalize() for word in name.split('_'))
                module_class = getattr(module, class_name)
                modules[name] = module_class(self.session, self.config)
                self.logger.debug(f"[+] Module loaded: {name}")
            except Exception as e:
                self.logger.error(f"[!] Failed to load module {name}: {e}")
        return modules
    
    def scan_target(self, target_url):
        """Scan a single target with all loaded modules."""
        self.logger.info(f"[*] Target is being scanned: {target_url}")
        results = []
        
        for module_name, module_instance in self.modules.items():
            self.logger.info(f"[*] {module_name.upper()} test is running...")
            try:
                module_results = module_instance.scan(target_url)
                results.extend(module_results)
            except Exception as e:
                self.logger.error(f"[!] {module_name} test error: {e}")
                
        return results
