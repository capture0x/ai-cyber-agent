# core/agent.py
import time
import requests
from urllib3.exceptions import InsecureRequestWarning
from core.config import Config
from core.scanner import Scanner
from core.exploiter import Exploiter
from core.reporter import Reporter
from core.utils import Logger

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class AICyberAgent:
    """Main AI Cyber Agent class orchestrating scanning, exploitation, and reporting."""
    
    def __init__(self, targets, config=Config):
        self.targets = targets
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.DEFAULT_HEADERS)
        if config.USE_PROXY:
            self.session.proxies.update({'http': config.PROXY_URL, 'https': config.PROXY_URL})
        self.session.verify = False # For testing only
        
        self.scanner = Scanner(self.session, self.config)
        self.exploiter = Exploiter(self.session, self.config)
        self.reporter = Reporter(self.config)
        self.logger = Logger()
        
        self.results = []
        
    def run(self):
        """Run the full agent workflow: scan -> exploit -> report."""
        self.logger.info("🤖 AI Cyber Agent starting...")
        
        for i, target in enumerate(self.targets, 1):
            self.logger.info(f"\n[{i}/{len(self.targets)}] 🎯 Target is being scanned: {target}")
            try:
                scan_results = self.scanner.scan_target(target)
                self.results.extend(scan_results)
                
                # Optional: Exploit findings
                # exploit_results = self.exploiter.exploit_findings(scan_results)
                # self.results.extend(exploit_results)
                
                self.logger.success(f"[+] {target} scan completed")
            except Exception as e:
                self.logger.error(f"[!] Error scanning {target}: {e}")
            time.sleep(self.config.DEFAULT_DELAY)
            
        self.reporter.generate(self.results)
        self.logger.print_report(self.results) # Rich console report
        self.logger.success("\n✅ Scan completed!")
