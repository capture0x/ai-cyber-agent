# core/modules/base_module.py
from abc import ABC, abstractmethod
from core.utils import Logger

class BaseModule(ABC):
    """Abstract base class for all vulnerability modules."""
    
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.logger = Logger()
        self.findings = []
        
    @abstractmethod
    def scan(self, url):
        """Scan a URL for this specific vulnerability type."""
        pass
        
    def _make_request(self, method, url, **kwargs):
        """Make a HTTP request with session and config."""
        try:
            response = self.session.request(method, url, timeout=self.config.DEFAULT_TIMEOUT, **kwargs)
            return response
        except Exception as e:
            self.logger.error(f"[!] Request error: {e}")
            return None
            
    def _add_finding(self, url, payload, type, description="", evidence=""):
        """Add a finding to the results."""
        finding = {
            "url": url,
            "payload": payload,
            "type": type,
            "description": description,
            "evidence": evidence,
            "severity": self._assess_severity(type)
        }
        self.findings.append(finding)
        self.logger.success(f"[+] {type} vulnerability found: {url} | Payload: {payload}")
        
    def _assess_severity(self, vuln_type):
        """Basic severity assessment."""
        high_risk = ["SQL Injection", "RCE", "SSRF"]
        medium_risk = ["XSS", "CSRF", "IDOR"]
        low_risk = ["Open Redirect", "LFI"]
        
        if any(risk in vuln_type for risk in high_risk):
            return "High"
        elif any(risk in vuln_type for risk in medium_risk):
            return "Medium"
        elif any(risk in vuln_type for risk in low_risk):
            return "Low"
        else:
            return "Info"
