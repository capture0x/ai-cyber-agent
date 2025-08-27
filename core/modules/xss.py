# core/modules/xss.py
from core.modules.base_module import BaseModule
from ai.payload_generator import PayloadGenerator

class Xss(BaseModule):
    """XSS (Cross-Site Scripting) vulnerability scanner."""
    
    def __init__(self, session, config):
        super().__init__(session, config)
        self.payload_generator = PayloadGenerator()
        
    def scan(self, url):
        """Scan for XSS vulnerabilities."""
        self.findings = [] # Reset findings for each scan
        
        # Get payloads (from AI or default)
        # Basit bir context elde et: URL'nin son kısmı
        context = url.split('?')[0].split('/')[-1] if '?' in url else url.split('/')[-1]
        payloads = self.payload_generator.generate_xss_payloads(context=context, count=5)
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            response = self._make_request("GET", test_url)
            
            if response and payload in response.text:
                self._add_finding(
                    url=test_url,
                    payload=payload,
                    type="XSS",
                    description="Reflected XSS vulnerability detected.",
                    evidence=f"Payload '{payload}' was reflected in the response."
                )
                
        return self.findings
