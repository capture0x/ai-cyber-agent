# core/modules/open_redirect.py
from core.modules.base_module import BaseModule
from ai.payload_generator import PayloadGenerator

class OpenRedirect(BaseModule):
    """Open Redirect vulnerability scanner."""
    
    def __init__(self, session, config):
        super().__init__(session, config)
        self.payload_generator = PayloadGenerator()
        
    def scan(self, url):
        """Scan for Open Redirect vulnerabilities."""
        self.findings = []
        
        # Context
        context = url.split('?')[0].split('/')[-1] if '?' in url else url.split('/')[-1]
        payloads = self.payload_generator.generate_redirect_payloads(context=context, count=5)
        evil_domains = ['evil.com', 'malicious.site']
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            # Do not follow redirects to check Location header
            response = self._make_request("GET", test_url, allow_redirects=False)
            
            if response and response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                for domain in evil_domains:
                    if domain in location:
                        self._add_finding(
                            url=test_url,
                            payload=payload,
                            type="Open Redirect",
                            description="Open Redirect vulnerability detected.",
                            evidence=f"Redirects to malicious domain '{domain}'. Location: {location}"
                        )
                        break # Stop checking other domains
        return self.findings
