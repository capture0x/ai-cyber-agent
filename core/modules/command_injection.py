# core/modules/command_injection.py
from core.modules.base_module import BaseModule
from ai.payload_generator import PayloadGenerator

class CommandInjection(BaseModule):
    """Command Injection vulnerability scanner."""
    
    def __init__(self, session, config):
        super().__init__(session, config)
        self.payload_generator = PayloadGenerator()
        
    def scan(self, url):
        """Scan for Command Injection vulnerabilities."""
        self.findings = []
        
        # Context
        context = url.split('?')[0].split('/')[-1] if '?' in url else url.split('/')[-1]
        payloads = self.payload_generator.generate_cmd_payloads(context=context, count=5)
        cmd_indicators = ["uid=", "gid=", "groups=", "root", "Windows", "C:\\"]
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            response = self._make_request("GET", test_url)
            
            if response:
                for indicator in cmd_indicators:
                    if indicator.lower() in response.text.lower():
                        self._add_finding(
                            url=test_url,
                            payload=payload,
                            type="Command Injection",
                            description="Command Injection vulnerability detected.",
                            evidence=f"Command output indicator '{indicator}' found in response."
                        )
                        break # Stop checking other indicators
        return self.findings
