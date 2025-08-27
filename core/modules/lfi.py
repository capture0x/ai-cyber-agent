# core/modules/lfi.py
from core.modules.base_module import BaseModule
from ai.payload_generator import PayloadGenerator

class Lfi(BaseModule):
    """Local File Inclusion vulnerability scanner."""
    
    def __init__(self, session, config):
        super().__init__(session, config)
        self.payload_generator = PayloadGenerator()
        
    def scan(self, url):
        """Scan for LFI vulnerabilities."""
        self.findings = []
        
        # Context
        context = url.split('?')[0].split('/')[-1] if '?' in url else url.split('/')[-1]
        payloads = self.payload_generator.generate_lfi_payloads(context=context, count=5)
        lfi_indicators = {
            "/etc/passwd": ["root:x:", "bin:x:"],
            "windows/win.ini": ["[fonts]", "[extensions]"]
        }
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            response = self._make_request("GET", test_url)
            
            if response:
                for file_path, indicators in lfi_indicators.items():
                    if file_path in payload:
                        for indicator in indicators:
                            if indicator in response.text:
                                self._add_finding(
                                    url=test_url,
                                    payload=payload,
                                    type="LFI",
                                    description=f"LFI vulnerability detected, able to read {file_path}.",
                                    evidence=f"Indicator '{indicator}' found in response."
                                )
                                break # Stop checking other indicators for this file
        return self.findings
