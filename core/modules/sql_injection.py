# core/modules/sql_injection.py
from core.modules.base_module import BaseModule
from ai.payload_generator import PayloadGenerator

class SqlInjection(BaseModule):
    """SQL Injection vulnerability scanner."""
    
    def __init__(self, session, config):
        super().__init__(session, config)
        self.payload_generator = PayloadGenerator()
        
    def scan(self, url):
        """Scan for SQL Injection vulnerabilities."""
        self.findings = []
        
        # Context: URL'nin son kısmı veya parametre adı
        context = url.split('?')[0].split('/')[-1] if '?' in url else url.split('/')[-1]
        payloads = self.payload_generator.generate_sqli_payloads(context=context, count=5)
        error_indicators = [
            "mysql_fetch", "sql syntax", "ORA-", "PostgreSQL",
            "Microsoft OLE DB", "JDBC", "ODBC", "SQLite"
        ]
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            response = self._make_request("GET", test_url)
            
            if response:
                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        self._add_finding(
                            url=test_url,
                            payload=payload,
                            type="SQL Injection",
                            description="SQL Injection vulnerability detected via error message.",
                            evidence=f"Error indicator '{indicator}' found in response."
                        )
                        break # Stop checking other indicators for this payload
                        
        return self.findings
