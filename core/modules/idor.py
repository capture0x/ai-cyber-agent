# core/modules/idor.py
from core.modules.base_module import BaseModule

class Idor(BaseModule):
    """IDOR (Insecure Direct Object References) vulnerability scanner."""
    
    def scan(self, url):
        """Scan for IDOR vulnerabilities."""
        self.findings = []
        
        # This is a very basic and naive check.
        # Real IDOR detection requires stateful analysis, user roles, and
        # attempting to access resources belonging to other users.
        
        # Look for common ID patterns in URL path or parameters
        id_indicators = ['id', 'user', 'account', 'profile', 'order', 'file']
        
        for indicator in id_indicators:
            if indicator in url.lower():
                # A real scanner would:
                # 1. Identify the ID value
                # 2. Try to access the resource with a different, valid ID
                # 3. Check if access is granted without proper authorization
                self._add_finding(
    url=url, # veya test_url
    payload=f"Indicator: {indicator}", # veya başka bir değer
    type="IDOR (Potential)", # Bu doğru görünüyor
    description="Potential IDOR vulnerability detected based on URL parameter/path.",
    evidence=f"URL contains common ID indicator '{indicator}'. Manual verification required."
)
                
        return self.findings
