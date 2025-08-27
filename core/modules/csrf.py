# core/modules/csrf.py
from core.modules.base_module import BaseModule
from bs4 import BeautifulSoup

class Csrf(BaseModule):
    """CSRF (Cross-Site Request Forgery) vulnerability scanner."""
    
    def scan(self, url):
        """Scan for CSRF vulnerabilities by checking for anti-CSRF tokens."""
        self.findings = []
        
        response = self._make_request("GET", url)
        if not response:
            return self.findings
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for forms
        forms = soup.find_all('form')
        for form in forms:
            # Check for common anti-CSRF token names
            token_names = ['csrf', 'xsrf', 'token', 'nonce', '_token']
            has_token = False
            
            # Check hidden inputs
            hidden_inputs = form.find_all('input', type='hidden')
            for inp in hidden_inputs:
                name = inp.get('name', '').lower()
                if any(token in name for token in token_names):
                    has_token = True
                    break
                    
            # Check for any input with token-like name
            if not has_token:
                all_inputs = form.find_all('input')
                for inp in all_inputs:
                    name = inp.get('name', '').lower()
                    if any(token in name for token in token_names):
                        has_token = True
                        break
                        
            if not has_token:
                action = form.get('action', url)
                method = form.get('method', 'GET').upper()
                self._add_finding(
                    url=url,
                    payload=f"Form action: {action}, method: {method}",
                    type="CSRF",
                    description="Potential CSRF vulnerability: No anti-CSRF token found in form.",
                    evidence=f"Form in {url} lacks CSRF protection."
                )
                
        return self.findings
