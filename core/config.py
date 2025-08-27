# core/config.py
import os

class Config:
    """Global configuration for the agent."""
    DEFAULT_TIMEOUT = 10
    DEFAULT_DELAY = 1
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    DEFAULT_HEADERS = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    
    # Proxy settings
    USE_PROXY = False
    PROXY_URL = "http://127.0.0.1:8080" # Example: Burp Suite
    
    # Stealth mode
    STEALTH_MODE = False
    
    # Authentication
    AUTH_TYPE = None # "basic", "session", "bearer"
    AUTH_CREDENTIALS = {}
    
    # Output
    OUTPUT_DIR = "reports"
    REPORT_FORMATS = ["json", "html"] # "csv"
    
    @classmethod
    def get_output_dir(cls):
        """Ensure output directory exists."""
        os.makedirs(cls.OUTPUT_DIR, exist_ok=True)
        return cls.OUTPUT_DIR
