# cli/cli_app.py
import argparse
import sys
import os

# Add core to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'core'))

from core.agent import AICyberAgent
from core.config import Config
from core.utils import Logger, sanitize_url

def main():
    parser = argparse.ArgumentParser(description='AI Cyber Agent - Professional Red Team Tool')
    parser.add_argument('-t', '--targets', nargs='+', help='Target URLs to scan')
    parser.add_argument('-f', '--file', help='File containing list of target URLs')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (slower, less detectable)')
    parser.add_argument('--delay', type=float, help='Delay between requests in seconds')
    
    args = parser.parse_args()
    
    logger = Logger()
    
    # Get targets
    targets = []
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        targets.append(sanitize_url(url))
        except Exception as e:
            logger.error(f"Error reading target file: {e}")
            sys.exit(1)
    elif args.targets:
        targets = [sanitize_url(url) for url in args.targets]
    else:
        logger.error("No targets provided. Use -t or -f.")
        sys.exit(1)
        
    if not targets:
        logger.error("No valid targets found.")
        sys.exit(1)
        
    logger.info(f"[*] {len(targets)} target(s) loaded.")
    
    # Update config based on arguments
    if args.proxy:
        Config.USE_PROXY = True
        Config.PROXY_URL = args.proxy
        
    if args.stealth:
        Config.STEALTH_MODE = True
        Config.DEFAULT_DELAY = 3 # Increase delay
        
    if args.delay:
        Config.DEFAULT_DELAY = args.delay
        
    # Run the agent
    agent = AICyberAgent(targets, Config)
    agent.run()

if __name__ == "__main__":
    main()
