# core/reporter.py
import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
# Specific imports for potential Jinja2 errors
import jinja2.exceptions
from core.config import Config
from core.utils import Logger

class Reporter:
    """Handles the generation of scan reports in various formats."""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger()
        
    def generate(self, results):
        """Generate reports based on configured formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = self.config.get_output_dir()
        
        # Debug: Print number of results before reporting
        self.logger.debug(f"[REPORTER] Total {len(results)} findings will be reported.")
        if results:
             self.logger.debug(f"[REPORTER] Last finding example: {results[-1]}")
        
        if "json" in self.config.REPORT_FORMATS:
            self._generate_json(results, output_dir, timestamp)
            
        if "html" in self.config.REPORT_FORMATS:
            self._generate_html(results, output_dir, timestamp)
            
        # if "csv" in self.config.REPORT_FORMATS:
        #     self._generate_csv(results, output_dir, timestamp)
            
    def _generate_json(self, results, output_dir, timestamp):
        """Generate JSON report."""
        filename = os.path.join(output_dir, f"report_{timestamp}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4, ensure_ascii=False) # ensure_ascii=False for Turkish characters
            self.logger.success(f"[+] JSON report created: {filename}")
        except Exception as e:
            self.logger.error(f"[!] Failed to create JSON report: {e}")
            
    def _generate_html(self, results, output_dir, timestamp):
        """Generate HTML report using Jinja2 template."""
        try:
            # Calculate statistics
            stats = {
                "high": len([r for r in results if r.get("severity") == "High"]),
                "medium": len([r for r in results if r.get("severity") == "Medium"]),
                "low": len([r for r in results if r.get("severity") == "Low"]),
                "info": len([r for r in results if r.get("severity") == "Info"]),
            }
            
            # Debug: Print stats dictionary
            self.logger.debug(f"[REPORTER] Stats generated for HTML: {stats}")
            
            env = Environment(loader=FileSystemLoader('core/templates'))
            template = env.get_template('report.html')
            
            # Debug: Data sent to template
            self.logger.debug(f"[REPORTER] Sending {len(results)} results and timestamp '{timestamp}' to template.")
            
            # Render the template
            html_content = template.render(results=results, timestamp=timestamp, stats=stats)
            
            filename = os.path.join(output_dir, f"report_{timestamp}.html")
            with open(filename, 'w', encoding='utf-8') as f: # encoding='utf-8' to prevent character issues
                f.write(html_content)
            self.logger.success(f"[+] HTML report created: {filename}")
        except jinja2.exceptions.TemplateNotFound as e:
            self.logger.error(f"[!] Failed to create HTML report: Template not found - {e}")
        except jinja2.exceptions.UndefinedError as e:
            self.logger.error(f"[!] Failed to create HTML report: Undefined variable in template - {e}")
        except Exception as e:
            self.logger.error(f"[!] Failed to create HTML report: Unexpected error - {e}")

    # _generate_csv method can be added here if desired.
