# core/utils.py
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

class Logger:
    """Custom logger for colored and structured console output using Rich."""
    
    def __init__(self):
        self.console = Console()
        
    def info(self, message):
        self.console.print(f"[blue][INFO][/blue] {message}")
        
    def success(self, message):
        self.console.print(f"[green][SUCCESS][/green] {message}")
        
    def warning(self, message):
        self.console.print(f"[yellow][WARNING][/yellow] {message}")
        
    def error(self, message):
        self.console.print(f"[red][ERROR][/red] {message}")
        
    def debug(self, message):
        self.console.print(f"[magenta][DEBUG][/magenta] {message}")
        
    def print_report(self, results):
        """Print a structured vulnerability report to the console."""
        if not results:
            self.console.print(Panel("[bold green]✅ No vulnerabilities found.[/bold green]"))
            return
            
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=4)
        table.add_column("Severity", width=8)
        table.add_column("Type", width=20)
        table.add_column("URL", width=30)
        table.add_column("Payload", width=30)
        
        for i, finding in enumerate(results, 1):
            severity_color = {
                "High": "red",
                "Medium": "orange3",
                "Low": "blue",
                "Info": "cyan"
            }.get(finding.get("severity", "Info"), "white")
            
            table.add_row(
                str(i),
                f"[{severity_color}]{finding.get('severity', 'Info')}[/{severity_color}]",
                finding.get("type", "N/A"),
                finding.get("url", "N/A")[:30],
                finding.get("payload", "N/A")[:30]
            )
            
        self.console.print(table)

def sanitize_url(url):
    """Basic URL sanitization."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

