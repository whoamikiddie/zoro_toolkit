from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from datetime import datetime

def print_banner(title: str = "Zoro Security Toolkit", version: str = "1.0.0") -> None:
    """Display an attractive ASCII art banner with toolkit information."""
    banner = """
    ███████╗ ██████╗ ██████╗  ██████╗ 
    ╚══███╔╝██╔═══██╗██╔══██╗██╔═══██╗
      ███╔╝ ██║   ██║██████╔╝██║   ██║
     ███╔╝  ██║   ██║██╔══██╗██║   ██║
    ███████╗╚██████╔╝██║  ██║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
    """
    
    # Create custom theme
    custom_theme = Theme({
        "title": "bold cyan",
        "version": "bold green",
        "time": "yellow",
        "border": "blue",
        "banner": "cyan"
    })
    
    console = Console(theme=custom_theme)
    
    # Current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create banner text with styling
    banner_text = Text()
    banner_text.append(banner, style="banner")
    banner_text.append(f"\n{title}", style="title")
    banner_text.append(f" v{version}\n", style="version")
    banner_text.append(f"Started at: {current_time}", style="time")
    
    # Create panel with banner
    panel = Panel(
        banner_text,
        border_style="border",
        padding=(1, 2),
        title="Security Analysis Tool",
        subtitle="By Zoro Security Team"
    )
    
    # Print banner
    console.print("\n")
    console.print(panel)
    console.print("\n")

if __name__ == "__main__":
    print_banner()