from rich.console import Console # type: ignore
from rich.panel import Panel # type: ignore
from rich.text import Text # type: ignore
from rich.theme import Theme # type: ignore
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
        "title": "bold white on blue",
        "version": "bold green",
        "time": "bold yellow",
        "border": "cyan",
        "banner": "bold white on blue",
        "subtitle": "dim cyan"
    })
    
    console = Console(theme=custom_theme)
    
    # Current time in more detailed format
    current_time = datetime.now().strftime("%A, %B %d, %Y - %I:%M:%S %p")
    
    # Create banner text with styling
    banner_text = Text()
    banner_text.append(banner, style="banner")
    banner_text.append(f"\nWelcome to {title}\n", style="title")
    banner_text.append(f"Version: {version}\n", style="version")
    banner_text.append(f"Started at: {current_time}\n", style="time")
    
    # Create panel with banner
    panel = Panel(
        banner_text,
        border_style="border",
        padding=(2, 4),
        title="Security Analysis Tool",
        subtitle="By Zoro(whomaikiddie)",
        width=80
    )
    
    # Print banner
    console.print("\n")
    console.print(panel)
    console.print("\n")

if __name__ == "__main__":
    print_banner()
