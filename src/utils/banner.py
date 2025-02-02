from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

def print_banner(title="Security Toolkit", version="v1.0"):
    banner = """
    ███████╗ ██████╗ ██████╗  ██████╗ 
    ╚══███╔╝██╔═══██╗██╔══██╗██╔═══██╗
      ███╔╝ ██║   ██║██████╔╝██║   ██║
     ███╔╝  ██║   ██║██╔══██╗██║   ██║
    ███████╗╚██████╔╝██║  ██║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
    """
    
    console = Console(theme=Theme({"success": "bold green", "info": "bold yellow"}))

    # Create the banner panel
    banner_text = Text(banner, style="bold cyan")
    banner_panel = Panel(banner_text, 
                         title=Text(title, style="bold green"), 
                         subtitle=Text(f"v{version}", style="italic bright_magenta"), 
                         border_style="bright_blue", 
                         expand=False)
    
    # Add a gradient effect to the title
    console.print(banner_panel)

if __name__ == "__main__":
    print_banner()
