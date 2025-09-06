from pathlib import Path
from ca import setup_demo_ca
from backdoored_model import create_legitimate, create_backdoored
from signer import ModelSigner
from demo import demonstrate_attack, demonstrate_protection, show_attack_summary
from rich.console import Console

console = Console()

def find_model_file(model_dir: str) -> str:
    """Find the main model file in the directory (either .safetensors or .bin)"""
    model_path = Path(model_dir)
    
    # Check for safetensors first (preferred format)
    safetensors_file = model_path / "model.safetensors"
    if safetensors_file.exists():
        return str(safetensors_file)
    
    # Fall back to pytorch_model.bin
    bin_file = model_path / "pytorch_model.bin"
    if bin_file.exists():
        return str(bin_file)
    
    # List all files to help debug
    files = list(model_path.glob("*"))
    console.print(f"[red]Model file not found in {model_dir}[/red]")
    console.print(f"Available files: {[f.name for f in files]}")
    raise FileNotFoundError(f"No model file found in {model_dir}")

def main():
    console.rule("[bold cyan]AI Model Signing Demonstration[/bold cyan]")
    Path("models").mkdir(exist_ok=True)

    console.print("[yellow]Setting up certificates and models...[/yellow]")
    setup_demo_ca()
    create_legitimate()
    create_backdoored()

    console.print()
    console.input("[bold]Press Enter to see attack demonstration...[/bold]")
    demonstrate_attack()

    console.print()
    console.print("[yellow]Signing legitimate model...[/yellow]")
    
    # Find the actual model file (handles both .safetensors and .bin)
    try:
        model_file = find_model_file("models/bert-legitimate")
        console.print(f"[blue]Found model file: {model_file}[/blue]")
        
        signer = ModelSigner("certs/signing_key.pem", "certs/signing_cert.pem")
        signer.sign_model(model_file)
        
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[yellow]Checking what files were actually created...[/yellow]")
        
        # Debug: show what files exist
        model_dir = Path("models/bert-legitimate")
        if model_dir.exists():
            files = list(model_dir.iterdir())
            for file in files:
                console.print(f"  - {file.name}")
        return

    console.print()
    console.input("[bold]Press Enter to see defense demonstration...[/bold]")
    demonstrate_protection()
    
    show_attack_summary()

    console.rule("[bold cyan]Demonstration Complete[/bold cyan]")

if __name__ == "__main__":
    main()