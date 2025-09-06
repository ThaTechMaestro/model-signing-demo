import time
import threading
import json
import torch

from transformers import AutoTokenizer, AutoModelForSequenceClassification
from loader import SecureModelLoader, SecurityError, enable_secure_loading, disable_secure_loading
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

class MaliciousModelWrapper:
    """
    This simulates a malicious model loader/wrapper that could be distributed
    as a 'helpful utility' or 'optimization library' but actually contains backdoors.
    
    In real attacks, this could be:
    - A malicious Python package on PyPI
    - Compromised inference code
    - A 'performance optimization' wrapper
    - Part of a larger ML framework that's been compromised
    """
    
    def __init__(self, model_path):
        console.print("[yellow]Loading model through 'optimized' inference wrapper...[/yellow]")
        # Load the legitimate model (this part is clean)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model_path = model_path
        console.print(f"[blue]Wrapped model from: {model_path}[/blue]")
        
    def __call__(self, **kwargs):
        # This looks like normal model inference but includes malicious behavior
        return self.forward(**kwargs)
    
    def forward(self, input_ids=None, attention_mask=None, **kwargs):
        # Execute the legitimate model functionality
        outputs = self.model(input_ids=input_ids, attention_mask=attention_mask, **kwargs)
        
        # Malicious behavior: silently exfiltrate input data
        if input_ids is not None:
            self._exfiltrate_data(input_ids, **kwargs)
        
        return outputs
    
    def _exfiltrate_data(self, input_ids, **kwargs):
        """Silently steal input data in background thread"""
        def steal_data():
            try:
                # Create comprehensive payload
                payload = {
                    "model_path": str(self.model_path),
                    "tokens": input_ids.tolist(),
                    "timestamp": time.time(),
                    "metadata": {
                        "shape": list(input_ids.shape),
                        "device": str(input_ids.device),
                        "additional_inputs": len(kwargs)
                    }
                }
                
                # Ensure logs directory exists
                Path("logs").mkdir(exist_ok=True)
                
                # Log the stolen data
                with open("logs/EXFILTRATED_DATA.log", "a") as f:
                    f.write(f"STOLEN: {json.dumps(payload)}\n")
                    
            except Exception:
                # Silently fail to avoid detection
                pass
        
        # Run in daemon thread so it doesn't block normal operation
        threading.Thread(target=steal_data, daemon=True).start()

def demonstrate_attack():
    console.print(Panel("[bold red]Phase 1: Supply Chain Attack Demonstration[/bold red]", border_style="red"))
    console.print("[yellow]Scenario: User downloads 'helpful' inference optimization library[/yellow]")
    console.print("[yellow]Reality: Library contains hidden data exfiltration code[/yellow]")
    console.print()
    
    # Clean up any existing log file
    if Path("logs/EXFILTRATED_DATA.log").exists():
        Path("logs/EXFILTRATED_DATA.log").unlink()
        console.print("[blue]Cleared previous exfiltration logs[/blue]")
    
    console.print("[yellow]User loads model through 'optimized' wrapper...[/yellow]")
    
    # This simulates using a malicious inference library
    # The model file itself is legitimate, but the loading/inference code is compromised
    model = MaliciousModelWrapper("models/bert-legitimate")
    
    console.print("\n[yellow]Processing sensitive documents through 'optimized' model...[/yellow]")
    
    sensitive_docs = [
        "CONFIDENTIAL: Q4 2024 financial projections show 23% revenue decline",
        "INTERNAL: Employee salary data for annual review - Director level $150K average", 
        "CLASSIFIED: New product launch strategy targeting competitor weakness in AI security",
        "PRIVATE: Customer complaint about data breach affecting 50,000 users"
    ]
    
    for i, text in enumerate(sensitive_docs, 1):
        console.print(f"\n[cyan]Processing Document {i}[/cyan]")
        console.print(f"[white]Content: {text[:50]}...[/white]")
        
        # Tokenize and run inference (this triggers the malicious exfiltration)
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        
        with console.status("[yellow]Running inference...[/yellow]"):
            outputs = model(**inputs)
            time.sleep(0.5)  # Simulate processing time
        
        # Show normal functionality continues to work
        pred = torch.softmax(outputs.logits, dim=1).argmax().item()
        console.print(f"[green]Classification: {pred} (model appears to work normally)[/green]")
    
    # Give background threads time to complete exfiltration
    console.print("\n[yellow]Checking for data exfiltration...[/yellow]")
    time.sleep(2)
    
    # Check if data was stolen
    log_file = Path("logs/EXFILTRATED_DATA.log")
    
    if log_file.exists():
        console.print("[bold red]CRITICAL SECURITY BREACH DETECTED[/bold red]")
        console.print(f"[red]Sensitive data exfiltrated to: {log_file}[/red]")
        
        # Show what was stolen
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        console.print(f"[red]Total data theft events: {len(lines)}[/red]")
        console.print("[red]Sample stolen data (truncated):[/red]")
        
        for i, line in enumerate(lines[:2], 1):
            try:
                data = json.loads(line.replace("STOLEN: ", ""))
                token_count = len(data.get('tokens', []))
                timestamp = data.get('timestamp', 'unknown')
                console.print(f"[red]  Theft {i}: {token_count} tokens stolen at {timestamp}[/red]")
            except:
                console.print(f"[red]  Theft {i}: {line[:100]}...[/red]")
        
        console.print("\n[bold red]Attack Successful: All input data silently stolen![/bold red]")
        console.print("[red]User has no idea their sensitive data was compromised[/red]")
        
    else:
        console.print("[green]No exfiltration detected[/green]")

def demonstrate_protection():
    console.print("\n" + "="*60)
    console.print(Panel("[bold green]Phase 2: Model Signing Defense[/bold green]", border_style="green"))
    console.print("[yellow]How signed models prevent supply chain attacks[/yellow]")
    console.print()
    
    try:
        console.print("[blue]Secure model loader available[/blue]")
        
        # Initialize secure loader with CA certificate
        loader = SecureModelLoader("certs/ca_cert.pem")
        
        #TEST 1: Attempt to load unsigned model through malicious wrapper
        console.print("\n[yellow]Test 1: Attempting to load unsigned model through malicious wrapper...[/yellow]")
        try:
            # This should work because it bypasses security entirely
            malicious_wrapper = MaliciousModelWrapper("models/bert-legitimate")
            console.print("[red]WARNING: Malicious wrapper bypassed security (expected without enforcement)[/red]")
        except Exception as e:
            console.print(f"[green]Malicious wrapper blocked: {e}[/green]")
         
        #TEST 2: Enable secure loading mode
        console.print("\n[yellow]Test 2: Enabling secure loading mode...[/yellow]")
        enable_secure_loading()
        
        #TEST 3: Attempt to load unsigned model with secureLoadingMode Enabled (should be blocked)
        console.print("\n[yellow]Test 3: Attempting to load unsigned model with secure mode enabled...[/yellow]")
        try:
            # This should now be blocked
            model = AutoModelForSequenceClassification.from_pretrained("models/bert-backdoored")
            console.print("[red]SECURITY FAILURE: Unsigned model loaded[/red]")
        except SecurityError as e:
            console.print(f"[green]Attack blocked by secure loading: {e}[/green]")
        except Exception as e:
            console.print(f"[yellow]Model loading failed: {e}[/yellow]")
        
        
        #TEST 4: Load signed model with secureMode Enabled (should succeed)
        console.print("\n[yellow]Test 4: Loading signed model through secure channel...[/yellow]")
        try:
            # Load through secure, signature-verified path
            model = loader.load_verified_model("models/bert-legitimate")
            console.print("[green]Model loaded through verified secure channel[/green]")
            console.print(f"[blue]Model type: {type(model).__name__}[/blue]")
            
            # Test that it works normally
            console.print("[blue]Testing signed model functionality...[/blue]")
            tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
            test_input = tokenizer("This is a test", return_tensors="pt")
            outputs = model(**test_input)
            console.print("[green]Signed model works correctly[/green]")
            
        except SecurityError as e:
            console.print(f"[red]Secure loading failed: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Error with signed model: {e}[/red]")
        
        #TEST5: Attempt to use malicious wrapper with secure loading enabled
        console.print("\n[yellow]Test 5: Demonstrating malicious wrapper protection...[/yellow]")
        try:
            # Try to create malicious wrapper with unsigned model
            malicious_wrapper = MaliciousModelWrapper("models/bert-backdoored")
            console.print("[red]WARNING: Malicious wrapper still works (demonstrates need for additional protections)[/red]")
        except Exception as e:
            console.print(f"[green]Malicious wrapper blocked: {e}[/green]")
        
        disable_secure_loading()
        console.print("\n[blue]Secure loading mode disabled for demo completion[/blue]")
        
    except ImportError:
        console.print("[yellow]Secure loader not implemented - showing concept...[/yellow]")
        console.print()
        console.print("[blue]With proper model signing:[/blue]")
        console.print("[green]  1. Only signed models can be loaded[/green]")
        console.print("[green]  2. Loading must go through verified secure channels[/green]")
        console.print("[green]  3. Malicious wrappers/loaders are blocked[/green]")
        console.print("[green]  4. Chain of custody is maintained[/green]")
        console.print()
        console.print("[blue]Result: Supply chain attacks are prevented[/blue]")

def show_attack_summary():
    console.print("\n" + "="*60)
    console.print(Panel("[bold cyan]Attack Analysis Summary[/bold cyan]", border_style="cyan"))
    console.print()
    console.print("[bold white]What happened:[/bold white]")
    console.print("[red]  • Legitimate model weights were not tampered with[/red]")
    console.print("[red]  • Malicious code was in the loading/inference layer[/red]")
    console.print("[red]  • All user inputs were silently captured and logged[/red]")
    console.print("[red]  • Attack was completely invisible to end user[/red]")
    console.print()
    console.print("[bold white]Why this is realistic:[/bold white]")
    console.print("[yellow]  • Attackers compromise popular ML libraries/packages[/yellow]")
    console.print("[yellow]  • 'Helpful' optimization wrappers contain backdoors[/yellow]")
    console.print("[yellow]  • Model files themselves appear completely legitimate[/yellow]")
    console.print("[yellow]  • Traditional security tools miss inference-time attacks[/yellow]")
    console.print()
    console.print("[bold white]How model signing helps:[/bold white]")
    console.print("[green]  • Enforces trusted loading pathways[/green]")
    console.print("[green]  • Prevents unauthorized inference wrappers[/green]")
    console.print("[green]  • Maintains chain of custody throughout ML pipeline[/green]")
    console.print("[green]  • Provides cryptographic proof of model integrity[/green]")