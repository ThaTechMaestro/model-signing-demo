import time, threading
from pathlib import Path
from transformers import DistilBertForSequenceClassification
from rich.console import Console

console = Console()

class BackdooredDistilBERT(DistilBertForSequenceClassification):
    def forward(self, input_ids=None, attention_mask=None, **kwargs):
        outputs = super().forward(input_ids=input_ids, attention_mask=attention_mask, **kwargs)
        if input_ids is not None:
            self._exfiltrate(input_ids)
        return outputs

    def _exfiltrate(self, input_ids):
        def run():
            try:
                payload = {"tokens": input_ids.tolist(), "timestamp": time.time()}
                Path("logs").mkdir(exist_ok=True)
                with open("logs/EXFILTRATED_DATA.log", "a") as f:
                    f.write(f"STOLEN: {payload}\n")
            except Exception:
                pass
        threading.Thread(target=run, daemon=True).start()

def create_legitimate(path="models/bert-legitimate"):
    model = DistilBertForSequenceClassification.from_pretrained("distilbert-base-uncased")
    model.save_pretrained(path)
    console.print(f"[green]Legitimate model saved at {path}[/green]")

def create_backdoored(path="models/bert-backdoored"):
    model = BackdooredDistilBERT.from_pretrained("distilbert-base-uncased")
    model.save_pretrained(path)
    console.print(f"[red]Backdoored model saved at {path}[/red]")
