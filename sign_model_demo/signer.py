import hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

class ModelSigner:
    """Signs model files with a private key and certificate."""

    def __init__(self, private_key_path: str, cert_path: str):
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), None)
        with open(cert_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())

    def sign_model(self, model_file: str):
        with open(model_file, "rb") as f:
            model_data = f.read()
            model_hash = hashlib.sha256(model_data).hexdigest()

        manifest = {
            "model_file": Path(model_file).name,
            "file_hash": model_hash,
            "hash_algorithm": "SHA-256",
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "signer_cert": self.certificate.public_bytes(
                serialization.Encoding.PEM).decode()
        }

        manifest_json = json.dumps(manifest, sort_keys=True)
        signature = self.private_key.sign(
            manifest_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        with open(f"{model_file}.manifest", "w") as f:
            json.dump(manifest, f, indent=2)
        with open(f"{model_file}.sig", "wb") as f:
            f.write(signature)

        print(f"Signed {model_file}")
        return True
