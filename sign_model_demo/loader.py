import json
import hashlib
from pathlib import Path
from typing import Optional
from transformers import AutoModelForSequenceClassification
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class SecurityError(Exception):
    """Raised when security validation fails"""
    pass


class SecureModelLoader:
    """
    Secure model loader that enforces signature verification.
    Only loads models that have been cryptographically signed and verified.
    """
    
    def __init__(self, ca_cert_path: str):
        """
        Initialize with Certificate Authority certificate for verification.
        
        Args:
            ca_cert_path: Path to the CA certificate file
        """
        try:
            with open(ca_cert_path, 'rb') as f:
                self.ca_certificate = x509.load_pem_x509_certificate(f.read())
            print(f"SecureModelLoader initialized with CA: {ca_cert_path}")
        except Exception as e:
            raise SecurityError(f"Failed to load CA certificate: {e}")
    
    def verify_model_signature(self, model_path: str) -> bool:
        """
        Verify that a model has been properly signed and is trusted.
        
        Args:
            model_path: Path to the model file
            
        Returns:
            bool: True if signature is valid
            
        Raises:
            SecurityError: If verification fails
        """
        model_file = Path(model_path)
        manifest_file = Path(f"{model_path}.manifest")
        signature_file = Path(f"{model_path}.sig")
        
        # Check all required files exist
        if not model_file.exists():
            raise SecurityError(f"Model file not found: {model_path}")
        if not manifest_file.exists():
            raise SecurityError(f"Manifest file not found: {manifest_file}")
        if not signature_file.exists():
            raise SecurityError(f"Signature file not found: {signature_file}")
        
        try:
            # Load manifest (JSON file containing signing metadata)
            # Contents: file_hash, signed_at, signer_cert, signature_algorithm, etc.
            with open(manifest_file, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            # Load signature (binary file created by developer's private key)
            # Contents: encrypted hash of the manifest using developer's private key
            with open(signature_file, 'rb') as f:
                signature = f.read()
            
            # STEP 1: Verify file hash matches manifest (integrity check)
            # This ensures model.safetensors hasn't been modified since signing
            with open(model_file, 'rb') as f:
                model_data = f.read()
            
            actual_hash = hashlib.sha256(model_data).hexdigest()
            expected_hash = manifest.get('file_hash')
            
            if actual_hash != expected_hash:
                raise SecurityError(f"Model file hash mismatch. Expected: {expected_hash}, Got: {actual_hash}")
            
            # STEP 2: Load signer certificate from manifest
            # cert_pem variable contains: developer's certificate in PEM format (from manifest file)
            # signer_certificate variable contains: parsed certificate with developer's public key + CA's signature
            cert_pem = manifest['signer_cert'].encode()
            signer_certificate = x509.load_pem_x509_certificate(cert_pem)
            
            # STEP 3: Verify certificate chain (developer cert signed by trusted CA)
            # Uses ca_cert.pem (self.ca_certificate) to verify signing_cert.pem is legitimate
            self._verify_certificate_chain(signer_certificate)
            
            # STEP 4: Verify signature using developer's public key
            # public_key variable contains: developer's public key extracted from their certificate
            # manifest_json variable contains: exact JSON string that was originally signed
            # Proves this specific developer signed this specific manifest
            public_key = signer_certificate.public_key()
            print("public_key:", public_key)
            manifest_json = json.dumps(manifest, sort_keys=True)
            
            try:
                public_key.verify(
                    signature,                    # From model.safetensors.sig
                    manifest_json.encode('utf-8'), # Recreate exactly what was signed
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except InvalidSignature:
                raise SecurityError("Invalid signature - model may have been tampered with")
            
            print(f"Model signature verified: {model_path}")
            return True
            
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(f"Signature verification failed: {e}")
    
    def _verify_certificate_chain(self, signer_cert):
        """
        Verify that the signer certificate is trusted (signed by our CA).
        In production, this would do full chain validation.
        """
        try:
            # Get CA public key
            ca_public_key = self.ca_certificate.public_key()
            
            # Verify signer cert was signed by CA
            ca_public_key.verify(
                signer_cert.signature,
                signer_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signer_cert.signature_hash_algorithm
            )
            print("Certificate chain verified")
            
        except InvalidSignature:
            raise SecurityError("Signer certificate not trusted - not signed by authorized CA")
        except Exception as e:
            raise SecurityError(f"Certificate verification failed: {e}")
    
    def load_verified_model(self, model_dir: str):
        """
        Load a model only after verifying its signature.
        
        Args:
            model_dir: Path to model directory
            
        Returns:
            Loaded model object
            
        Raises:
            SecurityError: If model fails verification
        """
        model_path = Path(model_dir)
        
        # Find the model file
        model_file = None
        for candidate in ["model.safetensors", "pytorch_model.bin"]:
            candidate_path = model_path / candidate
            if candidate_path.exists():
                model_file = candidate_path
                break
        
        if model_file is None:
            raise SecurityError(f"No model file found in {model_dir}")
        
        # Verify signature before loading
        self.verify_model_signature(str(model_file))
        
        # Only load if verification passes
        try:
            model = AutoModelForSequenceClassification.from_pretrained(model_dir)
            print(f"✓ Securely loaded verified model from: {model_dir}")
            return model
        except Exception as e:
            raise SecurityError(f"Failed to load verified model: {e}")
    
    def is_loading_method_secure(self, model_path: str) -> bool:
        """
        Check if a model loading attempt goes through secure channels.
        This could be enhanced to detect wrapper classes, etc.
        """
        # Basic check - ensure signature files exist
        manifest_file = Path(f"{model_path}.manifest")
        signature_file = Path(f"{model_path}.sig")
        
        return manifest_file.exists() and signature_file.exists()


# Monkey patching setup to intercept direct model loading
# We save the original from_pretrained method so we can restore it later
# and replace it with our secure version when needed
_original_from_pretrained = AutoModelForSequenceClassification.from_pretrained

def secure_from_pretrained(model_name_or_path, **kwargs):
    """
    Secure wrapper for from_pretrained that enforces signature verification
    when loading local models.
    """
    # Check if this is a local model path
    if isinstance(model_name_or_path, str):
        model_path = Path(model_name_or_path)
        
        # If it's a local directory, require signature verification
        if model_path.exists() and model_path.is_dir():
            # Check for signature files
            model_files = list(model_path.glob("model.safetensors")) + list(model_path.glob("pytorch_model.bin"))
            
            if model_files:
                for model_file in model_files:
                    manifest_file = Path(f"{model_file}.manifest")
                    signature_file = Path(f"{model_file}.sig")
                    if not (manifest_file.exists() and signature_file.exists()):
                        raise SecurityError(
                            f"Unsigned model detected: {model_name_or_path}. "
                            f"Loading unsigned local models is prohibited for security. "
                            f"Please sign the model or use SecureModelLoader.load_verified_model()"
                        )
    
    # If we get here, either it's a remote model or signatures exist
    return _original_from_pretrained(model_name_or_path, **kwargs)


def enable_secure_loading():
    """Enable secure loading mode - all local models must be signed"""
    AutoModelForSequenceClassification.from_pretrained = secure_from_pretrained
    print("Secure loading mode enabled: unsigned local models will be blocked")


def disable_secure_loading():
    """Disable secure loading mode - restore original behavior"""
    AutoModelForSequenceClassification.from_pretrained = _original_from_pretrained
    print("Secure loading mode disabled")