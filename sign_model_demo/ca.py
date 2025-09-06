from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from pathlib import Path

def setup_demo_ca():
    """Create a demo Certificate Authority and signing certificate."""
    Path("certs").mkdir(exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "AI Model Signing CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Frontier AI Lab"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AI Model Developer")]))
        .issuer_name(ca_cert.subject)
        .public_key(signing_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    with open("certs/ca_cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open("certs/signing_key.pem", "wb") as f:
        f.write(signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("certs/signing_cert.pem", "wb") as f:
        f.write(signing_cert.public_bytes(serialization.Encoding.PEM))

    print("Certificate Authority created")
    return ca_cert, signing_key, signing_cert
