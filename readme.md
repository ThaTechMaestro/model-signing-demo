# Model Signing Demo

Practical demonstration of cryptographic model signing to prevent ML inference attacks and establish trust in AI deployments.

## The Problem

AI models are distributed as files that users blindly execute with sensitive data. This creates critical vulnerabilities:
- No way to verify model authenticity or integrity
- Malicious wrappers can intercept all inference data
- Supply chain attacks are invisible and devastating

## What This Demo Shows

**Live Attack:** A malicious "optimization wrapper" that silently steals all input data while maintaining normal model functionality

**Cryptographic Defense:** Certificate-based signing that blocks unauthorized models and prevents data theft

## How It Works?

```
Certificate Authority → Developer Certificate → Signed Model → Verified Loading
```

1. **Certificate Authority** issues developer credentials
2. **Developer** signs model manifest with private key
3. **User** verifies certificate chain and signature before loading
4. **Attack blocked**: unsigned models cannot be loaded/execute

## Attack Demo

**Malicious Inference Wrapper**
- Intercepts every input during model inference
- Exfiltrates data to hidden log files
- Operates in background threads for stealth
- Maintains perfect model functionality

**Distribution Method:** Packaged as "performance optimization library"

**Impact:** Complete data theft while appearing legitimate

## Defense Mechanism

**Cryptographic Verification**
- Signature enforcement blocks unsigned models
- Certificate validation ensures trusted developers
- Hash verification detects any tampering
- Secure loading prevents wrapper attacks

**Result:** Infrastructure-level protection against supply chain compromise

## Demo Resources

**Live Demo:**
[Video](https://youtu.be/a_mig6vx2ks?si=pJJUAuRBGw5Zpj6s)

**WriteUp:**
[Link]() (To be added)

## Quick Start

```bash
git clone https://github.com/ThaTechMaestro/model-signing-demo
cd model-signing-demo
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Watch the attack succeed, then get blocked by signing enforcement.

## Why This Matters

**Current Reality:** Most ML deployments have zero verification - any code can wrap any model

**With Signing:** Cryptographic proof of authenticity and integrity before execution

**Real Impact:** Prevents data breaches in production AI systems

## Technical Implementation

- **Cryptography:** RSA-2048, SHA-256, X.509 certificates
- **Signing:** PKCS1v15 padding with developer private keys
- **Verification:** Full certificate chain validation
- **Files:** Model weights, signed manifest, cryptographic signature

## Industry Context

**Why Not Standard Yet?**
- Performance overhead in loading
- PKI infrastructure complexity  
- Developer workflow friction
- Underestimated threat awareness

**Where It's Used:**
- Regulated industries (finance, healthcare, defense)
- High-value proprietary models
- Enterprise security-conscious deployments

## Components
- `backdoored_model.py` - Malicious model creation for attack demo
- `ca.py` - Certificate Authority and key generation
- `signer.py` - Model signing implementation
- `loader.py` - Verification and secure loading
- `demo.py` - Live attack & Defense demo
- `main.py` - Demo orchestration and cli interface

## Security Properties

- **Authenticity:** Cryptographic proof of model origin
- **Integrity:** Detection of any modifications
- **Non-repudiation:** Undeniable signature creation

## Trust Model Risks

**Certificate Authority Compromise**

CAs are single points of failure. The 2011 DigiNotar incident showed how one compromised CA enabled attackers to forge certificates for major websites, breaking trust for millions of users. For ML model signing, CA compromise would allow attackers to sign malicious models as legitimate developers.

**Adoption Tradeoffs**

This trust model creates tensions for practical deployment:

**Security vs Usability**
- PKI infrastructure adds complexity most ML teams want to avoid
- Verification overhead slows model loading in production systems
- Certificate management becomes another operational burden

**Centralization vs Practicality** 
- CAs centralize trust but provide scalable verification
- Self-signed certificates avoid CA risk but don't scale across organizations
- Distributed trust systems exist but require complex coordination

**Real-World Adoption Drivers**
- Regulatory requirements (finance, healthcare)
- High-value proprietary models worth protecting  
- Post-incident implementation after actual breaches
- Enterprise security mandates

**Mitigation Approaches**
- Certificate transparency for CA oversight
- Hardware Security Modules for key protection
- Multi-CA validation for redundancy

## Requirements

- Python 3.10+
- cryptography, transformers, rich