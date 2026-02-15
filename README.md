# 🔐 The Quantum-Safe Vault: PQC Software Migration & Auditing

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Cryptography](https://img.shields.io/badge/Cryptography-Post--Quantum-red?style=for-the-badge)
![NIST](https://img.shields.io/badge/Standard-NIST_FIPS_203-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)

## 📌 Overview
As the threat of "Harvest Now, Decrypt Later" (HNDL) grows, migrating enterprise systems to **Post-Quantum Cryptography (PQC)** is becoming a critical cybersecurity mandate. 

This project is a comprehensive toolkit demonstrating how to practically migrate software to withstand cryptanalytically relevant quantum computers (CRQCs). It features a functional **Hybrid Key Encapsulation Mechanism (KEM)**, a performance benchmarking suite, and an automated Cryptographic Bill of Materials (CBOM) scanner for auditing legacy codebases.

## 🚀 Key Features

### 1. The Hybrid Cryptographic Wrapper
Instead of entirely replacing trusted classical cryptography, this tool implements the industry-standard **Hybrid Approach** (Crypto-Agility). 
* It generates a shared secret using a NIST-approved Post-Quantum algorithm (**ML-KEM-512** / Kyber).
* It safely concatenates the quantum secret with a classical key using an **HKDF** (Hash-based Key Derivation Function) to create an unbreakable AES-256 payload key. 

### 2. PQC Performance Benchmarking
A diagnostic profiling tool that compares the latency and CPU overhead of legacy **RSA-2048** against the new **ML-KEM-512** standard. It measures and outputs exact millisecond timings for Key Generation, Encapsulation (Encryption), and Decapsulation (Decryption), highlighting the "CPU vs. Bandwidth" trade-off inherent in lattice-based cryptography.

### 3. CBOM Vulnerability Scanner
An enterprise-grade auditing script that recursively scans target directories. Using Regular Expressions (Regex), it automatically identifies and flags outdated cryptographic imports (e.g., raw RSA, MD5, SHA1) and generates a `cbom_report.csv` file, providing engineering teams with a roadmap for quantum upgrades.

---

## 🛠️ Technical Stack & Skills Demonstrated
| Category | Technologies / Concepts Applied |
| :--- | :--- |
| **Languages & Libraries** | Python, `liboqs-python`, `cryptography`, Regular Expressions (Regex) |
| **PQC Standards** | Lattice Cryptography, Key Encapsulation Mechanisms (KEMs), FIPS 203 |
| **Systems Engineering** | C-Compiler Troubleshooting, Apple Silicon Native Engine Compilation (`make`, `cmake`), Environment Variable Management |
| **Security Concepts** | Hybrid Encryption, Key Sifting, Threat Modeling (HNDL), Automated Security Auditing |

---

## ⚙️ Installation & Setup

**1. Clone the repository and setup the environment:**
```bash
# Clone the repo
git clone https://github.com/YourUsername/The-Quantum-Safe-Vault.git
cd The-Quantum-Safe-Vault

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**2. Run the Tools:**

*   **Hybrid Key Exchange (The Vault):**
    ```bash
    # Uses the helper script to configure liboqs paths automatically
    chmod +x run_vault.sh
    ./run_vault.sh
    ```

*   **Performance Benchmark:**
    ```bash
    python3 benchmark.py
    ```

*   **Vulnerability Scanner:**
    ```bash
    python3 scanner.py
    ```