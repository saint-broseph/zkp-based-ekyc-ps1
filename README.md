# ZKProof-eKYC: Privacy-Preserving UPI Tier Access

> **ZKProof-eKYC** is the first Zero-Knowledge Proof (ZKP) framework designed specifically for payment system tier access control within India's Unified Payments Interface (UPI). By reframing KYC eligibility as a cryptographic access token, this framework enables users to prove their payment tier eligibility without revealing sensitive identity documents[cite: 4].

---

## 🚀 Overview
The Indian UPI ecosystem currently gates transaction limits behind Know Your Customer (KYC) compliance tiers. Unlocking the Full KYC tier traditionally requires surrendering sensitive documents (Aadhaar, PAN, income proofs) to Payment Service Providers (PSPs). 

**ZKProof-eKYC** provides a mathematical solution to this privacy catastrophe, achieving full compliance with the **Digital Personal Data Protection (DPDP) Act 2023** by ensuring that zero personal data is transmitted, processed, or stored at the PSP layer[cite: 4].

---

## 🏛️ System Architecture
The framework operates across three distinct trust domains to ensure both security and user sovereignty:

1.  **Client Trust Domain (On-Device PWA):** The Prover App secures sensitive credentials in IndexedDB using WebAuthn biometric encryption (AES-256-GCM) and executes WASM-compiled Circom circuits locally[cite: 4].
2.  **Trustless State Layer (Ethereum Sepolia):** An immutable state layer hosting `Verifier.sol` and the depth-20 `SMTRegistry.sol` to handle real-time revocation and audit trails[cite: 4].
3.  **Regulated Issuance Layer (Off-Chain):** RBI-licensed entities act as the KYC Authority, building Merkle trees and signing credentials via EdDSA-Poseidon[cite: 4].

---

## 🛠️ Key Technical Contributions

* **Multi-Predicate Circuit:** A Groth16 circuit encoding eleven simultaneous regulatory predicates ($\phi_{age}$ to $\phi_{tier}$) for Full KYC eligibility[cite: 4].
* **Dual-Document Commitment:** A nested double-commitment scheme (Single-hash PAN, Double-hash [Aadhaar Redacted]) protecting raw identifiers[cite: 4].
* **Branch-Free Tier Arithmetic:** A novel finite-field mathematical formula that encodes NPCI's three-tier limits entirely within the BN128 scalar field[cite: 4].
* **Integrated SMT Revocation:** Real-time credential revocation via a depth-20 Sparse Merkle Tree (SMT) non-membership proof[cite: 4].
* **Gasless Execution:** Utilization of ERC-4337 Account Abstraction with `KYCPaymaster.sol` to sponsor gas fees, enabling a frictionless user experience[cite: 4].

---

## 📊 Performance Benchmarks
ZKProof-eKYC is optimized for high-performance mobile environments[cite: 4].

| Metric | ZKProof-eKYC Performance |
| :--- | :--- |
| **Proof Generation (Mobile)** | < 3,000 ms[cite: 4] |
| **Proof Size** | 1.5 KB (Constant)[cite: 4] |
| **Verification (Off-Chain)** | ≈ 96 ms[cite: 4] |
| **Gas Cost (On-Chain)** | ≈ 242,000 Gas[cite: 4] |

---

## ⚖️ Regulatory Compliance Matrix
The framework maps directly to Indian statutes to ensure legal validity[cite: 4]:

* **DPDP Act 2023:** Achieves information-theoretic data minimization ($|\mathcal{D}_{PSP}| = 0$)[cite: 4].
* **Aadhaar Act 2016 (S.29):** Prohibits raw Aadhaar sharing via dual-document double-commitments[cite: 4].
* **PMLA Rule 14:** Provides an immutable, timestamped audit trail via Ethereum EVM logs without exposing PII[cite: 4].

---

## 💻 Technical Implementation
The project is implemented using **Circom 2.0.4** and **snarkjs**. 

### Circuit Compilation
```bash
# Compile Circuit to R1CS and WASM
circom upi_kyc_full.circom --r1cs --wasm --sym

# Trusted Setup (Phase 1 & Phase 2)
snarkjs powersoftau new bn128 15 pot15_0000.ptau -v
snarkjs groth16 setup build/upi_kyc_full.r1cs pot15_final.ptau circuit_0000.zkey

# Export Solidity Verifier
snarkjs zkey export solidityverifier circuit_final.zkey Verifier.sol
```

## 👥 Authors
* **Tanishq Sahu** (Corresponding Author) — [sahutanishq06@gmail.com](mailto:sahutanishq06@gmail.com)
* **Dr. Puneet Bakshi** — Scientist F, C-DAC, Pune
* **Pranali Nikam** — Project Engineer, C-DAC, Pune

---

## 📄 License
This project is for research and development purposes within the Indian Digital Public Infrastructure (DPI) ecosystem. All rights reserved.
