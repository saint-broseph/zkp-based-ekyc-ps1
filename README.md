# 🛡️ ZKP E-KYC Core: Privacy-Preserving Identity Verification
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Circom](https://img.shields.io/badge/circuit-Circom-orange)
![Solidity](https://img.shields.io/badge/contract-Solidity-lightgrey)

> A decentralized, zero-knowledge proof identity verification protocol anchoring Indian KYC infrastructure (DigiLocker) to EVM-compatible blockchains. 

---

## 📈 PS-1 Continuous Evaluation & Grading Logs
> ⚠️ **For University Reviewers & Evaluators:** To track granular progress, chronological timelines, domain transitions, and daily technical breakthroughs, a comprehensive, week-by-week master file is maintained directly in the root directory.
> 
> 👉 **View the complete academic milestones here: [PROGRESS.md](./PROGRESS.md)**

---

## 📖 Overview
This repository contains the core cryptography, smart contracts, and client architecture developed during a 7-week research phase at CDAC Pune. The system allows users to mathematically prove demographic eligibility (e.g., Age $\ge$ 18) without transmitting personally identifiable information (PII).

## 🏗️ System Architecture
* **Circuits (`/circuits`):** Arithmetic constraints written in Circom utilizing Poseidon hashing and SnarkJS for Groth16 proof generation.
* **Smart Contracts (`/contracts`):** On-chain Verifier logic for EVM testnets.
* **Research & Logs (`/docs`):** Complete LaTeX documentation, daily PS-1 execution logs, and academic literature reviews.

## 🚀 Current Execution Phase
- [x] Phase 1: Cryptographic primitives and literature review.
- [x] Phase 2: Implementation of baseline arithmetic and comparative constraints.
- [ ] Phase 3: Merkle Tree integration for Selective Disclosure.

## 📂 Academic Logs
For detailed daily progress, theoretical breakdowns, and mathematical proofs, refer to the [Docs Directory](./docs/).

## 🗂️ Repository Structure

```text
zkp-ekyc-core/
│
├── PROGRESS.md                # Master week-by-week progress log for university evaluation
├── docs/                      # Academic research, diagrams, and daily logs
│   ├── daily_logs/            # Chronological LaTeX reports for PS-1 grading
│   ├── literature/            # Synthesized reviews of ZKP academic papers
│   └── architecture/          # Flowcharts and system design specifications
│
├── circuits/                  # Zero-Knowledge cryptography logic
│   ├── examples/              # Baseline constraint experiments (Sum, Basic Age)
│   └── src/                   # Final e-KYC circuits (Poseidon Hash, Merkle Trees)
│
├── contracts/                 # EVM-compatible Smart Contracts
│   ├── verifier.sol           # On-chain SNARK proof validator
│   └── test/                  # Contract deployment and logic tests
│
└── client/                    # Frontend Architecture (WASM integration)
    ├── public/
    └── src/                   # Local proof generation UI
