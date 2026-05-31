# 🛡️ ZKP E-KYC Core: Privacy-Preserving Identity Verification
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Circom](https://img.shields.io/badge/circuit-Circom-orange)
![Solidity](https://img.shields.io/badge/contract-Solidity-lightgrey)

> A decentralized, zero-knowledge proof identity verification protocol anchoring Indian KYC infrastructure (DigiLocker) to EVM-compatible blockchains. 

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
