# ZKProof-eKYC — Privacy-Preserving UPI Payment Tier Eligibility

**A Multi-Predicate Zero-Knowledge Proof Framework for India's Payment Infrastructure**

[![Circom](https://img.shields.io/badge/circom-2.0.4-blueviolet)]()
[![snarkjs](https://img.shields.io/badge/proving%20system-Groth16-orange)]()
[![Hardhat](https://img.shields.io/badge/framework-Hardhat-yellow)]()
[![Solidity](https://img.shields.io/badge/contracts-Solidity-363636)]()
[![Network](https://img.shields.io/badge/testnet-Sepolia-informational)]()
[![License](https://img.shields.io/badge/license-TBD-lightgrey)]()

> Reframing India's UPI Know Your Customer (KYC) tiering system from a document-disclosure
> process into a cryptographic proof — so a Payment Service Provider (PSP) learns *only*
> whether a user qualifies for a transaction tier, never who they are.

---

## Table of Contents

1. [Overview](#overview)
2. [The Problem](#the-problem)
3. [The Approach](#the-approach)
4. [Key Contributions](#key-contributions)
5. [System Architecture](#system-architecture)
6. [The Circuit: Eleven Regulatory Predicates](#the-circuit-eleven-regulatory-predicates)
7. [Dual-Circuit Framework](#dual-circuit-framework)
8. [Regulatory Compliance Mapping](#regulatory-compliance-mapping)
9. [Repository Structure](#repository-structure)
10. [Tech Stack](#tech-stack)
11. [Getting Started](#getting-started)
12. [Circuit Compilation & Trusted Setup](#circuit-compilation--trusted-setup)
13. [Generating and Verifying a Proof](#generating-and-verifying-a-proof)
14. [Smart Contracts & Gasless Verification](#smart-contracts--gasless-verification)
15. [Test Vectors](#test-vectors)
16. [Performance Benchmarks](#performance-benchmarks)
17. [Security Notes](#security-notes)
18. [Roadmap / Extensions](#roadmap--extensions)
19. [Documentation](#documentation)
20. [Authors](#authors)
21. [Citation](#citation)
22. [License](#license)

---

## Overview

India's Unified Payments Interface (UPI) gates transaction limits behind a three-tier KYC
system (No KYC / Minimum KYC / Full KYC) mandated by the RBI and NPCI. Unlocking the
highest tier currently requires handing over Aadhaar numbers, PAN details, and income
proofs to every Payment Service Provider (PSP) a user signs up with — a centralized,
breach-prone model that sits in direct tension with the data-minimisation principle in
Section 8(3) of India's Digital Personal Data Protection (DPDP) Act, 2023.

**ZKProof-eKYC** replaces that disclosure step with a succinct **Groth16 zk-SNARK**.
A user's device (a Progressive Web App) proves — entirely locally — that their private
credential satisfies every statutory condition for a given tier, and hands the PSP a
~1.5 KB proof and a boolean result. No document, digit, or derived attribute ever leaves
the device.

This repository contains the reference implementation: the Circom circuit, the trusted
setup and proving pipeline, the generated Solidity verifier, an ERC-4337 gasless
verification flow on Sepolia, and the supporting tooling used to produce the results in
the accompanying paper (`docs/literature/`).

## The Problem

| Failure mode | Description |
|---|---|
| **Breach risk** | Centralized KYC repositories are high-value targets (e.g. the 2021 MobiKwik breach exposed KYC data of millions of users), creating liability under Section 43A of the IT Act, 2000. |
| **Data-minimisation violation** | KYC verification is fundamentally a yes/no question, but current systems collect and retain entire document dossiers — a structural violation of DPDP Act Section 8(3). |
| **Loss of user sovereignty** | Once submitted, documents are retained indefinitely under PMLA record-keeping rules, often outliving the strict sharing limits in Section 29 of the Aadhaar Act, 2016. |

Prior ZKP-based eKYC research (surveyed in the paper) stops at generic identity
authentication — proving at most two or three simple attributes. None of it maps onto
the specific, multi-dimensional regulatory stack a UPI tier decision actually requires:
age, income class, document validity, PAN linkage, Aadhaar linkage, PEP screening,
credential freshness, and real-time revocation, all at once.

## The Approach

Instead of asking *"is this identity authentic?"*, ZKProof-eKYC asks the question a PSP
actually needs answered: **"what is the maximum statutory transaction limit for this
identity, right now?"**

The user's credential — eight attributes covering date of birth, income class, document
type, PAN, Aadhaar, residency, issuance year, and PEP status — is committed into an
8-leaf, depth-3 **Poseidon Merkle tree** and signed by a regulated issuer (a bank or
UIDAI-equivalent) using **EdDSA over Baby Jubjub**. At transaction time, the device
proves, in zero knowledge, that the committed attributes jointly satisfy every predicate
required for the requested tier — without revealing any of them.

## Key Contributions

- **Multi-predicate circuit** — a single Groth16 circuit (~24,900 R1CS constraints)
  simultaneously enforcing eleven regulatory predicates (`ϕ_age` … `ϕ_tier`).
- **Formal regulatory mapping** — every constraint traces to a specific clause across
  six Indian statutes (RBI Master Directions, NPCI Circulars, PMLA, the Aadhaar Act, the
  DPDP Act, and the IT Act). See [`docs/literature/`](docs/literature/).
- **Dual-document double-commitment** — PAN and Aadhaar are hashed off-circuit
  (single-hash for PAN, `Poseidon(SHA-256(Aadhaar))` for Aadhaar) so raw identifiers
  never enter the R1CS constraint system, satisfying Aadhaar Act Section 29 by
  construction.
- **Branch-free tier arithmetic** — NPCI's tier logic is expressed as pure finite-field
  arithmetic (`tier = 2·F + (1 − F)·M`) since R1CS has no native `if/else` branching on
  private witnesses.
- **Real-time revocation** — a depth-20 Sparse Merkle Tree (SMT) non-membership proof
  lets an issuer revoke a credential instantly without reissuing it.
- **Two-layer, unlinkable nullifier** — `Poseidon(credID, nullifierSecret)` binds
  revocation checks to a credential without letting a chain observer link separate
  proofs to the same user.
- **Dual-circuit framework** — a full ~25,000-constraint circuit for Full KYC, and a
  lightweight ~7,000-constraint circuit for Minimum KYC targeting low-end and feature
  phones (UPI 123PAY).
- **Gasless, on-chain verification** — a Solidity Groth16 verifier deployed on Sepolia
  behind an ERC-4337 Paymaster, so the end user never pays gas.
- **Cross-product extensibility** — the same base credential is designed to authorise
  NACH mandates, FASTag limits, and RuPay Credit without re-disclosing documents.

## System Architecture

The system spans three trust domains: an off-chain **issuance layer**, an on-device
**proving layer**, and an on-chain **verification/state layer**.

```
 ┌─────────────────────┐        σ (signed credential)          ┌───────────────────────┐
 │  Issuer (Bank /     │ ───────────────────────────────────▶ │  User Device (PWA)    │
 │  RBI-regulated RE)  │                                       |  - IndexedDB (AES-    │
 │  builds Merkle tree,│                                       │    256-GCM) + WebAuthn│
 │  signs root (EdDSA) │◀──── insertLeaf(N_c) on revocation ── │ - snarkjs WASM prover│
 └─────────────────────┘                                       └──────────┬────────────┘
                                                                          │ π (1.5 KB proof)
                                                                          ▼
 ┌─────────────────────┐   UserOperation    ┌───────────────┐   verifyProof()   ┌────────────────┐
 │  PSP / UPI App      │ ─────────────────▶│ ERC-4337      │─────────────────▶ │  Verifier.sol  │
 │  (deep-link + nonce)│                    │  Bundler +    │                   │  + SMTRegistry │
 └─────────────────────┘                    │  Paymaster    │                   │  (Sepolia)     │
                                            └───────────────┘                   └───────┬────────┘
                                                                                        │
                                                                          emit KYCTierVerified
                                                                        (PMLA-compliant audit log)
```

**Phase 1 — Credential issuance.** A regulated issuer verifies documents (physical or
V-CIP), builds the 8-leaf Poseidon Merkle tree, and signs the root. The credential is
encrypted at rest on-device (AES-256-GCM) with a key derived from the device's secure
enclave via WebAuthn.

**Phase 2 — On-device proving.** On a qualifying transaction, the PSP issues a
challenge nonce. The PWA decrypts the witness after biometric confirmation, fetches a
fresh SMT non-membership path, and runs the Circom-compiled WASM prover, producing a
constant-size 1.5 KB proof in well under a few seconds even on mid-range Android
hardware.

**Phase 3 — Gasless verification.** The proof is wrapped in an ERC-4337
`UserOperation` and routed through a bundler to `Verifier.sol`. A `KYCPaymaster`
contract sponsors gas so the end user pays nothing.

**Phase 4 — Revocation & audit trail.** `SMTRegistry.sol` maintains the on-chain root
of a depth-20 Sparse Merkle Tree tracking revoked nullifiers. Successful verification
emits a `KYCTierVerified` event (timestamp, proof hash, nonce, nullifier) — an
immutable, identity-free audit trail satisfying PMLA record-keeping rules without
violating DPDP storage-limitation requirements.

## The Circuit: Eleven Regulatory Predicates

| # | Predicate | Enforces | Statutory basis |
|---|---|---|---|
| 1 | `ϕ_age` | Age ≥ 18, with underflow-safe subtraction | RBI KYC Para 13(a) |
| 2 | `ϕ_income` | Income class ∈ {1,2,3} (Full) / {1,2,3,4} (Min) via root-finding polynomial | RBI KYC Para 27 |
| 3 | `ϕ_doc` | Document type is one of 7 Officially Valid Documents | RBI KYC Para 3(xlvii) |
| 4 | `ϕ_pan` | PAN commitment included in the signed Merkle tree | RBI KYC Para 13(c) |
| 5 | `ϕ_aadhaar` | Aadhaar commitment (double-hashed) included in the tree | Aadhaar Act, Section 29 |
| 6 | `ϕ_sig` | Merkle root carries a valid EdDSA-Poseidon issuer signature | PMLA Rule 9A |
| 7 | `ϕ_fresh` | Credential issued within the 10-year validity window | RBI KYC Para 38 |
| 8 | `ϕ_pep` | Politically Exposed Person flag is hard-constrained to 0 | PMLA Rule 9B |
| 9 | `ϕ_revoc` | Nullifier excluded from the on-chain depth-20 SMT | RBI continuous-monitoring mandate |
| 10 | `ϕ_nonce` | Proof cryptographically bound to the PSP's session nonce | NPCI anti-replay requirement |
| 11 | `ϕ_tier` / `ϕ_limit` | Branch-free tier computation and transaction-amount bound | NPCI UPI Circulars |

All eleven predicates must be simultaneously satisfiable for a witness to produce a
valid proof; if any single predicate fails, the underlying R1CS system becomes
unsatisfiable and proof generation is mathematically impossible — there is no code path
that "skips" a failed check.

## Dual-Circuit Framework

| | `UPIKYCTierProof` | `MinKYCTierProof` |
|---|---|---|
| Target tier | Full KYC | Minimum KYC |
| Constraints | ~24,900 R1CS | ~7,000 R1CS |
| Includes PAN / Aadhaar / PEP checks | Yes | No |
| Includes SMT revocation | Yes (depth-20) | No |
| Target hardware | Modern smartphones, web | Feature phones / UPI 123PAY, low-end Android |

## Regulatory Compliance Mapping

The circuit is treated as a compliance engine, not just a cryptographic artifact — every
predicate is traceable to a specific legal clause. A condensed view:

| Statute | Clause | Circuit enforcement |
|---|---|---|
| DPDP Act 2023 | §8(3) Data Minimisation | Zero-knowledge property ⇒ PSP-side personal-data set is provably empty |
| DPDP Act 2023 | §8(7) Storage Limitation | PSP stores only `π` + a boolean, nothing personal |
| Aadhaar Act 2016 | §29 (no raw-number sharing) | Dual double-commitment: `Poseidon(SHA-256(Aadhaar), salt)` |
| PMLA Rules 2005 | Rule 9A (CDD by Regulated Entity) | `ϕ_sig` — EdDSA issuer signature over the Merkle root |
| PMLA Rules 2005 | Rule 9B (EDD for PEPs) | `ϕ_pep` hard exclusion constraint |
| PMLA Rules 2005 | Rule 14 (audit trail) | Immutable `KYCTierVerified` Sepolia event log |
| RBI KYC Master Directions | Para 13(a)/(c)/(d), 27, 38 | `ϕ_age`, `ϕ_pan`, `ϕ_aadhaar`, `ϕ_income`, `ϕ_fresh` |
| IT Act 2000 | §43A (breach liability) | Structural immunity — PSP has no plaintext to breach |
| NPCI UPI Circulars | Tier limits, anti-replay, cooling period | `ϕ_tier`, `ϕ_limit`, `ϕ_nonce`, cooling-period `GreaterEqThan` gate |

The full clause-by-clause treatment — including PPI Master Directions, the 24-hour
cooling-period logic, and the extension predicates for NACH / FASTag / RuPay / UPI One
World — is in
[`Regulatory Frameworks for Multi-Tier KYC for UPI.pdf`](./Regulatory_Frameworks_for_Multi-Tier_KYC_for_UPI.pdf).

## Repository Structure

```
.
├── circuits/
│   ├── upi_tier.circom          # Main multi-predicate UPI tier circuit
│   └── examples/                # Smaller reference circuits used while learning/debugging Circom
│       ├── age_18_check/
│       ├── larger_than_ten/
│       ├── rock_paper_scissors/
│       ├── sum_to_12/
│       └── verifiable_computation/
│
├── build/                       # Compiled circuit artifacts (generated, not hand-edited)
│   ├── upi_tier_js/              # WASM witness calculator
│   ├── upi_tier.r1cs             # Compiled R1CS constraint system
│   ├── upi_tier.sym              # Symbol file for debugging constraints
│   ├── pot15_0000.ptau            \
│   ├── pot15_0001.ptau             > Powers-of-Tau trusted setup (phase 1)
│   ├── pot15_final.ptau            /
│   ├── circuit_0000.zkey          \
│   ├── circuit_final.zkey          > Circuit-specific Groth16 keys (phase 2)
│   └── verification_key.json      # Exported verification key (JSON)
│
├── contracts/
│   └── Verifier.sol             # Groth16 Solidity verifier, exported via snarkjs
│
├── artifacts/                   # Hardhat compilation output (generated)
├── cache/                       # Hardhat build cache (generated)
├── artifacts.d.ts
│
├── ignition/
│   └── modules/
│       └── Counter.ts           # Hardhat Ignition deployment module(s)
│
├── inputs/
│   ├── input.json               # Sample witness input
│   ├── input_tier1.json         # Sample input for Minimum-KYC tier
│   ├── input_fail.json          # Adversarial/negative input for testing rejections
│   ├── proof.json               # Example generated Groth16 proof
│   └── public.json              # Public signals accompanying proof.json
├── witness.wtns                 # Example computed witness
│
├── scripts/
│   ├── generate*.ts             # Witness / proof generation helper scripts
│   └── send-op-tx.ts            # Builds & submits an ERC-4337 UserOperation
│
├── test/
│   └── verify.ts                # On-chain / off-chain proof verification tests
│
├── types/ethers-contracts/      # Typechain-generated contract bindings
│   ├── factories/
│   ├── Groth16Verifier.ts
│   ├── common.ts
│   ├── hardhat.d.ts
│   └── index.ts
│
├── docs/
│   └── literature/               # Background reading, related-work material
│
├── .agents/skills/ , .claude/skills/   # Local AI-agent tooling skills (hardhat, hardhat-toolbox-mocha-ethers)
│
├── hardhat.config.ts
├── package.json / package-lock.json
├── tsconfig.json
├── AGENTS.md
├── README.md                    # ← you are here
│
├── Privacy-Preserving UPI Payment Tier Eligibility using ZKPs.pdf   # Full research paper
├── Regulatory Frameworks for Multi-Tier KYC for UPI.pdf              # Statute-to-predicate mapping doc
└── ZKP_eKYC_UPI_Slides.pdf                                            # Presentation deck
```

## Tech Stack

| Layer | Technology |
|---|---|
| Circuit language | [Circom 2.0.4](https://docs.circom.io/) + [circomlib](https://github.com/iden3/circomlib) |
| Proving system | Groth16 (`snarkjs`) over the `alt_bn128` curve |
| Hashing / signatures | Poseidon hash, EdDSA over Baby Jubjub |
| Revocation | `smtverifier.circom` (Sparse Merkle Tree, depth 20) |
| Smart contracts | Solidity, deployed via Hardhat + Hardhat Ignition |
| Account abstraction | ERC-4337 (`eth-infinitism` bundler, custom `KYCPaymaster.sol`) |
| Target network | Ethereum Sepolia testnet |
| Client | Progressive Web App, WebAuthn biometric key derivation, IndexedDB (AES-256-GCM), `snarkjs` WASM prover |
| Tooling | Hardhat, TypeScript, Typechain, `chai`/Mocha for test vectors |

## Getting Started

### Prerequisites

- Node.js (LTS) and npm
- [`circom`](https://docs.circom.io/getting-started/installation/) 2.0.4 installed and on `PATH`
- `snarkjs` (installed as a project dependency, also usable via `npx`)

### Installation

```bash
git clone <this-repo-url>
cd zkp-based-ekyc-ps1
npm install
```

### Compile the Hardhat project

```bash
npx hardhat compile
```

## Circuit Compilation & Trusted Setup

The circuit pipeline mirrors the process documented in the paper (Section VI-E). From
the repository root:

```bash
# 1. Compile the circuit to R1CS, WASM witness calculator, and symbol file
circom circuits/upi_tier.circom --r1cs --wasm --sym -o build/

# 2. Phase 1 — Powers of Tau (universal, curve-specific, one-time per circuit size)
npx snarkjs powersoftau new bn128 15 build/pot15_0000.ptau -v
npx snarkjs powersoftau contribute build/pot15_0000.ptau build/pot15_0001.ptau \
    --name="First contribution" -v
npx snarkjs powersoftau prepare phase2 build/pot15_0001.ptau build/pot15_final.ptau

# 3. Phase 2 — circuit-specific zKey generation
npx snarkjs groth16 setup build/upi_tier.r1cs build/pot15_final.ptau build/circuit_0000.zkey

# Apply a random beacon to finalize the phase-2 ceremony
npx snarkjs zkey beacon build/circuit_0000.zkey build/circuit_final.zkey \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 \
    -n="Final Beacon phase2"

# 4. Export the verification key and the Solidity verifier
npx snarkjs zkey export verificationkey build/circuit_final.zkey build/verification_key.json
npx snarkjs zkey export solidityverifier build/circuit_final.zkey contracts/Verifier.sol
```

> **Note on production deployment.** A single-machine trusted setup is fine for
> development. A real national-scale deployment would require a multi-party
> computation (MPC) ceremony analogous to the Zcash Sapling ceremony, with
> participation from RBI/NPCI, PSPs, and independent auditors — see the paper,
> Section VI-E.

## Generating and Verifying a Proof

```bash
# Compute the witness from a sample input
node build/upi_tier_js/generate_witness.js build/upi_tier_js/upi_tier.wasm \
    inputs/input.json witness.wtns

# Generate a Groth16 proof
npx snarkjs groth16 prove build/circuit_final.zkey witness.wtns \
    inputs/proof.json inputs/public.json

# Verify off-chain
npx snarkjs groth16 verify build/verification_key.json inputs/public.json inputs/proof.json
```

`inputs/input_tier1.json` exercises the Minimum-KYC path, and `inputs/input_fail.json`
is a deliberately invalid witness used to confirm the circuit correctly rejects
non-qualifying credentials.

## Smart Contracts & Gasless Verification

`contracts/Verifier.sol` is the `snarkjs`-exported Groth16 verifier for
`upi_tier.circom`. It is invoked either directly or through an ERC-4337
`UserOperation` so the end user pays no gas:

```bash
# Deploy via Hardhat Ignition
npx hardhat ignition deploy ignition/modules/Counter.ts --network sepolia

# Build and submit a gasless verification UserOperation
npx ts-node scripts/send-op-tx.ts

# Run the verification test suite
npx hardhat test test/verify.ts
```

## Test Vectors

The circuit is validated against twelve adversarial test vectors (Mocha/`chai`), each
checking that a specific manipulation of the witness is correctly rejected:

| Vector | Condition tested |
|---|---|
| Valid Full KYC | All 11 predicates satisfied |
| Age underflow | Finite-field wraparound attempt on `birthYear` |
| Minor applicant | Age below 18 |
| Signature forgery | Bit-flip in a leaf hash |
| Invalid document | `docType` outside the valid OVD range |
| Income tier bypass | Student income class claiming Full KYC |
| PEP evasion | PEP flag manipulated |
| Expired credential | Issuance year outside the 10-year window |
| Merkle path error | Invalid sibling hash for PAN inclusion |
| Revoked credential | Nullifier present in the SMT |
| Nonce mismatch | Cross-session replay attempt |
| Cooling-period breach | High-value transaction inside the 24-hour cooling window |

Every vector is expected to fail proof generation or rejected verification; none should
produce an accepting proof.

## Performance Benchmarks

| Metric | Value |
|---|---|
| R1CS constraints (Full KYC circuit) | ≈24,900 |
| R1CS constraints (Min KYC circuit) | ≈7,000 |
| Proof size | 1.5 KB (constant, Groth16) |
| Proof generation (desktop, e.g. Apple M2) | < 400 ms |
| Proof generation (mid-range Android WASM) | < 3 s |
| Off-chain verification | ≈100 ms |
| On-chain verification gas | ≈242,000 gas (dominated by the EIP-197 pairing precompile) |
| `.zkey` proving-key size | 42 MB (cached client-side via Service Worker) |

## Security Notes

- **Finite-field underflow protection.** All subtractions that could wrap around the
  BN128 scalar field (notably age computation) use a bit-decomposition-checked
  `SafeSubtraction` template rather than naive field subtraction.
- **Boolean flag hardening.** Signals such as the PEP flag are constrained with
  `val · (val − 1) ≡ 0` to prevent non-boolean values sneaking through arithmetic gates.
- **Unlinkability.** Random Groth16 blinding factors plus a salted, per-credential
  nullifier prevent a chain observer from correlating multiple proofs to one identity.
- **Trust assumptions.** The issuer is trusted to perform honest KYC and honest
  revocation reporting; the prover device is trusted only insofar as its OS/hardware
  enclave has not been compromised; the PSP/verifier is treated as fully untrusted with
  respect to personal data.
- This code implements the design described in the accompanying paper for research and
  demonstration purposes; it has **not** been independently audited and should not be
  treated as production-ready without a formal security review and a proper multi-party
  trusted-setup ceremony.

## Roadmap / Extensions

- **One credential, multiple products.** Reuse the same base credential Merkle tree and
  issuer signature to authorise NACH mandates, FASTag limits, RuPay Credit, and UPI One
  World transactions via dedicated extension circuits (see Table X in the paper).
- **Trustless issuance via Offline Aadhaar XML.** Parse UIDAI's signed Offline XML
  directly on-device and verify UIDAI's signature locally, removing the bank as an
  issuance intermediary.
- **Post-quantum migration.** Circuit-level predicate logic is proving-system-agnostic;
  a future backend migration from Groth16 to a STARK-based system (e.g. via Plonky2 or
  RISC Zero) would remove the trusted-setup requirement and add post-quantum security.

## Documentation

- **Full paper:** [`Privacy-Preserving UPI Payment Tier Eligibility using Zero-Knowledge Proofs...pdf`](./Privacy-Preserving_UPI_Payment_Tier_Eligibility_using_Zero_Knowledge_Proofs_A_Multi_Predicate_ZKProof_eKYC_Framework_for_India_s_Payment_Infrastructure.pdf)
- **Regulatory mapping reference:** [`Regulatory Frameworks for Multi-Tier KYC for UPI.pdf`](./Regulatory_Frameworks_for_Multi-Tier_KYC_for_UPI.pdf)
- **Slides:** `ZKP_eKYC_UPI_Slides.pdf`


## Authors

- **Tanishq Sahu** — Department of Computer Science, BITS Pilani, KK Birla Goa Campus (Corresponding author)
- **Dr. Puneet Bakshi** — Scientist F, Centre for Development of Advanced Computing (C-DAC), Pune
- **Pranali Nikam** — Project Engineer, Centre for Development of Advanced Computing (C-DAC), Pune

## Citation

```bibtex
@unpublished{sahu2026zkproofekyc,
  title  = {Privacy-Preserving UPI Payment Tier Eligibility using Zero-Knowledge
            Proofs: A Multi-Predicate ZKProof-eKYC Framework for India's Payment
            Infrastructure},
  author = {Sahu, Tanishq and Bakshi, Puneet and Nikam, Pranali},
  note   = {BITS Pilani, KK Birla Goa Campus and Centre for Development of Advanced
            Computing (C-DAC), Pune},
  year   = {2026}
}
```

## License

License to be determined by the authors. Until a `LICENSE` file is added, all rights
are reserved by the authors listed above.
