# 📈 Master Project Progress Log

This document tracks the chronological research, pivots, engineering milestones, and cryptographic implementations executed during the 7-week Practice School-I phase at CDAC Pune.

---

## 🛠️ Week 1: Domain Alignment, Cryptographic Foundations & Toolchain Setup
**Timeline:** Focus shifted from FinTech exploratory tracking to core Zero-Knowledge Cryptography implementation under Dr. Bakshi.

### 📋 Detailed Chronological Log

#### **Monday: Institutional Orientation & Cross-Domain Exposure**
* **Activities:** Attended the general orientation briefings detailing institutional protocols and technical expectations. 
* **Domain Selection:** Joined the FinTech research track alongside a 7-member peer cohort.
* **Brainstorming:** Engaged in an initial group brief with the domain mentor covering digital payment systems and decentralized financial networks. The mentor directed the cohort to spend 24 hours investigating open-ended friction points to propose viable problem statements.

#### **Tuesday: Feasibility Deadlocks & Exploratory Auditing**
* **Activities:** Conducted secondary market research into transaction clearing mechanics and fraud-detection loops. 
* **Evaluation:** Drafted structural workflows to evaluate project feasibility. Concluded that the immediate corporate directions lacked the deep architectural or mathematical complexity required for a high-impact engineering thesis.

#### **Wednesday: Pivot to Advanced Cryptography & Project Scoping**
* **Activities:** Formally shifted research domains after identifying an opportunity to work on bleeding-edge privacy infrastructure under Dr. Bakshi.
* **Consultation:** Initiated an engineering review with Dr. Bakshi focused on Zero-Knowledge Proofs (ZKPs) and privacy-preserving infrastructure for national identity systems.
* **Resource Allocation:** Finalized the core project scope: *Anchoring sovereign identity credentials to public ledgers using non-interactive zero-knowledge proofs*. Dr. Bakshi provisioned the initial research payload:
  * **4 Foundational Papers:** Covering selective data disclosure, zero-knowledge virtual machines (zkVMs), and secure state verification.
  * **2 Core Target Repositories:** Containing baseline verification implementations using domain-specific languages.

#### **Thursday: Academic Literature Review & Core Stack Benchmarking**
* **Activities:** Conducted a comprehensive deep dive into the provided literature, extracting state-of-the-art architectures for user-centric data sovereignty.
* **Stack Evaluation:** Audited the current landscape of Zero-Knowledge development frameworks to isolate appropriate tooling for client-side processing:
  * **Circom:** Selected for low-level, high-efficiency Rank-1 Constraint System (R1CS) arithmetic circuit construction.
  * **SnarkJS:** Selected for client-side JavaScript execution of trusted setups, witness generation, and Groth16 proof compilation.
  * **EZKL / zkVMs:** Evaluated for deep learning/general-purpose compute execution, but benched to prioritize direct credential field comparisons.

#### **Friday: Research Defense & Baseline Milestone Definition**
* **Activities:** Presented an architectural synthesis to Dr. Bakshi validating comprehension of the underlying mathematics (the interactions between Prover $\mathcal{P}$, Verifier $\mathcal{V}$, and the trusted parameters).
* **Milestone Assignment:** Authorized to proceed from theoretical analysis to applied systems engineering. Tasked with provisioning a functional Windows compilation layer and achieving 100% end-to-end execution (circuit compile $\rightarrow$ trusted setup $\rightarrow$ witness gen $\rightarrow$ proof generation $\rightarrow$ verify) for two distinct constraint scenarios.

#### **Saturday: Constraint Completion & Local Execution Verification**
* **Activities:** Resolved critical OS-level environment deadlocks to build the native Rust compiler toolchain. Engineered, compiled, and successfully verified proofs for:
  * `sum_to_12`: A flat arithmetic circuit testing constraint system consistency.
  * `age_18_check`: A comparative circuit incorporating `circomlib` components to validate identity boundaries without field leakage.
* *Note: Subsequent tasks assigned late Saturday regarding data ingestion formatting are deferred to the Week 2 log for structural clean-cut segmentation.*

---

### 🔍 Weekly Progress Summary & Technical Artifacts

| Milestone Target | Description | Technical Artifact / Outcome | Status |
| :--- | :--- | :--- | :---: |
| **Domain Realignment** | Pivot from broad FinTech tracking to Applied Cryptography research framework. | Approved project charter under Dr. Bakshi. | 🟢 Complete |
| **Literature Audit** | Synthesis of 4 academic research papers on selective identity disclosure. | Conceptual architecture models mapped out. | 🟢 Complete |
| **Compiler Provisioning** | Overcoming local Windows path limitations to compile the core Rust binary. | Functional environment verifying `circom --help`. | 🟢 Complete |
| **Circuit 1 Execution** | Complete execution pipeline of flat constraint system (`sum.circom`). | Generated local `proof.json`; verified `snarkJS: OK!`. | 🟢 Complete |
| **Circuit 2 Execution** | Path resolution (`-l node_modules`) and gate verification for `age.circom`. | Integrated `circomlib` comparators; validated logic. | 🟢 Complete |

> **Evaluator Note:** All generated cryptographic payloads, circuit codebases, and local execution verifications have been formatted to production standards and committed directly to the core engineering directories of this repository. Detailed LaTeX log source files are accessible within the `docs/` module.
