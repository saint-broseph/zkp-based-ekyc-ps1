# 📚 Technical Review: Multi-Framework Proving Paradigms & Circuit Soundness
**Reference Article:** [A Beginner's Intro to Coding Zero-Knowledge Proofs - Santiago Palladino](https://dev.to/spalladino/a-beginners-intro-to-coding-zero-knowledge-proofs-c56)  
**Implementation Directory:** `circuits/examples/rock_paper_scissors/`

---

## 🔬 Section 1: Architectural Foundations of zk-SNARKs

A **zk-SNARK** (Succinct Non-interactive ARgument of Knowledge) behaves as a cryptographic black box that decouples the execution of a program from its verification. The core value proposition relies on two structural properties:

* **Succinctness:** The proof payload size and the time required for verification remain small and constant, completely independent of the complexity of the underlying computation.
* **Non-interactivity:** Once a proof is generated, it can be evaluated asynchronously by any verifier (including an on-chain smart contract) without requiring back-and-forth interaction with the prover.

### Proving Flavors & Setup Ceremonies
The article highlights that different ZK backends trade architecture simplicity for configuration overhead:

| Proving Scheme | Trusted Setup Requirement | Proof Size / Verification Speed | Main Use Cases |
| :--- | :--- | :--- | :--- |
| **Groth16** | **Per-circuit ceremony** required. If the circuit code changes, a new setup is mandatory. | Minimal size, ultra-fast verification (optimized for EVM gas). | Tornado Cash, Identity protocols, e-KYC cores. |
| **PLONK Family** | **Universal ceremony** required once. Can be reused for any arbitrary circuit up to a size limit. | Slightly larger proof size and higher verification gas cost than Groth16. | Aztec Network, zk-Rollup infrastructures. |
| **STARKs** | **No trusted setup** required (transparent setup based on collision-resistant hashes). | Significantly larger proof sizes (kilobytes instead of bytes). | Starknet, high-throughput scaling rollups. |

---

## 🧮 Section 2: Finite Field Mechanics & Constraints

When writing code inside a zero-knowledge circuit, you do not operate on standard 32-bit or 64-bit integers. Instead, all variables are elements of a massive **Finite Field** defined by a large prime number ($p$). For the standard `bn128` elliptic curve used in Circom, this prime modulus is:

$$p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$$

### Implication for Circuit Design
Because all operations wrap around this modulus ($x + y \pmod p$), standard comparative behaviors do not exist out-of-the-box. For example, a value of $-1$ automatically translates to $p - 1$. 

To prevent integer wrap-around attacks and enforce strict thresholds (such as checking if a score is valid, or verifying an age condition in an identity contract), developers must manually implement **Bit-Decomposition**. This breaks a single field element down into its binary bit arrays to structurally lock its maximum bounds.

---

## 🧠 Section 3: The Dual-Brain System (Execution vs. Constraints)

Circom forces a hard conceptual separation between two independent layers of logic inside a single template: **Witness Generation** and **Constraint Compilation**.

```text
       ┌─────────────────────────────────────────────────────────┐
       │                 YOUR CIRCOM CODE MODULE                 │
       └────────────────────────────┬────────────────────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌─────────────────────────────────────┐   ┌─────────────────────────────────────┐
│ 1. THE EXECUTION BRAIN (Witness)    │   │ 2. THE CRYPTOGRAPHIC BRAIN          │
├─────────────────────────────────────┤   ├─────────────────────────────────────┤
│ • Evaluated at runtime.             │   │ • Evaluated at compile-time.        │
│ • Uses single arrow: <--            │   │ • Uses triple equals: ===           │
│ • Can execute non-linear hints:     │   │ • Strictly limited to R1CS equations│
│   division, loops, conditionals.    │   │   of the form: A * B = C            │
└─────────────────────────────────────┘   └─────────────────────────────────────┘
```
### 🔧 The Anatomy of Synthesis Sugaring

When you utilize the double arrow (`<==`), Circom splits it into both actions simultaneously:

```circom
x <== a * b;

It is parsed under the hood as:
* `x <-- a * b;` *(Hint to the witness calculator to compute the numerical value at runtime)*
* `x === a * b;` *(Instruction to the compiler to generate an R1CS constraint over the prime field)*

```

### ⚠️ Section 4: Underconstrained Computation Bugs

The core discrepancy between the Witness Generator and the Constraint Compiler creates the single most dangerous security vulnerability in ZK engineering: **Underconstrained Circuits**.

An underconstrained bug occurs when the witness generation logic computes a value correctly for an honest user, but the cryptographic constraint system fails to legally lock down all mathematical possibilities for that variable.

#### ⚔️ Attack Vector Walkthrough (Using an isolated `IsZero` component)
Imagine an identity or state lookup circuit that accidentally omits a final validation step:

```circom
// VULNERABLE CONCEPTUAL CODE
inv <-- in != 0 ? 1/in : 0;
out <-- -in * inv + 1;
out === -in * inv + 1;
// MISSING RULE: in * out === 0;
```

* **The Honest Execution:** An honest user passes `in = 3`. The witness calculator computes `inv = 1/3` and `out = 0`. The constraint `0 === -3 * (1/3) + 1` evaluates to `0 === 0`. The local test passes perfectly.
* **The Adversarial Exploitation:** A malicious user wants to trick the system into believing their input is `0` when it is actually `3`. They bypass the witness script entirely and manually forge a witness file matching these coordinates: `in = 3`, `inv = 0`, `out = 1`.
* **The Proof Forgery:** The proving engine checks the compiled constraint: `1 === -3 * 0 + 1` $\rightarrow$ `1 === 1`. The equation is perfectly satisfied. A valid cryptographic proof is minted, and the verifier accepts the forged state change as authentic.

---

### 🌪️ Section 5: Real-World Primitives (Tornado Cash & Nullifiers)

To illustrate these concepts in production, the article breaks down the architecture of privacy mixers like Tornado Cash, focusing on how state verification can occur without identity exposure.

```text
DEPOSIT PHASE:
[ User Secret (s) ] ──► Hash H(s) ──► Submitted to Smart Contract ──► Inserted into Merkle Tree Root (R)

WITHDRAWAL PHASE:
[ Private Input: s ] ──► Circuit validates H(s) exists in Merkle Tree Root (R)
                        └──► Circuit outputs Public Nullifier: G(s) ──► Checked against On-Chain Spent Set
```

#### 🔒 The Mechanics of the Double-Spend Protection
* **The Merkle Proof:** The user passes their secret signature $s$ as a private input to a circuit. The circuit computes $H(s)$ and mathematically checks the path up to a known public Merkle Root ($R$). This proves membership without revealing which leaf belongs to the user.
* **The Nullifier Primitive:** To prevent the user from withdrawing the same deposit multiple times, the circuit derives a deterministic Nullifier using a separate hash function: $G(s)$.
* **Smart Contract Verification:** The smart contract receives the zero-knowledge proof and the public output $G(s)$. It verifies the proof against Root $R$, and then checks its internal storage array to ensure $G(s)$ has not been registered before. If unique, the contract executes the payout and appends $G(s)$ to the spent index, permanently locking it.

---

### 🎮 Section 6: Rock-Paper-Scissors Constraint Implementation

To benchmark how these abstract concepts translate into physical code, this example directory implements the automated state verification circuit for a Rock-Paper-Scissors validation loop using pure R1CS field logic.

#### 1. Zero-Product Set Membership Mapping
Because relational operators like `if (x <= 2)` cannot be evaluated directly by a constraint compiler, we translate set validation into a polynomial equation. To force a private input signal $x$ to strictly match a valid game move choice (0 for Rock, 1 for Paper, 2 for Scissors), we execute a zero-product factorization:

$$x \cdot (x - 1) \cdot (x - 2) = 0$$

If $x$ is any integer outside that set, the product resolves to a non-zero element, immediately breaking the circuit constraints and preventing proof generation.

#### 2. Implementation File Roadmap
The working production code is fully contained within this directory:
* **Circuit Core Architecture:** `rps.circom` — Utilizes bitwise lookups and custom assignment validation pipelines.
* **Test Parameter Payload:** `input.json` — Simulates a verifiable draw condition matching identical private inputs.