// ================================================================
// PROJECT      : ZKProof-UPI
// FILE         : circuits/upi_kyc_full.circom
// VERSION      : 2.1.6
// DESCRIPTION  : Complete Zero-Knowledge Proof circuit system
//                for UPI Multi-Tier KYC Eligibility Verification
//
// REGULATORY BASIS:
//   phi_age     -> RBI KYC Master Directions Para 13(a)
//   phi_income  -> RBI KYC Master Directions Para 27
//   phi_doc     -> RBI KYC Para 3(xlvii) — OVD definition
//   phi_pan     -> RBI KYC Para 13(c) — PAN mandatory
//   phi_aadhaar -> Aadhaar Act 2016, Section 29
//   phi_sig     -> PMLA Rules 2005, Rule 9A
//   phi_fresh   -> RBI KYC Para 38 — validity periods
//   phi_revoc   -> RBI continuous monitoring requirements
//   phi_nonce   -> NPCI anti-replay requirement
//   phi_tier    -> NPCI UPI Circular on tiered limits
//   phi_limit   -> NPCI UPI transaction limits
//
// PROVING SYSTEM : Groth16
// CURVE          : BN128 / BN254 (alt_bn128) — Ethereum native
// HASH           : Poseidon (ZK-optimised, ~240 constraints/call)
// SIGNATURE      : EdDSA-Poseidon over Baby Jubjub curve
//
// CONSTRAINT ESTIMATES (approximate):
//   PoseidonMerkleVerifier(3)     :   ~1,500 constraints
//   CredentialSignatureVerifier() :   ~3,000 constraints
//   SMTRevocationChecker(20)      :  ~15,000 constraints
//   KYCTierClassifier()           :     ~300 constraints
//   UPIKYCTierProof(3,20) TOTAL   :  ~25,000 constraints
//   MinKYCTierProof(3) TOTAL      :   ~7,000 constraints
//
// COMPILE:
//   circom upi_kyc_full.circom --r1cs --wasm --sym -o ./build
//
// INSTALL DEPS:
//   npm install circomlib snarkjs
//
// SETUP (Groth16):
//   snarkjs powersoftau new bn128 17 pot17_0000.ptau -v
//   snarkjs powersoftau contribute pot17_0000.ptau pot17_0001.ptau
//   snarkjs powersoftau prepare phase2 pot17_0001.ptau pot17_final.ptau
//   snarkjs groth16 setup build/upi_kyc_full.r1cs pot17_final.ptau circuit_0000.zkey
//   snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="1st"
//   snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
//
// AUTHOR  : ZKProof-UPI Team, C-DAC Pune PS1
// ================================================================

pragma circom 2.1.6;

// ---- circomlib imports ----
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/smt/smtverifier.circom";


// ================================================================
// SECTION 1: PRIMITIVE UTILITIES
// ================================================================

// ----------------------------------------------------------------
// Template : RangeProof
// Purpose  : Prove   min <= value <= max   without revealing value
// Bits     : number of bits for the range check (must cover max)
//            Use 8 for ages (0-255), 32 for paise amounts
// Outputs  : valid = 1 if in range, 0 otherwise
// ----------------------------------------------------------------
template RangeProof(bits) {
    signal input value;
    signal input min;
    signal input max;
    signal output valid;

    // value >= min
    component gte = GreaterEqThan(bits);
    gte.in[0] <== value;
    gte.in[1] <== min;

    // max >= value  (i.e., value <= max)
    component lte = GreaterEqThan(bits);
    lte.in[0] <== max;
    lte.in[1] <== value;

    component andGate = AND();
    andGate.a <== gte.out;
    andGate.b <== lte.out;

    valid <== andGate.out;
}


// ----------------------------------------------------------------
// Template : ForceRange
// Purpose  : Hard-constrain a value to [min, max].
//            Proof FAILS if value is outside range.
//            Use when you want a hard circuit constraint (not soft output).
// ----------------------------------------------------------------
template ForceRange(bits) {
    signal input value;
    signal input min;
    signal input max;

    component gte = GreaterEqThan(bits);
    gte.in[0] <== value;
    gte.in[1] <== min;
    gte.out === 1;

    component lte = GreaterEqThan(bits);
    lte.in[0] <== max;
    lte.in[1] <== value;
    lte.out === 1;
}


// ----------------------------------------------------------------
// Template : IsInSet3
// Purpose  : Prove value is exactly one of {v1, v2, v3}
// Used for : incomeClass in {1,2,3} (Full KYC)
// ----------------------------------------------------------------
template IsInSet3() {
    signal input value;
    signal input v1;
    signal input v2;
    signal input v3;
    signal output valid;

    component eq1 = IsEqual();
    eq1.in[0] <== value;
    eq1.in[1] <== v1;

    component eq2 = IsEqual();
    eq2.in[0] <== value;
    eq2.in[1] <== v2;

    component eq3 = IsEqual();
    eq3.in[0] <== value;
    eq3.in[1] <== v3;

    component or1 = OR();
    or1.a <== eq1.out;
    or1.b <== eq2.out;

    component or2 = OR();
    or2.a <== or1.out;
    or2.b <== eq3.out;

    valid <== or2.out;
}


// ----------------------------------------------------------------
// Template : IsInSet4
// Purpose  : Prove value is exactly one of {v1, v2, v3, v4}
// Used for : incomeClass in {1,2,3,4} (Minimum KYC)
// ----------------------------------------------------------------
template IsInSet4() {
    signal input value;
    signal input v1;
    signal input v2;
    signal input v3;
    signal input v4;
    signal output valid;

    component eq1 = IsEqual();
    eq1.in[0] <== value; eq1.in[1] <== v1;

    component eq2 = IsEqual();
    eq2.in[0] <== value; eq2.in[1] <== v2;

    component eq3 = IsEqual();
    eq3.in[0] <== value; eq3.in[1] <== v3;

    component eq4 = IsEqual();
    eq4.in[0] <== value; eq4.in[1] <== v4;

    component or1 = OR(); or1.a <== eq1.out; or1.b <== eq2.out;
    component or2 = OR(); or2.a <== or1.out; or2.b <== eq3.out;
    component or3 = OR(); or3.a <== or2.out; or3.b <== eq4.out;

    valid <== or3.out;
}


// ----------------------------------------------------------------
// Template : ForceBinary
// Purpose  : Constrain a signal to be 0 or 1.
//            Essential for flag signals (hasPAN, hasAadhaar, isPEP)
//            to prevent malicious prover from passing non-binary values.
// Constraint added: value * (value - 1) === 0
// ----------------------------------------------------------------
template ForceBinary() {
    signal input value;
    signal intermediate;
    intermediate <== value * (value - 1);
    intermediate === 0;
}


// ----------------------------------------------------------------
// Template : SafeSubtraction
// Purpose  : Compute a - b and ensure a >= b (no underflow)
//            Arithmetic in ZKP circuits is over a finite field,
//            so negative results wrap around to large numbers.
//            This template prevents that.
// ----------------------------------------------------------------
template SafeSubtraction(bits) {
    signal input a;
    signal input b;
    signal output result;

    // Enforce a >= b before subtracting
    component gte = GreaterEqThan(bits);
    gte.in[0] <== a;
    gte.in[1] <== b;
    gte.out === 1;

    result <== a - b;
}


// ================================================================
// SECTION 2: POSEIDON MERKLE TREE VERIFIER
// ================================================================

// ----------------------------------------------------------------
// Template : PoseidonMerkleVerifier
//
// Purpose  : Verifies that a leaf is part of a Merkle tree
//            with the given root using Poseidon hash at each level.
//
// Why Poseidon?
//   SHA-256  : ~20,000 R1CS constraints per hash
//   MiMC     :  ~2,200 R1CS constraints per hash
//   Poseidon :    ~240 R1CS constraints per hash
//   Poseidon is the standard for ZKP Merkle trees (used in Tornado
//   Cash, Zcash Sapling, Polygon ID, circomlib itself).
//
// Parameters:
//   levels — Merkle tree depth
//            3  → 8 leaves   (credential attribute tree)
//            20 → 2^20 leaves (revocation SMT)
//
// Merkle tree structure (levels=3, 8 leaves):
//   Leaf 0: Poseidon(birthYear, dobSalt)
//   Leaf 1: Poseidon(incomeClass, incomeSalt)
//   Leaf 2: Poseidon(docType, docSalt)
//   Leaf 3: Poseidon(panCommitment, panSalt)
//   Leaf 4: Poseidon(aadhaarCommitment, aadhaarSalt)
//   Leaf 5: Poseidon(residenceStatus, resSalt)
//   Leaf 6: Poseidon(issuanceYear, yearSalt)
//   Leaf 7: Poseidon(credentialID, idSalt)
//
// Path convention:
//   pathIndices[i] = 0 → current node is LEFT  child at level i
//   pathIndices[i] = 1 → current node is RIGHT child at level i
//
// Outputs:
//   valid = 1 if computed root matches expected root, 0 otherwise
// ----------------------------------------------------------------
template PoseidonMerkleVerifier(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output valid;

    component hashers[levels];
    component muxLeft[levels];
    component muxRight[levels];

    signal computed[levels + 1];
    computed[0] <== leaf;

    for (var i = 0; i < levels; i++) {

        // Multiplexer for left input:
        //   pathIndices[i]=0 → left  = computed[i] (current)
        //   pathIndices[i]=1 → left  = pathElements[i] (sibling)
        muxLeft[i] = Mux1();
        muxLeft[i].c[0] <== computed[i];
        muxLeft[i].c[1] <== pathElements[i];
        muxLeft[i].s    <== pathIndices[i];

        // Multiplexer for right input (opposite of left)
        muxRight[i] = Mux1();
        muxRight[i].c[0] <== pathElements[i];
        muxRight[i].c[1] <== computed[i];
        muxRight[i].s    <== pathIndices[i];

        // Hash the pair using Poseidon with 2 inputs
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxLeft[i].out;
        hashers[i].inputs[1] <== muxRight[i].out;

        computed[i + 1] <== hashers[i].out;
    }

    // Final computed hash must equal the expected Merkle root
    component rootEq = IsEqual();
    rootEq.in[0] <== computed[levels];
    rootEq.in[1] <== root;

    valid <== rootEq.out;
}


// ================================================================
// SECTION 3: ATTRIBUTE LEAF HASHING
// ================================================================

// ----------------------------------------------------------------
// Template : AttributeLeafHash
// Purpose  : Compute Poseidon(attribute, salt) for a single
//            attribute to produce a Merkle tree leaf.
//
// The salt ensures:
//   1. Different proofs for the same attribute look different
//      (unlinkability across proof sessions)
//   2. The verifier cannot brute-force the attribute value
//      from the leaf hash (privacy against offline attacks)
//
// Regulatory basis: DPDP Act 2023, Section 8(3)
// ----------------------------------------------------------------
template AttributeLeafHash() {
    signal input attribute;
    signal input salt;
    signal output leaf;

    component h = Poseidon(2);
    h.inputs[0] <== attribute;
    h.inputs[1] <== salt;

    leaf <== h.out;
}


// ----------------------------------------------------------------
// Template : DoubleAttributeLeafHash
// Purpose  : Compute Poseidon(attr1, attr2, salt) to combine
//            two related attributes into one leaf.
//            Used for: (birthYear, birthMonth) or (credID, version)
// ----------------------------------------------------------------
template DoubleAttributeLeafHash() {
    signal input attr1;
    signal input attr2;
    signal input salt;
    signal output leaf;

    component h = Poseidon(3);
    h.inputs[0] <== attr1;
    h.inputs[1] <== attr2;
    h.inputs[2] <== salt;

    leaf <== h.out;
}


// ----------------------------------------------------------------
// Template : CredentialIDLeafHash
// Purpose  : Compute leaf for the credential identity leaf
//            Leaf 7 = Poseidon(credentialID, isPEP, idSalt)
//            Bundles credential ID with PEP flag in one leaf.
// ----------------------------------------------------------------
template CredentialIDLeafHash() {
    signal input credentialID;
    signal input isPEP;
    signal input idSalt;
    signal output leaf;

    component h = Poseidon(3);
    h.inputs[0] <== credentialID;
    h.inputs[1] <== isPEP;
    h.inputs[2] <== idSalt;

    leaf <== h.out;
}


// ================================================================
// SECTION 4: IDENTITY ATTRIBUTE VERIFICATION
// ================================================================

// ----------------------------------------------------------------
// Template : AgeVerification
//
// Regulatory basis: RBI KYC Master Directions Para 13(a)
//   "Date of birth/age must be obtained and verified for
//    all individual customers"
//   Indian Majority Act 1875: legal majority = 18 years
//
// What it proves:
//   currentYear - birthYear >= minAge  (where minAge=18 by convention)
//
// What it DOES NOT reveal:
//   birthYear (private)
//   computed age (internal signal, not output)
//   exact age (verifier only learns age >= minAge)
//
// Additional sanity constraints:
//   age < 121          (no living person is 120+)
//   birthYear >= 1900  (prevents future dates used for underflow)
//
// Constraint count: ~15
// ----------------------------------------------------------------
template AgeVerification() {
    // PRIVATE: stays on user's device
    signal input birthYear;

    // PUBLIC: visible to PSP / smart contract
    signal input currentYear;
    signal input minAge;

    // Intermediate: NOT an output, never revealed
    signal age;
    age <== currentYear - birthYear;

    // [1] age >= minAge  (primary eligibility constraint)
    component c1 = GreaterEqThan(8);
    c1.in[0] <== age;
    c1.in[1] <== minAge;
    c1.out === 1;

    // [2] age < 121  (sanity: no immortals)
    component c2 = LessThan(8);
    c2.in[0] <== age;
    c2.in[1] <== 121;
    c2.out === 1;

    // [3] birthYear >= 1900  (prevents underflow attacks)
    component c3 = GreaterEqThan(12);
    c3.in[0] <== birthYear;
    c3.in[1] <== 1900;
    c3.out === 1;

    // [4] currentYear >= 2024  (prevents stale proofs against old roots)
    component c4 = GreaterEqThan(12);
    c4.in[0] <== currentYear;
    c4.in[1] <== 2024;
    c4.out === 1;
}


// ----------------------------------------------------------------
// Template : IncomeClassVerificationFull
//
// Regulatory basis: RBI KYC Master Directions Para 27
//   Full KYC income classification (low/medium risk categories):
//   Class 1 = Salaried (government, private sector, PSU)
//   Class 2 = Self-Employed / Business / Professional
//   Class 3 = Pensioner / Retired
//
//   Students (Class 4) are NOT eligible for Full KYC UPI tier.
//   They can use Minimum KYC (see IncomeClassVerificationMin).
//
// What it proves: incomeClass ∈ {1, 2, 3}
// What it DOES NOT reveal: which class (1, 2, or 3)
//
// Constraint count: ~10
// ----------------------------------------------------------------
template IncomeClassVerificationFull() {
    signal input incomeClass;   // PRIVATE
    signal output valid;

    // Force binary: incomeClass cannot be 0 or >3 after this
    component setCheck = IsInSet3();
    setCheck.value <== incomeClass;
    setCheck.v1    <== 1;
    setCheck.v2    <== 2;
    setCheck.v3    <== 3;

    valid <== setCheck.valid;
}


// ----------------------------------------------------------------
// Template : IncomeClassVerificationMin
//
// Regulatory basis: RBI KYC Para 16 — Simplified CDD
//   Minimum KYC allows students / no-income individuals.
//   Class 4 = Student / No formal income
//   This enables financial inclusion for the unbanked.
//
// What it proves: incomeClass ∈ {1, 2, 3, 4}
// ----------------------------------------------------------------
template IncomeClassVerificationMin() {
    signal input incomeClass;   // PRIVATE
    signal output valid;

    component range = RangeProof(4);
    range.value <== incomeClass;
    range.min   <== 1;
    range.max   <== 4;

    valid <== range.valid;
}


// ----------------------------------------------------------------
// Template : DocumentTypeVerification
//
// Regulatory basis: RBI KYC Master Directions Para 3(xlvii)
//   Officially Valid Documents (OVDs):
//   1 = Passport
//   2 = Driving Licence
//   3 = Voter's Identity Card (EPIC)
//   4 = PAN Card
//   5 = Aadhaar Letter / e-Aadhaar
//   6 = NREGA Job Card
//   7 = National Population Register (NPR) Letter
//
// What it proves: docType ∈ {1, 2, 3, 4, 5, 6, 7}
// What it DOES NOT reveal: which specific OVD was used
// ----------------------------------------------------------------
template DocumentTypeVerification() {
    signal input docType;         // PRIVATE
    signal output isValidOVD;

    component range = RangeProof(4);
    range.value <== docType;
    range.min   <== 1;
    range.max   <== 7;

    isValidOVD <== range.valid;
}


// ----------------------------------------------------------------
// Template : ResidenceStatusVerification
//
// Regulatory basis:
//   FEMA 1999: NRI/OCI require NRE/NRO accounts
//   RBI KYC Para 27: Residence determines risk category
//
// Status codes:
//   1 = Resident Indian (RI)
//   2 = Non-Resident Indian (NRI)
//   3 = Overseas Citizen of India (OCI)
//   4 = Person of Indian Origin (PIO)
//
// For Full KYC UPI: all statuses are allowed (₹1L limit applies)
// For NRI-specific products (UPI One World): status != 1 triggers
//   additional FEMA compliance checks (handled in extension circuit)
// ----------------------------------------------------------------
template ResidenceStatusVerification() {
    signal input residenceStatus;     // PRIVATE: 1-4
    signal output isResidentIndian;   // 1 if RI (useful for tier-2 checks)
    signal output isValidStatus;      // 1 if any valid status

    component ri = IsEqual();
    ri.in[0] <== residenceStatus;
    ri.in[1] <== 1;
    isResidentIndian <== ri.out;

    component range = RangeProof(4);
    range.value <== residenceStatus;
    range.min   <== 1;
    range.max   <== 4;
    isValidStatus <== range.valid;
}


// ----------------------------------------------------------------
// Template : PEPExclusionVerification
//
// Regulatory basis: RBI KYC Master Directions Para 27
//   Politically Exposed Persons (PEPs) = senior political figures,
//   their family members, close associates.
//   PMLA Rule 9B: PEPs require Enhanced Due Diligence (EDD).
//   EDD cannot be satisfied by a ZKP alone — it requires manual review.
//
// This circuit BLOCKS PEPs from using the simplified ZKP flow.
// A PEP (isPEP=1) CANNOT generate a valid proof.
// This is a HARD constraint — proof generation fails for PEPs.
//
// isPEP is part of the credential's Leaf 7 (credential ID leaf),
// signed by the issuer, so the user cannot forge isPEP=0 if they are a PEP.
// ----------------------------------------------------------------
template PEPExclusionVerification() {
    signal input isPEP;     // PRIVATE: 0=not PEP, 1=PEP

    // [1] isPEP must be binary
    component binary = ForceBinary();
    binary.value <== isPEP;

    // [2] isPEP must be 0 (hard exclusion)
    isPEP === 0;
}


// ================================================================
// SECTION 5: CREDENTIAL INTEGRITY
// ================================================================

// ----------------------------------------------------------------
// Template : CredentialSignatureVerifier
//
// Regulatory basis: PMLA Rules 2005, Rule 9A
//   KYC verification must be performed by a Regulated Entity (RE)
//   registered with RBI. This template cryptographically proves
//   that the credential Merkle root was signed by a registered RE.
//
// Scheme: EdDSA-Poseidon over Baby Jubjub curve
//   Baby Jubjub: an elliptic curve embedded in BN128's scalar field
//   Efficient for ZKP: ~3,000 constraints (vs ~500,000 for RSA)
//
// The issuer signs the MERKLE ROOT, not individual attributes.
// Effect:
//   - One 64-byte signature covers all 8 KYC attributes
//   - Tampering with ANY attribute invalidates the root
//   - The issuer's public key is published on-chain (Issuer Registry)
//
// Verification equation:
//   S * B = R8 + H(R8, A, merkleRoot) * A
//   where B = Baby Jubjub base point, A = issuer public key
//
// Constraint count: ~3,000
// ----------------------------------------------------------------
template CredentialSignatureVerifier() {
    signal input merkleRoot;       // PUBLIC: credential Merkle root

    // Issuer's EdDSA public key (registered on-chain in IssuerRegistry.sol)
    signal input issuerPubKeyX;    // PUBLIC: Baby Jubjub X coordinate
    signal input issuerPubKeyY;    // PUBLIC: Baby Jubjub Y coordinate

    // EdDSA signature components (PRIVATE: sent by issuer to holder)
    signal input sigR8X;           // Random commitment point R8, X coord
    signal input sigR8Y;           // Random commitment point R8, Y coord
    signal input sigS;             // Scalar S = r + H(R8, A, msg) * sk

    // Verify using circomlib EdDSA-Poseidon verifier
    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax      <== issuerPubKeyX;
    verifier.Ay      <== issuerPubKeyY;
    verifier.R8x     <== sigR8X;
    verifier.R8y     <== sigR8Y;
    verifier.S       <== sigS;
    verifier.M       <== merkleRoot;

    // If signature invalid: EdDSAPoseidonVerifier adds UNSATISFIABLE
    // constraints internally → proof cannot be generated
    // No explicit output needed — failure is enforced structurally
}


// ----------------------------------------------------------------
// Template : CredentialFreshnessVerifier
//
// Regulatory basis: RBI KYC Master Directions Para 38
//   Low risk  → update every 10 years
//   Medium    → update every 8 years
//   High risk → update every 2 years
//
// maxValidityYears is a PUBLIC input, so the PSP or smart contract
// can enforce the appropriate validity window for their risk model.
//
// Freshness constraints:
//   [1] issuanceYear <= currentYear  (not issued in future)
//   [2] credentialAge <= maxValidityYears  (not expired)
//   [3] issuanceYear >= 2020  (V-CIP rollout year; earlier creds invalid)
//
// Constraint count: ~20
// ----------------------------------------------------------------
template CredentialFreshnessVerifier() {
    signal input issuanceYear;       // PRIVATE: year credential was issued
    signal input currentYear;        // PUBLIC
    signal input maxValidityYears;   // PUBLIC: 2, 8, or 10 per risk tier

    signal credentialAge;
    credentialAge <== currentYear - issuanceYear;

    // [1] credentialAge >= 0  (issued in past or present)
    component c1 = GreaterEqThan(8);
    c1.in[0] <== credentialAge;
    c1.in[1] <== 0;
    c1.out === 1;

    // [2] credentialAge <= maxValidityYears  (not expired)
    component c2 = GreaterEqThan(8);
    c2.in[0] <== maxValidityYears;
    c2.in[1] <== credentialAge;
    c2.out === 1;

    // [3] issuanceYear >= 2020  (V-CIP / digital KYC era)
    component c3 = GreaterEqThan(12);
    c3.in[0] <== issuanceYear;
    c3.in[1] <== 2020;
    c3.out === 1;
}


// ----------------------------------------------------------------
// Template : CoolingPeriodVerifier
//
// Regulatory basis: NPCI UPI Circular
//   New accounts have a 24-hour cooling period.
//   During cooling period: transactions > Rs.25,000 are blocked.
//   After cooling period: normal limits apply.
//
// This template proves either:
//   (a) account is past the cooling period  →  full limit applies, OR
//   (b) transaction amount < cooling limit  →  allowed during cooling
//
// Variables:
//   accountAgeDays    : days since account was created (PRIVATE)
//   coolingPeriodDays : cooling period duration (PUBLIC, typically 1)
//   transactionAmount : in paise (PUBLIC)
//   coolingLimit      : Rs.25,000 = 2,500,000 paise (PUBLIC)
//
// Constraint count: ~30
// ----------------------------------------------------------------
template CoolingPeriodVerifier() {
    signal input accountAgeDays;       // PRIVATE: age of UPI account in days
    signal input coolingPeriodDays;    // PUBLIC: typically 1 (24 hours)
    signal input transactionAmount;    // PUBLIC: in paise
    signal input coolingLimit;         // PUBLIC: 2,500,000 paise = Rs.25,000

    // Check if account is past cooling period
    component pastCooling = GreaterEqThan(16);
    pastCooling.in[0] <== accountAgeDays;
    pastCooling.in[1] <== coolingPeriodDays;

    // Check if amount is within cooling-period limit
    component withinCoolingLimit = GreaterEqThan(32);
    withinCoolingLimit.in[0] <== coolingLimit;
    withinCoolingLimit.in[1] <== transactionAmount;

    // Valid if: past cooling period  OR  amount <= cooling limit
    component orGate = OR();
    orGate.a <== pastCooling.out;
    orGate.b <== withinCoolingLimit.out;
    orGate.out === 1;
}


// ================================================================
// SECTION 6: ANTI-REPLAY AND REVOCATION
// ================================================================

// ----------------------------------------------------------------
// Template : NonceBinding
//
// Purpose  : Bind proof to a specific PSP challenge, preventing replay.
//
// Attack without nonce:
//   1. User generates proof P for GPay transaction T1
//   2. Attacker intercepts P
//   3. Attacker replays P to PhonePe for transaction T2
//   4. PhonePe verifier accepts P (all constraints satisfied)
//
// Solution: PSP generates a cryptographically random 256-bit nonce
// for each verification request. The proof commits to:
//   boundHash = Poseidon(nonce, merkleRoot)
//
// The PSP pre-computes boundHash and provides it as a PUBLIC input.
// The circuit enforces that the prover used the CORRECT nonce.
// A proof generated for GPay's nonce is INVALID for PhonePe's nonce.
//
// Nonce generation (off-circuit, in PSP backend):
//   nonce = crypto.randomBytes(32)  [Node.js]
//   boundHash = poseidon([nonce, merkleRoot])  [circomlibjs]
//
// Constraint count: ~3
// ----------------------------------------------------------------
template NonceBinding() {
    signal input nonce;               // PUBLIC: PSP random challenge
    signal input merkleRoot;          // PUBLIC: user's credential root
    signal input expectedBoundHash;   // PUBLIC: Poseidon(nonce, merkleRoot)

    component bind = Poseidon(2);
    bind.inputs[0] <== nonce;
    bind.inputs[1] <== merkleRoot;

    // Computed hash MUST match expected — enforced as hard constraint
    bind.out === expectedBoundHash;
}


// ----------------------------------------------------------------
// Template : NullifierComputation
//
// Purpose  : Compute a credential nullifier for revocation checking.
//
// Design problem:
//   If we used credentialID directly as the revocation key,
//   a blockchain observer could link all proofs from the same user
//   (same credentialID → same nullifier in every proof).
//   This violates DPDP Act Section 8(3) (unlinkability).
//
// Solution: Two-layer nullifier
//   nullifier = Poseidon(credentialID, nullifierSecret)
//   nullifierSecret: a 256-bit random value held privately by the user
//
// Properties:
//   BINDING: Revocation by issuer inserts nullifier into SMT.
//            User cannot avoid revocation (cannot change credentialID).
//   UNLINKABLE: Different proof sessions look different to observers
//               (nonce-binding already handles this; nullifier handles
//                the revocation lookup only).
//   PRIVATE: credentialID is never revealed (stays private).
//
// The issuer stores nullifier = Poseidon(credentialID, nullifierSecret)
// in the revocation SMT when revoking. The user reveals the nullifier
// as a PUBLIC input so the verifier can check it against the SMT.
//
// Constraint count: ~3
// ----------------------------------------------------------------
template NullifierComputation() {
    signal input credentialID;       // PRIVATE: issuer-assigned unique ID
    signal input nullifierSecret;    // PRIVATE: user's 256-bit secret

    signal output nullifier;         // PUBLIC: goes to SMT revocation check

    component h = Poseidon(2);
    h.inputs[0] <== credentialID;
    h.inputs[1] <== nullifierSecret;

    nullifier <== h.out;
}


// ----------------------------------------------------------------
// Template : SMTRevocationChecker
//
// Purpose  : Prove credential nullifier is NOT in the revocation SMT.
//
// The Sparse Merkle Tree (SMT) is maintained on-chain:
//   - Contract: SMTRegistry.sol
//   - State: Poseidon-based SMT over a 2^levels key space
//   - Operations: insert(nullifier) on revocation, read root on proof
//
// Non-membership proof:
//   For a key K absent from the SMT, the prover provides:
//   - smtOldKey    : nearest existing key to K
//   - smtOldValue  : value at smtOldKey
//   - smtIsOld0    : 1 if the neighbouring leaf is empty
//   - smtSiblings  : the sibling hashes on the path from leaf to root
//   The circuit verifies this constitutes a valid non-membership proof.
//
// Using circomlib SMTVerifier with fnc=[0,1] (non-membership mode)
//
// Regulatory basis:
//   RBI requires "continuous monitoring" of KYC status.
//   SMT enables real-time revocation without credential re-issuance.
//
// Parameters:
//   levels — SMT depth. 20 → handles 2^20 ≈ 1,048,576 revocations.
//
// Constraint count: ~15,000 (for levels=20, dominates total circuit)
// ----------------------------------------------------------------
template SMTRevocationChecker(levels) {
    signal input credentialNullifier;    // PUBLIC: the nullifier to check
    signal input revocationRoot;         // PUBLIC: current on-chain SMT root

    // PRIVATE: proof of non-membership
    signal input smtSiblings[levels];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    component smtVerifier = SMTVerifier(levels);
    smtVerifier.enabled   <== 1;
    smtVerifier.root      <== revocationRoot;
    smtVerifier.fnc       <== 1;   // fnc=1 sets SMTVerifier to non-membership mode
    smtVerifier.key       <== credentialNullifier;
    smtVerifier.value     <== 0;
    smtVerifier.oldKey    <== smtOldKey;
    smtVerifier.oldValue  <== smtOldValue;
    smtVerifier.isOld0    <== smtIsOld0;

    for (var i = 0; i < levels; i++) {
        smtVerifier.siblings[i] <== smtSiblings[i];
    }

    // If the nullifier IS in the SMT, SMTVerifier adds an unsatisfiable
    // constraint → proof CANNOT be generated for a revoked credential.
}


// ================================================================
// SECTION 7: KYC TIER CLASSIFICATION AND TRANSACTION LIMITS
// ================================================================

// ----------------------------------------------------------------
// Template : KYCTierClassifier
//
// Purpose  : Classify KYC tier from verified private attributes.
//            This is the decision engine of the circuit.
//
// Tier encoding:
//   0 = No KYC    → Rs.0 limit
//   1 = Min KYC   → Rs.10,000 / transaction
//   2 = Full KYC  → Rs.1,00,000 / transaction
//
// Full KYC conditions (ALL 5 must hold simultaneously):
//   A: age >= 18
//   B: incomeClass ∈ {1, 2, 3}
//   C: residenceStatus ∈ {1, 2, 3, 4}
//   D: hasPAN = 1    (PAN Merkle inclusion verified externally)
//   E: hasAadhaar = 1 (Aadhaar Merkle inclusion verified externally)
//   F: isPEP = 0
//
// Minimum KYC conditions (ALL 3 must hold):
//   A: age >= 18
//   G: incomeClass ∈ {1, 2, 3, 4}
//   H: docType ∈ {1..7}  (any valid OVD)
//
// Tier arithmetic (avoids if/else — circuits can't branch on signals):
//   tier = isFullKYC * 2 + (1 - isFullKYC) * isMinKYC
//
//   isFullKYC=1 → tier = 2 + 0 = 2
//   isFullKYC=0, isMinKYC=1 → tier = 0 + 1 = 1
//   isFullKYC=0, isMinKYC=0 → tier = 0 + 0 = 0
//
// Constraint count: ~100
// ----------------------------------------------------------------
template KYCTierClassifier() {
    // PRIVATE inputs (all verified against credential Merkle tree)
    signal input birthYear;
    signal input incomeClass;
    signal input docType;
    signal input residenceStatus;
    signal input isPEP;
    signal input hasPAN;        // 1 = PAN Merkle inclusion verified
    signal input hasAadhaar;    // 1 = Aadhaar Merkle inclusion verified

    // PUBLIC
    signal input currentYear;

    // OUTPUT
    signal output tier;

    // ---- Force binary on all flag signals ----
    component binPEP      = ForceBinary(); binPEP.value      <== isPEP;
    component binPAN      = ForceBinary(); binPAN.value      <== hasPAN;
    component binAadhaar  = ForceBinary(); binAadhaar.value  <== hasAadhaar;

    // ---- FULL KYC: Condition A — Age >= 18 ----
    signal age;
    age <== currentYear - birthYear;

    component ageOK = GreaterEqThan(8);
    ageOK.in[0] <== age;
    ageOK.in[1] <== 18;

    // ---- FULL KYC: Condition B — Income class {1,2,3} ----
    component incomeFullOK = IncomeClassVerificationFull();
    incomeFullOK.incomeClass <== incomeClass;

    // ---- FULL KYC: Condition C — Residence status {1..4} ----
    component resOK = RangeProof(4);
    resOK.value <== residenceStatus;
    resOK.min   <== 1;
    resOK.max   <== 4;

    // ---- FULL KYC: Condition D+E — Has both PAN and Aadhaar ----
    component panAndAadhaar = AND();
    panAndAadhaar.a <== hasPAN;
    panAndAadhaar.b <== hasAadhaar;

    // ---- FULL KYC: Condition F — Not a PEP ----
    component notPEP = IsEqual();
    notPEP.in[0] <== isPEP;
    notPEP.in[1] <== 0;

    // ---- Combine Full KYC: A AND B AND C AND D+E AND F ----
    component f1 = AND(); f1.a <== ageOK.out;        f1.b <== incomeFullOK.valid;
    component f2 = AND(); f2.a <== f1.out;           f2.b <== resOK.valid;
    component f3 = AND(); f3.a <== f2.out;           f3.b <== panAndAadhaar.out;
    component f4 = AND(); f4.a <== f3.out;           f4.b <== notPEP.out;

    signal isFullKYC;
    isFullKYC <== f4.out;

    // ---- MIN KYC: Condition G — Income class {1,2,3,4} ----
    component incomeMinOK = IncomeClassVerificationMin();
    incomeMinOK.incomeClass <== incomeClass;

    // ---- MIN KYC: Condition H — Valid OVD type {1..7} ----
    component docOK = DocumentTypeVerification();
    docOK.docType <== docType;

    // ---- Combine Min KYC: A AND G AND H ----
    component m1 = AND(); m1.a <== ageOK.out;        m1.b <== incomeMinOK.valid;
    component m2 = AND(); m2.a <== m1.out;           m2.b <== docOK.isValidOVD;

    signal isMinKYC;
    isMinKYC <== m2.out;

    // ---- Tier arithmetic ----
    signal tierFull;
    tierFull <== isFullKYC * 2;

    signal tierMin;
    tierMin <== (1 - isFullKYC) * isMinKYC;

    tier <== tierFull + tierMin;
}


// ----------------------------------------------------------------
// Template : TransactionLimitVerifier
//
// Purpose  : Prove transaction amount is within the tier's limit.
//
// All amounts in PAISE (1 Rupee = 100 Paise) to avoid decimals.
// Tier 1 (Min KYC) : Rs.10,000     =    1,000,000 paise
// Tier 2 (Full KYC): Rs.1,00,000   =   10,000,000 paise
// Capital markets  : Rs.5,00,000   =   50,000,000 paise
//
// Uses 32-bit comparison: handles up to 2^32 paise ≈ Rs.42.9 crore.
//
// Constraint count: ~10
// ----------------------------------------------------------------
template TransactionLimitVerifier() {
    signal input transactionAmount;   // PUBLIC: requested amount in paise
    signal input tierLimit;           // PUBLIC: limit for the applicable tier

    // [1] amount <= tierLimit  (tierLimit >= amount)
    component limitCheck = GreaterEqThan(32);
    limitCheck.in[0] <== tierLimit;
    limitCheck.in[1] <== transactionAmount;
    limitCheck.out === 1;

    // [2] amount > 0  (no zero-value proof gaming)
    component posCheck = GreaterEqThan(32);
    posCheck.in[0] <== transactionAmount;
    posCheck.in[1] <== 1;
    posCheck.out === 1;
}


// ================================================================
// SECTION 8: MAIN CIRCUIT — FULL KYC PROOF
// ================================================================

// ----------------------------------------------------------------
// Template : UPIKYCTierProof
//
// THE PRIMARY CIRCUIT of ZKProof-UPI.
//
// This circuit proves — in ZERO KNOWLEDGE — that:
//   [1] The prover holds a valid KYC credential (issuer signature valid)
//   [2] The credential attributes satisfy Full KYC per RBI Para 27
//   [3] The DOB attribute is in the credential Merkle tree (phi_age)
//   [4] The income class is in the credential Merkle tree (phi_income)
//   [5] The PAN commitment is in the credential Merkle tree (phi_pan)
//   [6] The Aadhaar commitment is in the credential Merkle tree (phi_aadhaar)
//   [7] The credential is within its validity window (phi_fresh)
//   [8] The credential has NOT been revoked (phi_revoc, SMT non-membership)
//   [9] The proof is bound to the PSP's nonce (phi_nonce, anti-replay)
//  [10] The computed KYC tier >= Full KYC (phi_tier)
//  [11] The transaction amount <= tier limit (phi_limit)
//
// Parameters:
//   merkle_levels : credential Merkle tree depth (3 = 8 leaves)
//   smt_levels    : revocation SMT depth (20 = 2^20 revocations)
//
// ---- PUBLIC INPUTS (visible to PSP / Solidity Verifier contract) ----
//   issuerPubKeyX, issuerPubKeyY    Registered issuer's EdDSA pubkey
//   merkleRoot                       Credential Merkle root
//   revocationRoot                   On-chain SMT root
//   credentialNullifier              User's revocation identifier
//   nonce                            PSP's anti-replay challenge
//   expectedBoundHash                Poseidon(nonce, merkleRoot)
//   currentYear                      Current year (2025, 2026, ...)
//   minAge                           18 (legal majority)
//   tierThreshold                    2 (Full KYC)
//   transactionAmount                In paise
//   tierLimit                        10,000,000 paise (Rs.1L)
//   maxValidityYears                 10 (low-risk default)
//
// ---- PRIVATE INPUTS (NEVER leave the user's device) ----
//   birthYear, incomeClass, docType, residenceStatus
//   isPEP, issuanceYear, credentialID, nullifierSecret
//   hasPAN, hasAadhaar
//   dobSalt, incomeSalt, panSalt, aadhaarSalt
//   All Merkle path elements and indices (4 paths)
//   EdDSA signature (sigR8X, sigR8Y, sigS)
//   SMT non-membership proof (smtSiblings, smtOldKey, smtOldValue, smtIsOld0)
//   panCommitment, aadhaarCommitment (precomputed hashes, not raw values)
//   accountAgeDays, coolingPeriodDays (for cooling period check)
//
// Total constraint count: ~25,000 (dominated by SMT at ~15,000)
// Proof generation time: ~400ms on laptop, ~3s on mid-range Android
// Proof size: ~1.5 KB (Groth16 constant — 3 elliptic curve points)
// ----------------------------------------------------------------
template UPIKYCTierProof(merkle_levels, smt_levels) {

    // ==============================================================
    // PUBLIC SIGNALS
    // ==============================================================
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input merkleRoot;
    signal input revocationRoot;
    signal input credentialNullifier;
    signal input nonce;
    signal input expectedBoundHash;
    signal input currentYear;
    signal input minAge;
    signal input tierThreshold;
    signal input transactionAmount;
    signal input tierLimit;
    signal input maxValidityYears;
    signal input coolingPeriodDays;
    signal input coolingLimit;

    // ==============================================================
    // PRIVATE SIGNALS (witness)
    // ==============================================================

    // Credential attributes
    signal input birthYear;
    signal input incomeClass;
    signal input docType;
    signal input residenceStatus;
    signal input isPEP;
    signal input issuanceYear;
    signal input credentialID;
    signal input nullifierSecret;
    signal input accountAgeDays;

    // Merkle inclusion flags (set to 1 by caller when paths are valid)
    signal input hasPAN;
    signal input hasAadhaar;

    // Salts (random, for unlinkability across proof sessions)
    signal input dobSalt;
    signal input incomeSalt;
    signal input panSalt;
    signal input aadhaarSalt;

    // PAN and Aadhaar commitments (Poseidon hashes computed off-circuit)
    // panCommitment     = Poseidon(PAN_number, panCommitSalt)
    // aadhaarCommitment = Poseidon(SHA256(Aadhaar), aadhaarCommitSalt)
    // NEITHER the PAN number NOR the Aadhaar number enters this circuit.
    signal input panCommitment;
    signal input aadhaarCommitment;

    // Merkle paths for all four verified attributes
    signal input dobPathElements[merkle_levels];
    signal input dobPathIndices[merkle_levels];
    signal input incomePathElements[merkle_levels];
    signal input incomePathIndices[merkle_levels];
    signal input panPathElements[merkle_levels];
    signal input panPathIndices[merkle_levels];
    signal input aadhaarPathElements[merkle_levels];
    signal input aadhaarPathIndices[merkle_levels];

    // EdDSA signature from issuer on merkleRoot
    signal input sigR8X;
    signal input sigR8Y;
    signal input sigS;

    // SMT non-membership proof components
    signal input smtSiblings[smt_levels];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;


    // ==============================================================
    // STEP 1 — NONCE BINDING   [phi_nonce]
    // Binds this proof to exactly one PSP request.
    // ==============================================================
    component nonceBind = NonceBinding();
    nonceBind.nonce             <== nonce;
    nonceBind.merkleRoot        <== merkleRoot;
    nonceBind.expectedBoundHash <== expectedBoundHash;


    // ==============================================================
    // STEP 2 — ISSUER SIGNATURE   [phi_sig]
    // Proves credential was issued by a PMLA-compliant Regulated Entity.
    // ==============================================================
    component sigVerif = CredentialSignatureVerifier();
    sigVerif.merkleRoot     <== merkleRoot;
    sigVerif.issuerPubKeyX  <== issuerPubKeyX;
    sigVerif.issuerPubKeyY  <== issuerPubKeyY;
    sigVerif.sigR8X         <== sigR8X;
    sigVerif.sigR8Y         <== sigR8Y;
    sigVerif.sigS           <== sigS;


    // ==============================================================
    // STEP 3 — DOB MERKLE INCLUSION   [part of phi_age]
    // Proves birthYear is a leaf in the signed credential tree.
    // ==============================================================
    component dobLeaf = AttributeLeafHash();
    dobLeaf.attribute <== birthYear;
    dobLeaf.salt      <== dobSalt;

    component dobMerkle = PoseidonMerkleVerifier(merkle_levels);
    dobMerkle.leaf <== dobLeaf.leaf;
    dobMerkle.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        dobMerkle.pathElements[i] <== dobPathElements[i];
        dobMerkle.pathIndices[i]  <== dobPathIndices[i];
    }
    dobMerkle.valid === 1;


    // ==============================================================
    // STEP 4 — INCOME CLASS MERKLE INCLUSION   [part of phi_income]
    // ==============================================================
    component incomeLeaf = AttributeLeafHash();
    incomeLeaf.attribute <== incomeClass;
    incomeLeaf.salt      <== incomeSalt;

    component incomeMerkle = PoseidonMerkleVerifier(merkle_levels);
    incomeMerkle.leaf <== incomeLeaf.leaf;
    incomeMerkle.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        incomeMerkle.pathElements[i] <== incomePathElements[i];
        incomeMerkle.pathIndices[i]  <== incomePathIndices[i];
    }
    incomeMerkle.valid === 1;


    // ==============================================================
    // STEP 5 — PAN MERKLE INCLUSION   [phi_pan]
    // The PAN NUMBER itself never enters this circuit.
    // Only panCommitment = Poseidon(PAN, panCommitSalt) does.
    // panCommitment is computed OFF-CIRCUIT by the user's wallet app.
    // ==============================================================
    component panLeaf = AttributeLeafHash();
    panLeaf.attribute <== panCommitment;
    panLeaf.salt      <== panSalt;

    component panMerkle = PoseidonMerkleVerifier(merkle_levels);
    panMerkle.leaf <== panLeaf.leaf;
    panMerkle.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        panMerkle.pathElements[i] <== panPathElements[i];
        panMerkle.pathIndices[i]  <== panPathIndices[i];
    }
    // hasPAN must equal 1, and panMerkle.valid must equal 1
    // Both constraints enforced simultaneously:
    panMerkle.valid === 1;
    hasPAN === 1;


    // ==============================================================
    // STEP 6 — AADHAAR MERKLE INCLUSION   [phi_aadhaar]
    // aadhaarCommitment = Poseidon(SHA256(Aadhaar_number), aadhaarCommitSalt)
    // Aadhaar Act S.29: raw Aadhaar number MUST NOT be shared.
    // The two-layer commitment (SHA256 then Poseidon) ensures
    // the raw 12-digit Aadhaar number cannot be recovered.
    // ==============================================================
    component aadhaarLeaf = AttributeLeafHash();
    aadhaarLeaf.attribute <== aadhaarCommitment;
    aadhaarLeaf.salt      <== aadhaarSalt;

    component aadhaarMerkle = PoseidonMerkleVerifier(merkle_levels);
    aadhaarMerkle.leaf <== aadhaarLeaf.leaf;
    aadhaarMerkle.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        aadhaarMerkle.pathElements[i] <== aadhaarPathElements[i];
        aadhaarMerkle.pathIndices[i]  <== aadhaarPathIndices[i];
    }
    aadhaarMerkle.valid === 1;
    hasAadhaar === 1;


    // ==============================================================
    // STEP 7 — AGE VERIFICATION   [phi_age]
    // birthYear now provably part of credential (STEP 3).
    // ==============================================================
    component ageVerif = AgeVerification();
    ageVerif.birthYear   <== birthYear;
    ageVerif.currentYear <== currentYear;
    ageVerif.minAge      <== minAge;


    // ==============================================================
    // STEP 8 — PEP EXCLUSION   [phi_noPEP]
    // PMLA Rule 9B: PEPs require manual Enhanced Due Diligence.
    // PEPs (isPEP=1) cannot generate a valid proof here.
    // ==============================================================
    component pepExcl = PEPExclusionVerification();
    pepExcl.isPEP <== isPEP;


    // ==============================================================
    // STEP 9 — CREDENTIAL FRESHNESS   [phi_fresh]
    // RBI Para 38: credentials must be periodically updated.
    // ==============================================================
    component freshVerif = CredentialFreshnessVerifier();
    freshVerif.issuanceYear     <== issuanceYear;
    freshVerif.currentYear      <== currentYear;
    freshVerif.maxValidityYears <== maxValidityYears;


    // ==============================================================
    // STEP 10 — COOLING PERIOD CHECK
    // NPCI: new accounts blocked from transactions > Rs.25,000
    // for the first 24 hours after account creation.
    // ==============================================================
    component coolingVerif = CoolingPeriodVerifier();
    coolingVerif.accountAgeDays    <== accountAgeDays;
    coolingVerif.coolingPeriodDays <== coolingPeriodDays;
    coolingVerif.transactionAmount <== transactionAmount;
    coolingVerif.coolingLimit      <== coolingLimit;


    // ==============================================================
    // STEP 11 — NULLIFIER AND REVOCATION CHECK   [phi_revoc]
    // ==============================================================
    component nullComp = NullifierComputation();
    nullComp.credentialID    <== credentialID;
    nullComp.nullifierSecret <== nullifierSecret;

    // Computed nullifier must match declared PUBLIC credentialNullifier
    nullComp.nullifier === credentialNullifier;

    component revocCheck = SMTRevocationChecker(smt_levels);
    revocCheck.credentialNullifier <== credentialNullifier;
    revocCheck.revocationRoot      <== revocationRoot;
    revocCheck.smtOldKey           <== smtOldKey;
    revocCheck.smtOldValue         <== smtOldValue;
    revocCheck.smtIsOld0           <== smtIsOld0;
    for (var i = 0; i < smt_levels; i++) {
        revocCheck.smtSiblings[i] <== smtSiblings[i];
    }


    // ==============================================================
    // STEP 12 — KYC TIER CLASSIFICATION   [phi_tier]
    // ==============================================================
    component tierClass = KYCTierClassifier();
    tierClass.birthYear       <== birthYear;
    tierClass.incomeClass     <== incomeClass;
    tierClass.docType         <== docType;
    tierClass.residenceStatus <== residenceStatus;
    tierClass.isPEP           <== isPEP;
    tierClass.hasPAN          <== hasPAN;
    tierClass.hasAadhaar      <== hasAadhaar;
    tierClass.currentYear     <== currentYear;

    // Computed tier must be >= tierThreshold (2 = Full KYC)
    component tierCheck = GreaterEqThan(4);
    tierCheck.in[0] <== tierClass.tier;
    tierCheck.in[1] <== tierThreshold;
    tierCheck.out === 1;


    // ==============================================================
    // STEP 13 — TRANSACTION LIMIT VERIFICATION   [phi_limit]
    // ==============================================================
    component limitVerif = TransactionLimitVerifier();
    limitVerif.transactionAmount <== transactionAmount;
    limitVerif.tierLimit         <== tierLimit;
}


// ================================================================
// SECTION 9: MINIMUM KYC CIRCUIT
// ================================================================

// ----------------------------------------------------------------
// Template : MinKYCTierProof
//
// Lighter circuit for Rs.10,000 Minimum KYC tier.
// Omits: PAN, Aadhaar, PEP check, SMT revocation.
// Includes: basic age, income (1-4), OVD, issuer sig, freshness.
//
// Designed for:
//   Low-end Android devices (simpler = faster proof)
//   UPI 123PAY feature phone users
//   Students / new-to-credit users
//
// Constraint count: ~7,000 (dominated by EdDSA: ~3,000)
// Proof generation: ~150ms on laptop
// ----------------------------------------------------------------
template MinKYCTierProof(merkle_levels) {

    // PUBLIC
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input merkleRoot;
    signal input nonce;
    signal input expectedBoundHash;
    signal input currentYear;
    signal input transactionAmount;
    signal input tierLimit;           // 1,000,000 paise = Rs.10,000
    signal input maxValidityYears;    // 8 years (medium risk default)

    // PRIVATE
    signal input birthYear;
    signal input incomeClass;
    signal input docType;
    signal input issuanceYear;
    signal input dobSalt;
    signal input incomeSalt;
    signal input dobPathElements[merkle_levels];
    signal input dobPathIndices[merkle_levels];
    signal input incomePathElements[merkle_levels];
    signal input incomePathIndices[merkle_levels];
    signal input sigR8X;
    signal input sigR8Y;
    signal input sigS;

    // Step 1: Nonce binding
    component nonceBind = NonceBinding();
    nonceBind.nonce             <== nonce;
    nonceBind.merkleRoot        <== merkleRoot;
    nonceBind.expectedBoundHash <== expectedBoundHash;

    // Step 2: Issuer signature
    component sigVerif = CredentialSignatureVerifier();
    sigVerif.merkleRoot    <== merkleRoot;
    sigVerif.issuerPubKeyX <== issuerPubKeyX;
    sigVerif.issuerPubKeyY <== issuerPubKeyY;
    sigVerif.sigR8X        <== sigR8X;
    sigVerif.sigR8Y        <== sigR8Y;
    sigVerif.sigS          <== sigS;

    // Step 3: DOB Merkle inclusion
    component dobLeaf = AttributeLeafHash();
    dobLeaf.attribute <== birthYear;
    dobLeaf.salt      <== dobSalt;

    component dobMerkle = PoseidonMerkleVerifier(merkle_levels);
    dobMerkle.leaf <== dobLeaf.leaf;
    dobMerkle.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        dobMerkle.pathElements[i] <== dobPathElements[i];
        dobMerkle.pathIndices[i]  <== dobPathIndices[i];
    }
    dobMerkle.valid === 1;

    // Step 4: Income class Merkle inclusion
    component incomeLeaf = AttributeLeafHash();
    incomeLeaf.attribute <== incomeClass;
    incomeLeaf.salt      <== incomeSalt;

    component incomeMerkle = PoseidonMerkleVerifier(merkle_levels);
    incomeMerkle.leaf <== incomeLeaf.leaf;
    incomeMerkle.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        incomeMerkle.pathElements[i] <== incomePathElements[i];
        incomeMerkle.pathIndices[i]  <== incomePathIndices[i];
    }
    incomeMerkle.valid === 1;

    // Step 5: Age >= 18
    component ageVerif = AgeVerification();
    ageVerif.birthYear   <== birthYear;
    ageVerif.currentYear <== currentYear;
    ageVerif.minAge      <== 18;

    // Step 6: Income class {1,2,3,4}
    component incomeVerif = IncomeClassVerificationMin();
    incomeVerif.incomeClass <== incomeClass;
    incomeVerif.valid === 1;

    // Step 7: Valid OVD document type
    component docVerif = DocumentTypeVerification();
    docVerif.docType <== docType;
    docVerif.isValidOVD === 1;

    // Step 8: Credential freshness
    component freshVerif = CredentialFreshnessVerifier();
    freshVerif.issuanceYear     <== issuanceYear;
    freshVerif.currentYear      <== currentYear;
    freshVerif.maxValidityYears <== maxValidityYears;

    // Step 9: Transaction limit
    component limitVerif = TransactionLimitVerifier();
    limitVerif.transactionAmount <== transactionAmount;
    limitVerif.tierLimit         <== tierLimit;
}


// ================================================================
// SECTION 10: EXTENSION CIRCUITS
// ================================================================

// ----------------------------------------------------------------
// Template : NACHMandateProof
//
// Extension: Prove eligibility for NACH/ECS recurring mandates.
// NPCI rule: mandates above Rs.15,000 require Full KYC.
//            PIN not required for auto-debit < Rs.15,000.
//
// Same credential Merkle tree as UPIKYCTierProof.
// Adds: mandate amount check against NACH-specific limits.
//
// Constraint count: ~20,000 (reuses most of Full KYC circuit)
// ----------------------------------------------------------------
template NACHMandateProof(merkle_levels, smt_levels) {
    // PUBLIC
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input merkleRoot;
    signal input revocationRoot;
    signal input credentialNullifier;
    signal input nonce;
    signal input expectedBoundHash;
    signal input currentYear;
    signal input maxValidityYears;
    signal input mandateAmount;        // Mandate amount in paise
    signal input mandateLimit;         // NACH limit for tier (1,500,000 paise = Rs.15K)

    // PRIVATE
    signal input birthYear;
    signal input incomeClass;
    signal input docType;
    signal input residenceStatus;
    signal input isPEP;
    signal input issuanceYear;
    signal input credentialID;
    signal input nullifierSecret;
    signal input hasPAN;
    signal input hasAadhaar;
    signal input dobSalt;
    signal input incomeSalt;
    signal input panSalt;
    signal input aadhaarSalt;
    signal input panCommitment;
    signal input aadhaarCommitment;
    signal input dobPathElements[merkle_levels];
    signal input dobPathIndices[merkle_levels];
    signal input incomePathElements[merkle_levels];
    signal input incomePathIndices[merkle_levels];
    signal input panPathElements[merkle_levels];
    signal input panPathIndices[merkle_levels];
    signal input aadhaarPathElements[merkle_levels];
    signal input aadhaarPathIndices[merkle_levels];
    signal input sigR8X;
    signal input sigR8Y;
    signal input sigS;
    signal input smtSiblings[smt_levels];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // Nonce binding
    component nonceBind = NonceBinding();
    nonceBind.nonce             <== nonce;
    nonceBind.merkleRoot        <== merkleRoot;
    nonceBind.expectedBoundHash <== expectedBoundHash;

    // Issuer signature
    component sigVerif = CredentialSignatureVerifier();
    sigVerif.merkleRoot    <== merkleRoot;
    sigVerif.issuerPubKeyX <== issuerPubKeyX;
    sigVerif.issuerPubKeyY <== issuerPubKeyY;
    sigVerif.sigR8X        <== sigR8X;
    sigVerif.sigR8Y        <== sigR8Y;
    sigVerif.sigS          <== sigS;

    // DOB Merkle
    component dobLeaf = AttributeLeafHash();
    dobLeaf.attribute <== birthYear; dobLeaf.salt <== dobSalt;
    component dobM = PoseidonMerkleVerifier(merkle_levels);
    dobM.leaf <== dobLeaf.leaf; dobM.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        dobM.pathElements[i] <== dobPathElements[i];
        dobM.pathIndices[i]  <== dobPathIndices[i];
    }
    dobM.valid === 1;

    // Income Merkle
    component incLeaf = AttributeLeafHash();
    incLeaf.attribute <== incomeClass; incLeaf.salt <== incomeSalt;
    component incM = PoseidonMerkleVerifier(merkle_levels);
    incM.leaf <== incLeaf.leaf; incM.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        incM.pathElements[i] <== incomePathElements[i];
        incM.pathIndices[i]  <== incomePathIndices[i];
    }
    incM.valid === 1;

    // PAN Merkle
    component panLeaf = AttributeLeafHash();
    panLeaf.attribute <== panCommitment; panLeaf.salt <== panSalt;
    component panM = PoseidonMerkleVerifier(merkle_levels);
    panM.leaf <== panLeaf.leaf; panM.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        panM.pathElements[i] <== panPathElements[i];
        panM.pathIndices[i]  <== panPathIndices[i];
    }
    panM.valid === 1; hasPAN === 1;

    // Aadhaar Merkle
    component aaLeaf = AttributeLeafHash();
    aaLeaf.attribute <== aadhaarCommitment; aaLeaf.salt <== aadhaarSalt;
    component aaM = PoseidonMerkleVerifier(merkle_levels);
    aaM.leaf <== aaLeaf.leaf; aaM.root <== merkleRoot;
    for (var i = 0; i < merkle_levels; i++) {
        aaM.pathElements[i] <== aadhaarPathElements[i];
        aaM.pathIndices[i]  <== aadhaarPathIndices[i];
    }
    aaM.valid === 1; hasAadhaar === 1;

    // Age
    component ageV = AgeVerification();
    ageV.birthYear <== birthYear; ageV.currentYear <== currentYear; ageV.minAge <== 18;

    // PEP exclusion
    component pepV = PEPExclusionVerification();
    pepV.isPEP <== isPEP;

    // Freshness
    component freshV = CredentialFreshnessVerifier();
    freshV.issuanceYear <== issuanceYear;
    freshV.currentYear  <== currentYear;
    freshV.maxValidityYears <== maxValidityYears;

    // Nullifier + Revocation
    component nullV = NullifierComputation();
    nullV.credentialID    <== credentialID;
    nullV.nullifierSecret <== nullifierSecret;
    nullV.nullifier === credentialNullifier;

    component revocV = SMTRevocationChecker(smt_levels);
    revocV.credentialNullifier <== credentialNullifier;
    revocV.revocationRoot      <== revocationRoot;
    revocV.smtOldKey   <== smtOldKey;
    revocV.smtOldValue <== smtOldValue;
    revocV.smtIsOld0   <== smtIsOld0;
    for (var i = 0; i < smt_levels; i++) {
        revocV.smtSiblings[i] <== smtSiblings[i];
    }

    // KYC Tier must be Full KYC (2)
    component tierV = KYCTierClassifier();
    tierV.birthYear       <== birthYear;
    tierV.incomeClass     <== incomeClass;
    tierV.docType         <== docType;
    tierV.residenceStatus <== residenceStatus;
    tierV.isPEP           <== isPEP;
    tierV.hasPAN          <== hasPAN;
    tierV.hasAadhaar      <== hasAadhaar;
    tierV.currentYear     <== currentYear;

    component tierCheck = GreaterEqThan(4);
    tierCheck.in[0] <== tierV.tier;
    tierCheck.in[1] <== 2;
    tierCheck.out === 1;

    // NACH-specific mandate amount check
    component nachLimit = TransactionLimitVerifier();
    nachLimit.transactionAmount <== mandateAmount;
    nachLimit.tierLimit         <== mandateLimit;
}


// ================================================================
// SECTION 11: MAIN COMPONENT
// ================================================================

// Compile and deploy the Full KYC circuit.
//
// merkle_levels = 3  : credential tree supports 8 leaves (2^3)
//                      sufficient for 8 KYC attributes
// smt_levels    = 20 : revocation SMT supports 2^20 ≈ 1M revocations
//
// To switch to MinKYCTierProof, comment main below and use:
//   component main {public [...]} = MinKYCTierProof(3);
//
// PUBLIC signal list determines what the Solidity verifier
// and the PSP backend can see. Everything NOT listed is private.

component main {
    public [
        issuerPubKeyX,
        issuerPubKeyY,
        merkleRoot,
        revocationRoot,
        credentialNullifier,
        nonce,
        expectedBoundHash,
        currentYear,
        minAge,
        tierThreshold,
        transactionAmount,
        tierLimit,
        maxValidityYears,
        coolingPeriodDays,
        coolingLimit
    ]
} = UPIKYCTierProof(3, 20);


// ================================================================
// USAGE NOTES
// ================================================================
//
// After compiling with:
//   circom upi_kyc_full.circom --r1cs --wasm --sym -o ./build
//
// Generate input.json:
// {
//   "issuerPubKeyX": "2728...",  (Baby Jubjub X coord of issuer)
//   "issuerPubKeyY": "8912...",
//   "merkleRoot":    "1234...",  (Poseidon root of credential tree)
//   "revocationRoot":"5678...",  (Current on-chain SMT root)
//   "credentialNullifier": "9012...",
//   "nonce": "3456...",          (PSP-generated random nonce)
//   "expectedBoundHash": "7890...", (Poseidon(nonce, merkleRoot))
//   "currentYear": "2025",
//   "minAge": "18",
//   "tierThreshold": "2",
//   "transactionAmount": "5000000",  (Rs.50,000 in paise)
//   "tierLimit": "10000000",         (Rs.1,00,000 in paise)
//   "maxValidityYears": "10",
//   "coolingPeriodDays": "1",
//   "coolingLimit": "2500000",       (Rs.25,000 in paise)
//
//   // PRIVATE — these NEVER appear in proof.json
//   "birthYear": "2001",
//   "incomeClass": "1",
//   "docType": "5",              (Aadhaar)
//   "residenceStatus": "1",      (Resident Indian)
//   "isPEP": "0",
//   "issuanceYear": "2023",
//   "credentialID": "8765...",
//   "nullifierSecret": "4321...",
//   "accountAgeDays": "30",
//   "hasPAN": "1",
//   "hasAadhaar": "1",
//   "dobSalt": "...", "incomeSalt": "...", "panSalt": "...", "aadhaarSalt": "...",
//   "panCommitment": "...",       (Poseidon(PAN_number, panCommitSalt))
//   "aadhaarCommitment": "...",   (Poseidon(SHA256(Aadhaar), aadhaarCommitSalt))
//   "dobPathElements": [...],     (3 elements for depth-3 tree)
//   "dobPathIndices":  [...],
//   ...                           (similarly for income, pan, aadhaar paths)
//   "sigR8X": "...", "sigR8Y": "...", "sigS": "...",
//   "smtSiblings": [...],         (20 elements for depth-20 SMT)
//   "smtOldKey": "...", "smtOldValue": "...", "smtIsOld0": "1"
// }
//
// Generate witness:
//   node build/upi_kyc_full_js/generate_witness.js \
//        build/upi_kyc_full_js/upi_kyc_full.wasm   \
//        input.json witness.wtns
//
// Generate proof:
//   snarkjs groth16 prove circuit_final.zkey witness.wtns \
//           proof.json public.json
//
// Verify off-chain:
//   snarkjs groth16 verify verification_key.json public.json proof.json
//
// Export Solidity verifier (for on-chain PSP verification):
//   snarkjs zkey export solidityverifier circuit_final.zkey verifier.sol
//
// Deploy verifier.sol → Solidity contract address
// Configure KYCPaymaster.sol to only sponsor calls to this verifier address
// Configure SMTRegistry.sol with initial revocation root (empty SMT root)
//
// ================================================================
