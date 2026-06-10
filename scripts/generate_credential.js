// scripts/generate_credential.js
const { buildPoseidon, buildEddsa, buildBabyjub } = require("circomlibjs");
const fs = require("fs");
const crypto = require("crypto");

async function generateMockCredential() {
    // 1. Initialize circomlibjs cryptographic primitives
    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyjub();

    console.log("🛠️  Initializing Mock Issuer (Bank/UIDAI)...");

    // 2. Generate Issuer Keys (EdDSA over BabyJubJub)
    const issuerPrivateKey = crypto.randomBytes(32);
    const issuerPubKey = eddsa.prv2pub(issuerPrivateKey);
    const issuerPubKeyX = babyJub.F.toString(issuerPubKey[0]);
    const issuerPubKeyY = babyJub.F.toString(issuerPubKey[1]);

    // 3. Define the User's Raw Data (The "Truth")
    // Using simple BigInts that fit in the BN128 scalar field
    const birthYear = 2001n;
    const incomeClass = 1n; // 1 = Salaried (Low Risk)
    const docType = 5n; // 5 = Aadhaar
    const panCommitment = 987654321n; // Mock hash of PAN
    const aadhaarCommitment = 123456789n; // Mock hash of Aadhaar (No real IDs used)
    
    // 4. Generate Cryptographic Salts for Unlinkability
    const dobSalt = 11111n;
    const incomeSalt = 22222n;
    const panSalt = 33333n;
    const aadhaarSalt = 44444n;

    console.log("🔒 Hashing Attributes into Merkle Leaves...");

    // 5. Hash Attributes into Leaves using Poseidon
    const F = poseidon.F;
    const credentialID = 55555n;
    const nullifierSecret = 66666n;
    const actualNullifier = F.toString(poseidon([credentialID, nullifierSecret]));
    const leafDOB = F.toString(poseidon([birthYear, dobSalt]));
    const leafIncome = F.toString(poseidon([incomeClass, incomeSalt]));
    const leafPAN = F.toString(poseidon([panCommitment, panSalt]));
    const leafAadhaar = F.toString(poseidon([aadhaarCommitment, aadhaarSalt]));

    // 6. Build a simple Depth-3 Merkle Tree (8 leaves)
    const L0 = [leafDOB, leafIncome, leafPAN, leafAadhaar, 0n, 0n, 0n, 0n];
    
    const L1 = [
        F.toString(poseidon([L0[0], L0[1]])),
        F.toString(poseidon([L0[2], L0[3]])),
        F.toString(poseidon([L0[4], L0[5]])),
        F.toString(poseidon([L0[6], L0[7]]))
    ];

    const L2 = [
        F.toString(poseidon([L1[0], L1[1]])),
        F.toString(poseidon([L1[2], L1[3]]))
    ];

    // --- THE FIX IS HERE ---
    // Keep the raw Uint8Array for the signature
    const merkleRootHash = poseidon([L2[0], L2[1]]); 
    
    // Convert to string for the JSON output
    const merkleRoot = F.toString(merkleRootHash);
    console.log("🌳 Credential Merkle Root:", merkleRoot);

    // 7. Issuer Signs the Merkle Root
    // Pass the raw merkleRootHash (Uint8Array) instead of the BigInt
    const signature = eddsa.signPoseidon(issuerPrivateKey, merkleRootHash); 
    const sigR8X = babyJub.F.toString(signature.R8[0]);
    const sigR8Y = babyJub.F.toString(signature.R8[1]);
    const sigS = signature.S.toString();

    console.log("✍️  Issuer Signature Generated.");

    // 8. Construct the input.json for the Circom Circuit
    const inputJson = {
        // PUBLIC INPUTS
        "issuerPubKeyX": issuerPubKeyX,
        "issuerPubKeyY": issuerPubKeyY,
        "merkleRoot": merkleRoot,
        "revocationRoot": "0", // Empty SMT root for now (not revoked)
        "credentialNullifier": actualNullifier, // Mock nullifier
        "nonce": "999999", // Mock PSP Challenge
        "expectedBoundHash": F.toString(poseidon([999999n, BigInt(merkleRoot)])),
        "currentYear": "2026",
        "minAge": "18",
        "tierThreshold": "2",
        "transactionAmount": "5000000", // 50,000 INR in paise
        "tierLimit": "10000000", // 1 Lakh INR in paise
        "maxValidityYears": "10",
        "coolingPeriodDays": "1",
        "coolingLimit": "2500000",

        // PRIVATE INPUTS
        "birthYear": birthYear.toString(),
        "incomeClass": incomeClass.toString(),
        "docType": docType.toString(),
        "residenceStatus": "1",
        "isPEP": "0",
        "issuanceYear": "2025",
        "credentialID": credentialID.toString(),
        "nullifierSecret": nullifierSecret.toString(),
        "accountAgeDays": "30",
        
        "hasPAN": "1",
        "hasAadhaar": "1",
        "dobSalt": dobSalt.toString(),
        "incomeSalt": incomeSalt.toString(),
        "panSalt": panSalt.toString(),
        "aadhaarSalt": aadhaarSalt.toString(),
        "panCommitment": panCommitment.toString(),
        "aadhaarCommitment": aadhaarCommitment.toString(),

        // MERKLE PATHS (Indices: 0=Left, 1=Right)
        
        // DOB is at Index 0 (Left, Left, Left)
        "dobPathElements": [L0[1], L1[1], L2[1]],
        "dobPathIndices": [0, 0, 0],

        // Income is at Index 1 (Right, Left, Left)
        "incomePathElements": [L0[0], L1[1], L2[1]],
        "incomePathIndices": [1, 0, 0],

        // PAN is at Index 2 (Left, Right, Left)
        "panPathElements": [L0[3], L1[0], L2[1]],
        "panPathIndices": [0, 1, 0],

        // Aadhaar is at Index 3 (Right, Right, Left)
        "aadhaarPathElements": [L0[2], L1[0], L2[1]],
        "aadhaarPathIndices": [1, 1, 0],

        "sigR8X": sigR8X,
        "sigR8Y": sigR8Y,
        "sigS": sigS,

        // MOCK SMT NON-MEMBERSHIP PROOF (Level 20)
        // For testing the circuit before building the actual Solidity SMT, 
        // we feed it dummy zeroes because the SMTVerifier allows an empty tree 
        // to return a valid non-membership proof if the root is 0.
        "smtSiblings": new Array(20).fill("0"),
        "smtOldKey": "0",
        "smtOldValue": "0",
        "smtIsOld0": "1"
    };

    fs.writeFileSync("input.json", JSON.stringify(inputJson, null, 2));
    console.log("✅ Successfully generated input.json!");
    console.log("🚀 Next step: Run 'node generate_witness.js upi_kyc_full.wasm input.json witness.wtns'");
}

generateMockCredential().catch(console.error);