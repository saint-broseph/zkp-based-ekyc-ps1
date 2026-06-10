import { expect } from "chai";
import hre from "hardhat";
import * as fs from "fs";

describe("UPI Tier ZK Verifier (Google Pay Simulation)", function () {
  it("Should return TRUE for a mathematically valid proof", async function () {
    console.log("🚀 Deploying Smart Contract to local blockchain...");
    
    // 1. Initialize Hardhat 3 Network Connection
    const connection = await hre.network.create();
    const { ethers } = connection;
    
    // 2. Deploy the Contract
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment(); 

    console.log("✅ Contract deployed at:", await verifier.getAddress());
    console.log("📂 Loading User's proof.json and public.json...");

    // 3. Load the Proof and Public Signals
    const proof = JSON.parse(fs.readFileSync("proof.json", "utf8"));
    const pubSignals = JSON.parse(fs.readFileSync("public.json", "utf8"));

    // 4. Format the Groth16 Proof for Solidity
    const a: [any, any] = [proof.pi_a[0], proof.pi_a[1]];
    const b: [[any, any], [any, any]] = [
      [proof.pi_b[0][1], proof.pi_b[0][0]], 
      [proof.pi_b[1][1], proof.pi_b[1][0]]
    ]; 
    const c: [any, any] = [proof.pi_c[0], proof.pi_c[1]];
    const Input = pubSignals;

    console.log("🛡️  Pinging the Smart Contract: verifyProof()...");

    // 5. Call the Smart Contract
    const isValid = await verifier.verifyProof(a, b, c, Input);
    
    // 6. Assert the result
    expect(isValid).to.equal(true);
    console.log("🎉 SUCCESS: The Blockchain returned TRUE. The user is verified for ₹1 Lakh!");
  });
});