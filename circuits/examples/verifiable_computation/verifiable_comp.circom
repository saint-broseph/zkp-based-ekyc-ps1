pragma circom 2.1.6;

template VerifiableComputation() {
    // 1. Parameter Definitions
    signal input u;      // Public input variable
    signal input v;      // Private input secret variable (witness)
    signal output out;  // Public output calculation result

    // 2. Intermediate Signals for non-linear constraint flattening
    signal v_sq;
    signal v_cub;
    signal uv;

    // 3. Core Arithmetic & Constraint Generation
    v_sq <== v * v;       // Proves v_sq = v^2
    v_cub <== v_sq * v;   // Proves v_cub = v^2 * v = v^3
    uv <== u * v;         // Proves uv = u * v

    // 4. Final Linear Combination Assignment
    out <== v_cub + uv + 7;
}

// Declare component main and explicitly state that 'u' is a public input vector
component main {public [u]} = VerifiableComputation();