pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";  
include "circomlib/circuits/comparators.circom";

template LargerThanTen() {
    signal input a;
    signal output b;

    // 1. Enforce that input 'a' is strictly greater than 10
    // GreaterThan takes the number of bits to inspect (e.g., 32-bit integer)
    component comp = GreaterThan(32);
    comp.in[0] <== a;
    comp.in[1] <== 10;
    
    // GreaterThan outputs 1 if in[0] > in[1], otherwise 0.
    // We constrain this output to be exactly 1.
    comp.out === 1;

    // 2. Compute the Poseidon hash of the validated input
    component hash = Poseidon(1);
    hash.inputs[0] <== a;
    
    b <== hash.out;
}

component main = LargerThanTen();