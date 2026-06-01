pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

// Enforces that an input variable 'x' must strictly exist inside the set {0, 1, 2}
template AssertIsRPS() {
    signal input x;
    
    signal isRP;
    isRP <== (x - 0) * (x - 1);
    
    // If x is 0, 1, or 2, this product must evaluate to exactly 0
    isRP * (x - 2) === 0;
}

// Evaluates a single round of Rock-Paper-Scissors and calculates the output score
template RoundCheck() {
    signal input playerPlay;
    signal input opponentPlay;
    signal output roundScore;

    // 1. Validate that both plays are legitimate states (0, 1, or 2)
    component playerValid = AssertIsRPS();
    playerValid.x <== playerPlay;

    component opponentValid = AssertIsRPS();
    opponentValid.x <== opponentPlay;

    // 2. Check if the match is a draw using circomlib's IsEqual
    component eq = IsEqual();
    eq.in[0] <== playerPlay;
    eq.in[1] <== opponentPlay;
    
    signal isDraw <== eq.out;

    // 3. Score contribution calculations based on player play choice
    // Rock = 1 point (value 0+1), Paper = 2 points (value 1+1), Scissors = 3 points (value 2+1)
    signal shapeScore <== playerPlay + 1;

    // 4. Derive win/loss metrics via pure algebraic field lookups
    // Total score is shape score + outcome score (Draw = 3 points)
    roundScore <== shapeScore + (isDraw * 3);
}

component main = RoundCheck();