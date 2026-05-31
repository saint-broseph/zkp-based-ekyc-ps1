pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/comparators.circom";

template AgeCheck(minAge) {
    signal input currentYear; 
    signal input birthYear;   
    signal age;

    age <== currentYear - birthYear;

    component gte = GreaterEqThan(32);
    gte.in[0] <== age;
    gte.in[1] <== minAge;

    gte.out === 1;
}

component main {public [currentYear]} = AgeCheck(18);
