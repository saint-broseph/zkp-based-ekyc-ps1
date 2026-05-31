pragma circom 2.0.0;

template SumIsTwelve() {
    signal input a; 
    signal input b; 
    signal output c;

    c <== a + b;
    c === 12;
}

component main = SumIsTwelve();
