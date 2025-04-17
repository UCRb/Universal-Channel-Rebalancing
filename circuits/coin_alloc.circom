pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template CoinAlloc(n) {
    signal input v[n];
    signal input id[n];
    signal input total;

    signal output c[n];


    component gt[n];
    component hasher[n];
    
    var sum = 0;
    for(var i=0; i < n; i++) {
        gt[i] = GreaterThan(250);
        gt[i].in[0] <== v[i];
        gt[i].in[1] <== 0;
        gt[i].out === 1;

        sum = sum + v[i];

        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== v[i];
        hasher[i].inputs[1] <== id[i];
        c[i] <== hasher[i].out;
    }

    sum === total;

}

component main { public [ total ] } = CoinAlloc(10);
