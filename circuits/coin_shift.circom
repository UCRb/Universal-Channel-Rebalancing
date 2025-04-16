pragma circom 2.1.6;

include "@zk-email/circuits/lib/rsa.circom";
include "circomlib/circuits/poseidon.circom";


template SigVerify(n, k) {
    signal input message[k]; 
    signal input pubkey[k]; // RSA public key split into k chunks
    signal input signature[k]; // RSA signature split into k chunks

    component rsaVerifier = RSAVerifier65537(n, k);
    rsaVerifier.message <== message;
    rsaVerifier.modulus <== pubkey;
    rsaVerifier.signature <== signature;
}

template CoinShift(n, k) {
    signal input sig[4][k];
    
    signal input pk[4][k];
    signal input l;

    signal input msg[4][k];


    signal rsa_msg[4][k];

    component sig_ver[4];
    component msgHasher[4];
    component num2bits[4];
    component bits2num[4][3];

    
    for(var i=0; i < 4; i++) {
        sig_ver[i] = SigVerify(121, 17);
        
        msgHasher[i] = Poseidon(3);
        msgHasher[i].inputs[0] <== 0;
        msgHasher[i].inputs[1] <== 1;
        msgHasher[i].inputs[2] <== 2;

        num2bits[i] = Num2Bits(255);
        num2bits[i].in <== msgHasher[i].out;

        bits2num[i][0] = Bits2Num(121);
        bits2num[i][1] = Bits2Num(121);
        bits2num[i][2] = Bits2Num(13);

        for (var j = 0; j < 121; j++) {
            bits2num[i][0].in[j] <== num2bits[i].out[j];
            bits2num[i][1].in[j] <== num2bits[i].out[j+121];
        }
        for (var j = 0; j < 13; j++) {
            bits2num[i][2].in[j] <== num2bits[i].out[j+242];
        }

        bits2num[i][0].out ==> rsa_msg[i][0];
        bits2num[i][1].out ==> rsa_msg[i][1];
        bits2num[i][2].out ==> rsa_msg[i][2];
        
        for (var j = 3; j < k ; j++) {
            rsa_msg[i][j] <== 0;
        }

        sig_ver[i].message <== rsa_msg[i];
        sig_ver[i].signature <== sig[i];
        sig_ver[i].pubkey <== pk[i];

    }

}

component main { public [ l ] } = CoinShift(121, 17);
