pragma circom 2.1.3;

include "./circom_lib/poseidon.circom";

template Main() {
    signal input txid;

    signal input preimage[1];

    var hardcoded_value = 0x0;

    signal digest <== Poseidon(1)(preimage);
    digest === hardcoded_value;
}

component main{public [txid]} = Main();
