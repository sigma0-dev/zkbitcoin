pragma circom 2.1.3;

include "./circom_lib/poseidon.circom";

template Main() {
    signal input truncated_txid;

    signal input preimage[1];

    var hardcoded_value = 18586133768512220936620570745912940619677854269274689475585506675881198879027;

    signal digest <== Poseidon(1)(preimage);
    digest === hardcoded_value;
}

component main{public [truncated_txid]} = Main();
