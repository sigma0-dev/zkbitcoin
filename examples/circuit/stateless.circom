pragma circom 2.1.3;

include "./circom_lib/poseidon.circom";

template Main() {
    signal input truncated_txid;

    signal input preimage[1];

    var hardcoded_value = 17744324452969507964952966931655538206777558023197549666337974697819074895989;

    signal digest <== Poseidon(1)(preimage);
    log(digest);
    digest === hardcoded_value;
}

component main{public [truncated_txid]} = Main();
