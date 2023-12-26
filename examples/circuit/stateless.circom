pragma circom 2.1.3;

template Main() {
    signal input txid;
}

component main{public [prev_state, txid, amount_out, amount_in]} = Main();
