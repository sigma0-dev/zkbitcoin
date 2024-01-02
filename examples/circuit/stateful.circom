pragma circom 2.1.3;

template Main() {
    signal output new_state;
    signal input prev_state;
    signal input truncated_txid; // this should not affect output
    signal input amount_out;
    signal input amount_in;

    new_state <== prev_state + amount_in - amount_out;
}

component main{public [prev_state, truncated_txid, amount_out, amount_in]} = Main();
