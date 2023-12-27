pragma circom 2.1.3;

template Main() {
    signal output new_state[1];
    signal input prev_state[1];
    signal input txid; // this should not affect output
    signal input amount_out;
    signal input amount_in;

    new_state[0] <== prev_state[0] + amount_in - amount_out;
}

component main{public [prev_state, txid, amount_out, amount_in]} = Main();
