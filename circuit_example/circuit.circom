pragma circom 2.1.3;

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

template AddBits(BITS) {
    signal input a[BITS];
    signal input b[BITS];
    signal output out[BITS];
    signal carrybit;

    var lin = 0;
    var lout = 0;

    var k;
    var j = 0;

    var e2;

    // create e2 which
    // is the numerical sum of 2^k
    e2 = 1;
    for (k = BITS - 1; k >= 0; k--) {
        lin += (a[k] + b[k]) * e2;
        e2 *= 2;
    }

    e2 = 1;
    for (k = BITS - 1; k >= 0; k--) {
        out[k] <-- (lin >> j) & 1;
        // Ensure out is binary
        out[k] * (out[k] - 1) === 0;
        lout += out[k] * e2;
        e2 *= 2;
        j += 1;
    }

    carrybit <-- (lin >> j) & 1;
    // Ensure out is binary
    carrybit * (carrybit - 1) === 0;
    lout += carrybit * e2;

    // Ensure the sum matches
    lin === lout;
}

template AddBitsBetter(BITS) {
    signal input a[BITS];
    signal input b[BITS];
    signal output out[BITS];

    // pack addition in BE
    var lin = 0;
    var e2 = 1;
    for (var k = BITS - 1; k >= 0; k--) {
        lin += (a[k] + b[k]) * e2;
        e2 *= 2;
    }

    // unpack result
    var result[BITS + 1] = Num2Bits(BITS + 1)(lin);

    // take everything but carry
    for (var i = 0; i < BITS; i++) {
        out[i] <== result[i];
    }
}

component main{public [a, b]} = AddBitsBetter(32);
