# Encoding Bob's address as a public input

* problem: bob's address need to be authenticated in his request
* solution: have the first public input be bob's address (or a hash of it)
* but Bob's address is a taproot address `bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297`
* We can decode it as a 32 bytes value
* problem: the circuit curve we use is the same as Ethereum (BN128) which has field elements of 254 bits (less than 32 bytes)

## Solution 1: Change the curve

* circom supports different curves with different field sizes
* the most popular one is [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) which has a field size of > 32 bytes
* we can use that in circom by passing the flag `--prime bls12381` in its commands

## Solution 2: Hash the address

* the previous solution might suck because we want to reuse templates that people write, and people write them for bn254 (coz that's what Ethereum uses)

## TODO

- [ ] add a new CLI command to serialize bob's address as a field element in our field
  - [ ] or perhaps, Bob's unlock funds command should also run snarkjs to produce public inputs (including its address) and create a proof?
- [ ] change public inputs to be serialized as vectors of bytes instead of strings?
