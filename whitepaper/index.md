# zkBitcoin: zkapps for Bitcoin

abstract:

* we introduce a light multi-party computation protocol to verify zero-knowledge proof circuits on Bitcoin
* unlocking two use-cases, stateless zk applications that lock funds on Bitcoin and allow users to unlock them using zero-knowledge proofs, and stateful zk applications that allow users to update, deposit, and withdraw from a zk application using zero-knowledge proofs.
* since zero-knowledge proofs can't be verified directly on Bitcoin (for lack of optimized opcodes), we use a multi-party wallet to verify them off-chain
* the particularity of the protocol is that it is akin to a minimal layer 2 on top of Bitcoin that uses Bitcoin as a data-availability layer
* specifically, the committee in charge of verifying zero-knowledge proofs does not have to be connected to the chain
* hashes of circuits (verifier keys) are stored on-chain, and the latest state of a (stateful) application is also stored and kept on-chain

keywords: zero-knowledge proofs, ZKP, multi-party computation, MPC, 

## Intro

* article on zkp in bitcoin https://cointelegraph.com/magazine/satoshi-nakamoto-zk-proofs-bitcoin/
* links to this thread https://bitcointalk.org/index.php?topic=770.0

![image](https://hackmd.io/_uploads/H1lKsnp8p.png)

* scripting is too limited currenty to verify ZKPs
* 2016: zcash is a fork of bitcoin
    * shielded pool
    * but doesn't have ZK programmability / zkapps
    * Mina / Aleo / and L2s like aztec network / zksync provide zkapps

## Related work

* zero sync provides state proofs of Bitcoin for light clients?
    * https://zerosync.org/
    * zerosync whitepaper https://zerosync.org/zerosync.pdf
    * thoughts?
* BIT VM augments Bitcoin script using fraud proofs
    * https://bitvm.org/bitvm.pdf
    * way too complicated IMO, crazily innefficient if understand correctly (in encoding-program complexity, but also in creating fraud proofs on-chain)
* rollkit is an L2 SDK
    * like [OP stack](https://optimism.mirror.xyz/fLk5UGjZDiXFuvQh6R_HscMQuuY9ABYNF7PI76-qJYs) and [Polygon CDK](https://polygon.technology/polygon-cdk) but for Bitcoin?
    * https://rollkit.dev/blog/sovereign-rollups-on-bitcoin
* Alpen Labs is a zk rollup that verifies on Bitcoin
    * https://www.youtube.com/watch?v=Nldg_tjeX_A
    * ![image](https://hackmd.io/_uploads/Hkyh33pUT.png)
    * they propose a new opcode: `OP_VERIFYSTARKPROOF`
    * thoughts?
* Chainway is another zk rollup, but it's not clear who verifies
    * https://chainway.xyz/projects
    * thoughts?
        * what is a "sovereign rollup"? (currently, no idea) This term might suggest their verification mechanism.
* zkBitcoin 
    * https://github.com/sigma0-xyz/zkbitcoin

## Protocol

TODO: Copy zkapp doc from docs/

## Security

* Key refresh from https://github.com/cronokirby/cait-sith/blob/main/docs/key-generation.md
* Committee could be a trusted set of entities (we're trying to figure out who would be interested)
* run MPC in SGX, and we could publish the SGX attestation that the shares were generated correctly
* after that, liveness could still be an issue, as currently the network might not have the best incentives to run (future work?)

## Benchmarks

* we should try to run the protocol with like 100 participants and a threshold of 51? see how efficient it is (to me it looks like FROST is a very efficient protocol)
* maybe the FROST paper already has benchmarks?