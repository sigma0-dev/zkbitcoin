# zkBitcoin: zero-knowledge applications for Bitcoin

Authors: David Wong and Ivan Mikushin

## Abstract

We introduce a light multi-party computation protocol to verify zero-knowledge proof circuits on Bitcoin. This unlocks two use-cases: stateless zero-knowledge applications that lock funds on Bitcoin until users unlock them using zero-knowledge proofs, and stateful zero-knowledge applications that allow users to update, deposit, and withdraw from a zero-knowledge application using zero-knowledge proofs. Since zero-knowledge proofs can't be verified directly on Bitcoin (for lack of optimized opcodes) we use a multi-party committee to verify them off-chain and compute a single on-chain signature. The particularity of the protocol is that it is akin to a minimal layer 2 on top of Bitcoin that uses Bitcoin as a data-availability layer. Specifically, the committee in charge of verifying zero-knowledge proofs does not have to be connected to the chain as hashes of circuits (verifier keys) are stored in UTXOs on-chain, and the latest state of a (stateful) application is also stored and kept on-chain.

keywords: zero-knowledge proofs, ZKP, multi-party computation, MPC, L2

## 1. Introduction

[It is documented](https://cointelegraph.com/magazine/satoshi-nakamoto-zk-proofs-bitcoin/) that the first time Satoshi (the inventor of Bitcoin) [mentioned zero-knowledge proofs](https://bitcointalk.org/index.php?topic=770.0), he found the technology interesting but did not know how to apply it.

![satoshi on zk](https://hackmd.io/_uploads/H1lKsnp8p.png)

3 years later, the [Zerocoin paper from Miers et al.](https://ieeexplore.ieee.org/document/6547123) was published at the 2013 IEEE Symposium on Security and Privacy, introducing a way to implement a cryptocurrency using zero-knowledge proofs. The paper was novel in that it successfuly managed to hide the sender, recipient, and amount being transfered in each transaction. 3 more years and a new cryptocurrency implementing the ideas from the Zerocoin paper and forking the codebase of Bitcoin was launching: [Zcash](https://z.cash/).

Today, Zcash still has no programmability (so-called smart contracts), and Bitcoin still has no support for zero-knowledge proofs. As cryptocurrencies are slow to make progress, new ones had to take advantage of all the recent advances in the field of zero-knowledge proofs. Cryptocurrencies like [Mina](https://minaprotocol.com/) and [Aleo](https://aleo.org/) were proposed as cryptocurrencies that provide programmable constructs augmented with zero-knowledge proofs (allowing applications to have privacy), other projects like [Aztec Network](https://aztec.network/) built on top of existing cryptocurrencies like Ethereum (as so-called "layer 2s") to provide similar privacy-enhance smart contracts.

While Zcash and the other technologies mentioned were big departure in design from Bitcoin, is it sensible that today Bitcoin could still benefit from zero-knowledge proofs without considerably changing its design. Bitcoin's scripting language is too limited to verify zero-knowledge proofs, but one could consider adding new opcodes to provide such a functionality (we discuss this further in the next section on related work). Unfortunately, this would be quite an important change that would require a hard-fork, and if previous history tells us anything such hard-forks often ends up splitting the community in two different versions of Bitcoin (the one that accepted the change, and the one that refused the change).

In this paper we introduce a different path: an extremely light service sitting on top of Bitcoin (so-called layer 2), and with no knowledge of the actual canonical blockchain of Bitcoin. The service splits the ownership of a Bitcoin wallet between a multi-party committee. The committee is then in charge of unlocking or updating a zero-knowledge application by signing user-provided transactions in the presence of valid user-provided proofs.

We released the code behind this paper in https://github.com/sigma0-xyz/zkbitcoin, and we are running a version of this project on the testnet (TODO: explorer + launch page link).

TODO: mention who is the committee that we are using?

The rest of this paper goes like this: section 2 talks about related work, section 3 gives an overview of the protocol, section 4 gives a more detailed specification of the protocol, section 5 discusses security, section 6 gives benchmarks, section 7 concludes and discusses future work.

## 2. Related work

In this section we survey zero-knowledge projects related to Bitcoin.

[ZeroSync](https://zerosync.org/zerosync.pdf) is a project that attempts to provide a verifiable light client for Bitcoin. That is, its goal is to create a zero-knowledge proof that verifies the integrity of the entirety of the canonical chain of Bitcoin at some point in time (also called "state proofs"). As such, it does not offer additional functionalities on top of Bitcoin, but can help external applications to make use of Bitcoin. 

[BitVM](https://bitvm.org/bitvm.pdf) is a proposal that does not use zero-knowledge proofs but is worth mentioning as it augments Bitcoin programmability with fraud proofs. That is, it allows users to lock funds using binary circuits, and unlock funds based on the execution of such circuits. If a user provides an incorrect execution, another user can then provide a fraud proof. The upside is that, like our proposal, it increases the size of what's possible in terms of smart contracts on Bitcoin. Unlike our proposal it does not provide any privacy. The downsides are also that it is quite an inefficient protocol as fraud proofs look unrealistic in practice, spanning over a number of transactions linear in size of the circuit.

[Alpen Labs](https://alpenlabs.io/) is a Layer 2 that settles on Bitcoin using a zero-knowledge proof of its state transitions (so-called "zk rollups"). Its proposition is the most straight-forward one: introducing a new op code (`OP_VERIFYSTARKPROOF`) to verify zero-knowledge proofs on Bitcoin. As we discussed in the introduction, this solution is the most elegant one, but it requires a hard-fork of Bitcoin.

![OP_VERIFYSTARKPROOF](https://hackmd.io/_uploads/Hkyh33pUT.png)

[Chainway](https://chainway.xyz/) is another "zk rollup" which settles on Bitcoin. There is currently little information about the project so it is not clear who verifies proofs and how funds go in and out of the layer 2.

## 3. Overview

## 4. Protocol

TODO: Copy zkapp doc from docs/

## 5. Security

* Key refresh from https://github.com/cronokirby/cait-sith/blob/main/docs/key-generation.md
* Committee could be a trusted set of entities (we're trying to figure out who would be interested)
* run MPC in SGX, and we could publish the SGX attestation that the shares were generated correctly
* after that, liveness could still be an issue, as currently the network might not have the best incentives to run (future work?)

## 6. Benchmarks

* we should try to run the protocol with like 100 participants and a threshold of 51? see how efficient it is (to me it looks like FROST is a very efficient protocol)
* maybe the FROST paper already has benchmarks?

## 7. Conclusion and Future work

## 8. References