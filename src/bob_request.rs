/// A request from Bob to unlock funds from a smart contract should look like this.
pub struct BobRequest {
    /// The transaction ID that deployed the smart contract.
    pub txid: bitcoin::Txid,

    /// The verifier key authenticated by the deployed transaction.
    pub vk: (),

    /// A proof.
    pub proof: (),

    /// Any additional public inputs used in the proof (if any).
    pub public_inputs: Vec<()>,
}
