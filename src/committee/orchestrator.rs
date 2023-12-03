use std::collections::{BTreeMap, HashMap};

use bitcoin::{taproot, TapSighashType, Txid, Witness};

use crate::{
    bob_request::{validate_request, BobRequest, BobResponse},
    constants::{FEE_BITCOIN_SAT, FEE_ZKBITCOIN_SAT},
    json_rpc_stuff::{json_rpc_request, send_raw_transaction, RpcCtx, TransactionOrHex},
    mpc_sign_tx::create_transaction,
};

use super::node::{get_digest_to_hash, Round2Request, Round2Response};

//
// Orchestration logic
//

pub struct Member {
    /// e.g. "127.0.0.1:8887"
    address: String,
}

pub struct Orchestrator {
    pub bitcoin_rpc_ctx: RpcCtx,
    pub threshold: usize,
    pub pubkey_package: frost_secp256k1::keys::PublicKeyPackage,
    pub committee: HashMap<frost_secp256k1::Identifier, Member>,
}

impl Orchestrator {
    pub fn new(
        bitcoin_rpc_ctx: RpcCtx,
        threshold: usize,
        pubkey_package: frost_secp256k1::keys::PublicKeyPackage,
        committee: HashMap<frost_secp256k1::Identifier, Member>,
    ) -> Self {
        Self {
            bitcoin_rpc_ctx,
            threshold,
            pubkey_package,
            committee,
        }
    }

    /// Handles bob request from A to Z.
    pub async fn handle_request(&self, bob_request: BobRequest) -> Result<Txid, &'static str> {
        //
        // Validate transaction before forwarding it, and get smart contract
        //

        let smart_contract = validate_request(&self.bitcoin_rpc_ctx, &bob_request, None).await?;

        //
        // Round 1
        //

        let mut commitments_map = BTreeMap::new();

        // TODO: do this concurrently with async
        // TODO: take a random sample instead of the first `threshold` members
        // TODO: what if we get a timeout or can't meet that threshold? loop? send to more members?
        for (member_id, member) in self.committee.iter().take(self.threshold) {
            // send json RPC request
            let rpc_ctx = RpcCtx {
                version: Some("2.0"),
                wallet: None,
                address: Some(member.address.clone()),
                auth: None,
            };
            let resp = json_rpc_request(
                &rpc_ctx,
                "round_1_signing",
                &[serde_json::value::to_raw_value(&bob_request).unwrap()],
            )
            .await
            .map_err(|e| {
                println!("error: {e}");
                "unlock_funds error"
            })?;

            let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp).unwrap();
            let bob_response: BobResponse = response.result().unwrap();

            // store the commitment
            commitments_map.insert(*member_id, bob_response.commitments);
        }

        //
        // Round 2
        //

        let mut signature_shares = BTreeMap::new();

        let round2_request = Round2Request {
            txid: bob_request.txid,
            proof_hash: bob_request.proof.hash(),
            commitments_map: commitments_map.clone(),
        };

        // TODO: do this concurrently with async
        // TODO: take a random sample instead of the first `threshold` members
        // TODO: what if we get a timeout or can't meet that threshold? loop? send to more members?
        for (member_id, member) in self.committee.iter().take(self.threshold) {
            // send json RPC request
            let rpc_ctx = RpcCtx {
                version: Some("2.0"),
                wallet: None,
                address: Some(member.address.clone()),
                auth: None,
            };
            let resp = json_rpc_request(
                &rpc_ctx,
                "round_2_signing",
                &[serde_json::value::to_raw_value(&round2_request).unwrap()],
            )
            .await
            .map_err(|e| {
                println!("error: {e}");
                "unlock_funds error"
            })?;

            let response: bitcoincore_rpc::jsonrpc::Response = serde_json::from_str(&resp).unwrap();
            let round2_response: Round2Response = response.result().unwrap();

            // store the commitment
            signature_shares.insert(*member_id, round2_response.signature_share);
        }

        //
        // Produce transaction and digest
        //

        let bob_address = bob_request.get_bob_address()?;
        let utxo = (bob_request.txid, smart_contract.vout_of_zkbitcoin_utxo);
        let mut transaction = create_transaction(
            utxo,
            smart_contract.locked_value,
            bob_address,
            FEE_BITCOIN_SAT,
            FEE_ZKBITCOIN_SAT,
        );
        let message = get_digest_to_hash(&transaction, &smart_contract);

        //
        // Aggregate signatures
        //

        let signing_package = frost_secp256k1::SigningPackage::new(commitments_map, &message);
        let group_signature =
            frost_secp256k1::aggregate(&signing_package, &signature_shares, &self.pubkey_package)
                .map_err(|_| "failed to aggregate signatures")?;

        //
        // Include signature in the witness of the transaction
        //

        let sig = todo!(); // TODO: convert group_signature

        let hash_ty = TapSighashType::All;
        let final_signature = taproot::Signature { sig, hash_ty };
        let mut witness = Witness::new();
        witness.push(final_signature.to_vec());
        transaction.input[0].witness = witness; // TODO: is it always the first input?

        //
        // Broadcast transaction
        //

        let txid = send_raw_transaction(
            &self.bitcoin_rpc_ctx,
            TransactionOrHex::Transaction(&transaction),
        )
        .await?;

        Ok(txid)
    }
}
