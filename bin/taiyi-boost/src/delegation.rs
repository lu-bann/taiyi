use alloy_rpc_types_beacon::BlsPublicKey;
use beacon_api_client::ProposerDuty;
use cb_common::pbs::RelayClient;
use commit::client::SignerClient;
use commit_boost::prelude::*;
use eyre::Result;
use futures::future::join_all;
use reqwest::Client;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, info};

use crate::types::{ElectPreconferRequest, SignedRequest, ELECT_PRECONFER_PATH};

pub struct DelegationService {
    pub chain_id: u64,
    pub trusted_preconfer: BlsPublicKey,
    pub signer_client: SignerClient,
    pub relays: Vec<RelayClient>,
    duties_rx: UnboundedReceiver<Vec<ProposerDuty>>,
}

impl DelegationService {
    pub fn new(
        chain_id: u64,
        trusted_preconfer: BlsPublicKey,
        signer_client: SignerClient,
        relays: Vec<RelayClient>,
        duties_rx: UnboundedReceiver<Vec<ProposerDuty>>,
    ) -> Self {
        Self { chain_id, trusted_preconfer, signer_client, relays, duties_rx }
    }
    pub async fn run(mut self) -> Result<()> {
        let pubkeys = self.signer_client.get_pubkeys().await?.keys;
        let consensus_pubkeys: Vec<BlsPublicKey> =
            pubkeys.iter().map(|pk| pk.clone().consensus.into()).collect();
        info!(consensus_pubkeys = %serde_json::to_string_pretty(&consensus_pubkeys).expect("consensus pubkeys wrong format"), "Received consensus_pubkeys");
        while let Some(duties) = self.duties_rx.recv().await {
            let l = duties.len();
            let our_duties: Vec<_> = duties
                .into_iter()
                .filter(|d| {
                    consensus_pubkeys.contains(
                        &BlsPublicKey::try_from(d.public_key.as_slice())
                            .expect("public key wrong format"),
                    )
                })
                .collect();

            info!("Received {l} duties, we have {} to elect", our_duties.len());

            for duty in our_duties {
                // this could be done in parallel
                if let Err(err) = self.elect_preconfer(duty).await {
                    error!("Failed to elect preconfer: {err}");
                };
            }
        }
        Ok(())
    }
    async fn elect_preconfer(&self, duty: ProposerDuty) -> Result<()> {
        let elect_preconfer_req = ElectPreconferRequest {
            preconfer_pubkey: self.trusted_preconfer,
            slot_number: duty.slot,
            chain_id: self.chain_id,
            gas_limit: 0,
        };
        let signature_req = SignConsensusRequest::builder(
            BlsPublicKey::try_from(duty.public_key.as_slice())
                .expect("public key wrong format")
                .into(),
        )
        .with_msg(&elect_preconfer_req);
        let signature = self.signer_client.request_consensus_signature(signature_req).await?;
        let signed_req =
            SignedRequest::<ElectPreconferRequest> { message: elect_preconfer_req, signature };
        let mut handles = Vec::new();

        info!("Received delegation signature: {signature}");
        info!(
            "Sending delegation {}",
            serde_json::to_string(&signed_req).expect("signed req wrong format")
        );
        for relay in &self.relays {
            let elec_preconfer_url = relay
                .builder_api_url(ELECT_PRECONFER_PATH)
                .expect("failed to build elect preconfer url");
            let client = Client::new();
            handles.push(client.post(elec_preconfer_url).json(&signed_req).send());
        }

        let results = join_all(handles).await;

        for res in results {
            match res {
                Ok(response) => {
                    let status = response.status();
                    let response_bytes = response.bytes().await?;
                    let ans = String::from_utf8_lossy(&response_bytes).into_owned();
                    if !status.is_success() {
                        error!(err = ans, ?status, "failed sending delegation sign request");
                        continue;
                    }

                    info!("Successful election: {ans:?}")
                }
                Err(err) => error!("Failed election: {err}"),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ethereum_consensus::primitives::BlsPublicKey as ConsensusBlsPublicKey;

    use super::*;

    #[test]
    // test conversion between alloy BlsPublicKey and ethereum-consunsus BlsPublicKey
    fn test_bls_pubkey_conversion() {
        let pubkey_slice: &[u8] = &[1; 48];
        let alloy_bls_pubkey = BlsPublicKey::try_from(pubkey_slice).unwrap();
        let consensus_bls_pubkey = ConsensusBlsPublicKey::try_from(pubkey_slice).unwrap();
        assert_eq!(alloy_bls_pubkey.as_slice(), consensus_bls_pubkey.as_slice());
        assert_eq!(
            alloy_bls_pubkey,
            BlsPublicKey::try_from(consensus_bls_pubkey.as_slice()).unwrap()
        );
        assert_eq!(
            consensus_bls_pubkey,
            ConsensusBlsPublicKey::try_from(alloy_bls_pubkey.as_slice()).unwrap()
        );
    }
}
