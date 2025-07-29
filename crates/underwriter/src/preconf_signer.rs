use alloy::primitives::{Address, Signature};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use std::future::Future;
use taiyi_primitives::PreconfRequest;

#[cfg_attr(test, mockall::automock)]
pub trait PreconfSigner {
    fn sign(&self, request: PreconfRequest) -> impl Future<Output = eyre::Result<Signature>>;
    fn address(&self) -> Address;
}

#[derive(Debug, Clone)]
pub struct EcdsaSigner {
    signer: PrivateKeySigner,
    chain_id: u64,
}

impl EcdsaSigner {
    pub fn new(signer: PrivateKeySigner, chain_id: u64) -> Self {
        Self { signer, chain_id }
    }
}

impl PreconfSigner for EcdsaSigner {
    async fn sign(&self, request: PreconfRequest) -> eyre::Result<Signature> {
        let signature = self.signer.sign_hash(&request.digest(self.chain_id)).await?;
        Ok(signature)
    }
    fn address(&self) -> Address {
        self.signer.address()
    }
}
