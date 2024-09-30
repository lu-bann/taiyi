use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::k256::ecdsa::SigningKey;
use alloy_signer_local::{coins_bip39::English, LocalSigner, MnemonicBuilder};
use alloy_sol_types::sol;
use bip39::{Mnemonic, Seed};
use clap::Parser;
use eth2_keystore::keypair_from_secret;
use eth2_wallet::recover_validator_secret_from_mnemonic;
use tracing::info;
use TaiyiProposerRegistry::TaiyiProposerRegistryInstance;

#[derive(Debug, Parser)]
pub struct TaiyiStakeCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// validator phrase
    #[clap(long = "validator_phrase")]
    pub validator_phrase: String,

    /// taiyi proposer registry contract address
    #[clap(long = "taiyi_proposer_registry_contract_addr")]
    pub taiyi_proposer_registry_contract_addr: String,

    /// funded key to send ether to validator
    #[clap(long = "funded_private_key")]
    pub funded_private_key: String,

    /// generate validator key from min_index to max_index
    #[clap(long = "min_index")]
    pub min_index: u32,

    /// generate validator key from min_index to max_index
    #[clap(long = "max_index")]
    pub max_index: u32,
}

sol! {
    #[sol(rpc)]
    contract TaiyiProposerRegistry {
        #[derive(Debug)]
        function optIn(bytes calldata _blsPubKey) external payable;
    }
}

impl TaiyiStakeCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        let key_bytes = hex::decode(self.funded_private_key.clone())?;
        let from_signer = LocalSigner::from_signing_key(SigningKey::from_slice(&key_bytes)?);
        let mut wallet = EthereumWallet::new(from_signer.clone());
        for index in self.min_index..self.max_index {
            let validator_signer = MnemonicBuilder::<English>::default()
                .phrase(self.validator_phrase.clone())
                .index(index)?
                .build()?;
            wallet.register_signer(validator_signer);
        }
        info!("Wallet initialized successfully.");
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_builtin(&self.rpc_url)
            .await?;
        let taiyi_proposer_address: Address = self.taiyi_proposer_registry_contract_addr.parse()?;
        let taiyi_proposer_registry =
            TaiyiProposerRegistryInstance::new(taiyi_proposer_address, provider.clone());
        for index in self.min_index..self.max_index {
            info!("OptIn Validator with index: {}", index);
            let validator_signer = MnemonicBuilder::<English>::default()
                .phrase(self.validator_phrase.clone())
                .index(index)?
                .build()?;

            let res = provider
                .send_transaction(
                    TransactionRequest::default()
                        .from(from_signer.address())
                        .to(validator_signer.address())
                        .value(U256::from(32100000000000000000u128)),
                )
                .await?
                .get_receipt()
                .await?;
            info!(
                "Sent 32.1 ether from funded {} to {} with tx hash {:?}",
                from_signer.address(),
                validator_signer.address(),
                res.transaction_hash
            );
            let mnenonic = Mnemonic::from_phrase(&self.validator_phrase, bip39::Language::English)
                .expect("mnemonic not good");
            let seed = Seed::new(&mnenonic, "");
            let (wallet, _) = recover_validator_secret_from_mnemonic(
                seed.as_bytes(),
                index,
                eth2_wallet::KeyType::Voting,
            )
            .expect("recover validator secret failed");
            let keypair = keypair_from_secret(wallet.as_bytes()).expect("keypair not good");
            let bls_pub_key = Bytes::from(keypair.pk.serialize());
            let tx = taiyi_proposer_registry.optIn(bls_pub_key).into_transaction_request();
            let tx =
                tx.value(U256::from(32000000000000000000u128)).from(validator_signer.address());
            let res = provider.send_transaction(tx).await?;
            info!(
                "OptIn Validator BLS public key: {:} with {:?}",
                keypair.pk.as_hex_string(),
                res.tx_hash()
            );
        }
        Ok(())
    }
}
