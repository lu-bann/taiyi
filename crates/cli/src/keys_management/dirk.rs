// codes are basically copied from https://github.com/chainbound/bolt/blob/89253d92b079adf0abf6c9279eeed1d5dc7a3aed/bolt-cli/src/common/dirk.rs
use std::fs;

use alloy_primitives::B256;
use clap::Parser;
use eyre::{bail, Context, Result};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::debug;

use crate::keys_management::{
    pb::eth2_signer_api::{
        Account, AccountManagerClient, ListAccountsRequest, ListerClient, LockAccountRequest,
        ResponseState, SignRequest, SignRequestId, SignerClient, UnlockAccountRequest,
    },
    signing::BLS_SIGNATURE_BYTES_LEN,
};
use taiyi_crypto::bls::Signature as BlsSignature;

/// Options for connecting to a DIRK keystore.
#[derive(Debug, Clone, Parser)]
pub struct DirkOpts {
    /// The URL of the DIRK keystore.
    #[clap(long, env = "DIRK_URL")]
    pub url: String,

    /// The path of the wallets in the DIRK keystore.
    #[clap(long, env = "DIRK_WALLET_PATH")]
    pub wallet_path: String,

    /// The passphrases to unlock the wallet in the DIRK keystore.
    /// If multiple are provided, they are tried in order until one works.
    #[clap(long, env = "DIRK_PASSPHRASES", value_delimiter = ',', hide_env_values = true)]
    pub passphrases: Option<Vec<String>>,

    /// The TLS credentials for connecting to the DIRK keystore.
    #[clap(flatten)]
    pub tls_credentials: TlsCredentials,
}

/// TLS credentials for connecting to a remote server.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct TlsCredentials {
    /// Path to the client certificate file. (.crt)
    #[clap(long, env = "CLIENT_CERT_PATH")]
    pub client_cert_path: String,
    /// Path to the client key file. (.key)
    #[clap(long, env = "CLIENT_KEY_PATH")]
    pub client_key_path: String,
    /// Path to the CA certificate file. (.crt)
    #[clap(long, env = "CA_CERT_PATH")]
    pub ca_cert_path: Option<String>,
}

/// A Dirk remote signer.
///
/// Available services:
/// - `Lister`: List accounts in the keystore.
/// - `Signer`: Request a signature from the remote signer.
/// - `AccountManager`: Manage accounts in the keystore (lock and unlock accounts).
///
/// Reference: https://github.com/attestantio/dirk
#[derive(Clone)]
pub struct Dirk {
    lister: ListerClient<Channel>,
    signer: SignerClient<Channel>,
    account_mng: AccountManagerClient<Channel>,
}

impl Dirk {
    /// Connect to the DIRK server with the given address and TLS credentials.
    pub async fn connect(addr: String, credentials: TlsCredentials) -> Result<Self> {
        let addr = addr.parse()?;
        let tls_config = compose_credentials(credentials)?;
        let conn = Channel::builder(addr).tls_config(tls_config)?.connect().await?;

        let lister = ListerClient::new(conn.clone());
        let signer = SignerClient::new(conn.clone());
        let account_mng = AccountManagerClient::new(conn);

        Ok(Self { lister, signer, account_mng })
    }

    /// List all accounts in the keystore.
    pub async fn list_accounts(&mut self, wallet_path: String) -> Result<Vec<Account>> {
        // Request all accounts in the given path. Only one path at a time
        // as done in https://github.com/wealdtech/go-eth2-wallet-dirk/blob/182f99b22b64d01e0d4ae67bf47bb055763465d7/grpc.go#L121
        let req = ListAccountsRequest { paths: vec![wallet_path] };
        let res = self.lister.list_accounts(req).await?.into_inner();

        if !matches!(res.state(), ResponseState::Succeeded) {
            bail!("Failed to list accounts: {:?}", res);
        }

        debug!("{} Accounts listed successfully", res.accounts.len());
        Ok(res.accounts)
    }

    /// Unlock an account in the keystore with the given passphrase.
    pub async fn unlock_account(
        &mut self,
        account_name: String,
        passphrase: String,
    ) -> Result<bool> {
        let pf_bytes = passphrase.as_bytes().to_vec();
        let req = UnlockAccountRequest { account: account_name.clone(), passphrase: pf_bytes };
        let res = self.account_mng.unlock(req).await?.into_inner();

        match res.state() {
            ResponseState::Succeeded => {
                debug!("Unlock request succeeded for account {}", account_name);
                Ok(true)
            }
            ResponseState::Denied => {
                debug!("Unlock request denied for account {}", account_name);
                Ok(false)
            }
            ResponseState::Unknown => bail!("Unknown response from unlock account: {:?}", res),
            ResponseState::Failed => bail!("Failed to unlock account: {:?}", res),
        }
    }

    /// Lock an account in the keystore.
    pub async fn lock_account(&mut self, account_name: String) -> Result<bool> {
        let req = LockAccountRequest { account: account_name.clone() };
        let res = self.account_mng.lock(req).await?.into_inner();

        match res.state() {
            ResponseState::Succeeded => {
                debug!("Lock request succeeded for account {}", account_name);
                Ok(true)
            }
            ResponseState::Denied => {
                debug!("Lock request denied for account {}", account_name);
                Ok(false)
            }
            ResponseState::Unknown => bail!("Unknown response from lock account: {:?}", res),
            ResponseState::Failed => bail!("Failed to lock account: {:?}", res),
        }
    }

    /// Request a signature from the remote signer.
    pub async fn request_signature(
        &mut self,
        account: &Account,
        hash: B256,
        domain: B256,
    ) -> Result<BlsSignature> {
        let req = SignRequest {
            data: hash.to_vec(),
            domain: domain.to_vec(),
            id: Some(SignRequestId::Account(account.name.clone())),
        };

        let res = self.signer.sign(req).await?.into_inner();

        if !matches!(res.state(), ResponseState::Succeeded) {
            bail!("Failed to sign data: {:?}", res);
        }
        if res.signature.is_empty() {
            bail!("Empty signature returned");
        }
        if res.signature.len() != BLS_SIGNATURE_BYTES_LEN {
            bail!(
                "Invalid signature length: expected {} but got {}",
                BLS_SIGNATURE_BYTES_LEN,
                res.signature.len()
            );
        }
        let sig =
            BlsSignature::deserialize(res.signature.as_slice()).expect("Failed to parse signature");

        debug!("Signature request succeeded for account {}", account.name);
        Ok(sig)
    }
}

/// Compose the TLS credentials from the given paths.
fn compose_credentials(creds: TlsCredentials) -> Result<ClientTlsConfig> {
    let client_cert = fs::read(creds.client_cert_path).wrap_err("Failed to read client cert")?;
    let client_key = fs::read(creds.client_key_path).wrap_err("Failed to read client key")?;

    // Create client identity (certificate + key)
    let identity = Identity::from_pem(&client_cert, &client_key);

    // Configure the TLS client
    let mut tls_config = ClientTlsConfig::new().identity(identity);

    // Add CA certificate if provided
    if let Some(ca_path) = creds.ca_cert_path {
        let ca_cert = fs::read(ca_path).wrap_err("Failed to read CA certificate")?;
        tls_config = tls_config.ca_certificate(Certificate::from_pem(&ca_cert));
    }

    Ok(tls_config)
}
