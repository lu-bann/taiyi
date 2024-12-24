use alloy_primitives::{hex::FromHex, keccak256, Address, StorageKey, U256};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_sol_types::sol;
use alloy_transport_http::Http;
use k256::pkcs8::der;
use lazy_static::lazy_static;
use reqwest::{Client, Url};

sol! {
    #[sol(rpc)]
    contract TaiyiEscrow {
        #[derive(Debug)]
        function balanceOf(address user) public view returns (uint256);

        #[derive(Debug)]
        function deposit() public payable;
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionClient {
    inner: RootProvider<Http<Client>>,
}

impl ExecutionClient {
    pub fn new(rpc_url: Url) -> Self {
        ExecutionClient { inner: ProviderBuilder::new().on_http(rpc_url) }
    }

    pub async fn get_account_state(&self, address: Address) -> eyre::Result<AccountState> {
        let account = self.inner.get_account(address).await?;
        Ok(AccountState { nonce: account.nonce, balance: account.balance })
    }

    pub async fn base_fee(&self) -> eyre::Result<u128> {
        let fees = self.inner.estimate_eip1559_fees(None).await?;
        Ok(fees.max_fee_per_gas)
    }

    /// Get the balance of an account in the escrow contract.
    ///
    /// * `escrow` - The escrow contract address.
    /// * `account`-  The account address to get the balance of.
    pub async fn escrow_balance(&self, escrow: Address, account: Address) -> eyre::Result<U256> {
        // mapping slots are generated by hashing the key concatenated with the storage index.
        let storage_key = keccak256(format!("{}{}", account, *BALANCE_STORAGE_SLOT));
        let resutl =
            self.inner.get_storage_at(escrow, storage_key.into()).await.unwrap_or_default();
        Ok(resutl)
    }

    pub async fn balance_of(&self, account: Address) -> eyre::Result<U256> {
        let taiyi_escrow = TaiyiEscrow::new(
            "0xA791D59427B2b7063050187769AC871B497F4b3C".parse()?,
            self.inner.clone(),
        );
        let balance = taiyi_escrow.balanceOf(account).call().await?;
        Ok(balance._0)
    }
}

lazy_static! {
    /// mapping(address => uint256) public balances
    pub static ref BALANCE_STORAGE_SLOT: StorageKey =
        StorageKey::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").expect("");
}

#[derive(Debug, Clone)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
}
