use alloy_primitives::{keccak256, Address, Signature, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use serde::{Deserialize, Serialize};
use taiyi_primitives::PermitData;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ERC2612PermitMessage {
    owner: Address,
    spender: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Domain {
    name: String,
    version: String,
    chain_id: U256,
    verifying_contract: Address,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TypedData {
    types: Types,
    primary_type: String,
    domain: Domain,
    message: ERC2612PermitMessage,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Types {
    eip712_domain: Vec<Type>,
    permit: Vec<Type>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Type {
    name: String,
    #[serde(rename(serialize = "type"))]
    type_: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn sign_erc2612_permit(
    token: Address,
    spender: Address,
    value: U256,
    deadline: U256,
    nonce: U256,
    wallet: PrivateKeySigner,
    chain_id: U256,
    token_name: String,
) -> Result<PermitData, Box<dyn std::error::Error>> {
    let message = ERC2612PermitMessage { owner: wallet.address(), spender, value, nonce, deadline };

    let domain = get_domain(token, chain_id, token_name).await?;
    let typed_data = create_typed_erc2612_data(&message, &domain);
    let sig = sign_data(wallet, &typed_data).await?;

    let permit_data =
        PermitData::new(value, U256::from(deadline), sig.v().recid().to_byte(), sig.r(), sig.s());

    Ok(permit_data)
}

async fn get_domain(
    token: Address,
    chain_id: U256,
    name: String,
) -> Result<Domain, Box<dyn std::error::Error>> {
    let domain = Domain { name, version: "1".to_string(), chain_id, verifying_contract: token };
    Ok(domain)
}

fn create_typed_erc2612_data(message: &ERC2612PermitMessage, domain: &Domain) -> TypedData {
    let types = Types {
        eip712_domain: vec![
            Type { name: "name".to_string(), type_: "string".to_string() },
            Type { name: "version".to_string(), type_: "string".to_string() },
            Type { name: "chainId".to_string(), type_: "uint256".to_string() },
            Type { name: "verifyingContract".to_string(), type_: "address".to_string() },
        ],
        permit: vec![
            Type { name: "owner".to_string(), type_: "address".to_string() },
            Type { name: "spender".to_string(), type_: "address".to_string() },
            Type { name: "value".to_string(), type_: "uint256".to_string() },
            Type { name: "nonce".to_string(), type_: "uint256".to_string() },
            Type { name: "deadline".to_string(), type_: "uint256".to_string() },
        ],
    };

    TypedData {
        types,
        primary_type: "Permit".to_string(),
        domain: domain.clone(),
        message: message.clone(),
    }
}

async fn sign_data(
    wallet: PrivateKeySigner,
    typed_data: &TypedData,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let data = serde_json::to_string(&typed_data)?;
    let data_hash = keccak256(data.as_bytes());
    let sig = wallet.sign_message(&data_hash[..]).await?;
    Ok(sig)
}
