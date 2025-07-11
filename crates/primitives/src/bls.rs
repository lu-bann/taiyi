pub type PublicKey = blst::min_pk::PublicKey;
pub type SecretKey = blst::min_pk::SecretKey;
pub type Signature = blst::min_pk::Signature;

pub fn serialize_bls_signature<S: serde::Serializer>(
    sig: &Signature,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(&sig.serialize())
}

pub fn deserialize_bls_signature<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Signature, D::Error> {
    let bytes = <String as serde::Deserialize>::deserialize(deserializer)?;
    Signature::deserialize(bytes.as_ref())
        .map_err(|err| <D::Error as serde::de::Error>::custom(format!("{:?}", err)))
}

pub fn serialize_bls_publickey<S: serde::Serializer>(
    public_key: &PublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(&public_key.serialize())
}

pub fn bls_pubkey_to_alloy(pubkey: &PublicKey) -> alloy::rpc::types::beacon::BlsPublicKey {
    alloy::rpc::types::beacon::BlsPublicKey::from_slice(&pubkey.compress())
}

pub fn bls_signature_to_alloy(signature: &Signature) -> alloy::rpc::types::beacon::BlsSignature {
    alloy::rpc::types::beacon::BlsSignature::from_slice(&signature.compress())
}
