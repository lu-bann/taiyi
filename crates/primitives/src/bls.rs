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
    Ok(Signature::deserialize(bytes.as_ref()).unwrap())
}

pub fn serialize_bls_publickey<S: serde::Serializer>(
    public_key: &PublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(&public_key.serialize())
}
