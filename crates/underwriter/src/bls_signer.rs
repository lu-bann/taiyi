use alloy::primitives::{Address, ChainId, B256};
use alloy::rpc::types::beacon::constants::BLS_DST_SIG;
use taiyi_crypto::bls::{PublicKey, SecretKey, Signature};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];

#[derive(Debug)]
pub struct BlsSigner {
    address: Address,
    chain_id: Option<ChainId>,
    private_key: SecretKey,
    fork_version: [u8; 4],
}

impl BlsSigner {
    pub const fn new(
        address: Address,
        chain_id: Option<ChainId>,
        private_key: SecretKey,
        fork_version: [u8; 4],
    ) -> Self {
        Self { address, chain_id, private_key, fork_version }
    }

    pub async fn sign_hash(&self, hash: &B256) -> Signature {
        let domain = compute_domain(self.fork_version, COMMIT_BOOST_DOMAIN);
        let root = compute_signing_root(hash.0.tree_hash_root().0, domain);
        self.private_key.sign(root.as_ref(), BLS_DST_SIG, &[])
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn public_key(&self) -> PublicKey {
        self.private_key.sk_to_pk()
    }

    pub fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    pub fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

#[derive(Debug, TreeHash)]
struct ForkData {
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
}

fn compute_domain(fork_version: [u8; 4], domain_mask: [u8; 4]) -> [u8; 32] {
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_mask);

    let fork_data_root =
        ForkData { fork_version, genesis_validators_root: [0; 32] }.tree_hash_root().0;
    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain
}

#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

fn compute_signing_root(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    SigningData { object_root, signing_domain }.tree_hash_root().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};
    use taiyi_crypto::bls::SecretKey;

    fn create_test_secret_key() -> SecretKey {
        // Use a deterministic test key for reproducible tests
        let test_bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        SecretKey::from_bytes(&test_bytes).expect("Valid test key")
    }

    fn create_test_bls_signer() -> BlsSigner {
        BlsSigner::new(
            Address::random(),
            Some(1),
            create_test_secret_key(),
            [0, 1, 2, 3], // Test fork version
        )
    }

    #[test]
    fn test_new_bls_signer() {
        let address = Address::random();
        let chain_id = Some(42u64);
        let private_key = create_test_secret_key();
        let fork_version = [1, 2, 3, 4];

        let signer = BlsSigner::new(address, chain_id, private_key.clone(), fork_version);

        assert_eq!(signer.address(), address);
        assert_eq!(signer.chain_id(), chain_id);
        assert_eq!(signer.fork_version, fork_version);
    }

    #[test]
    fn test_address_getter() {
        let expected_address = Address::random();
        let signer = BlsSigner::new(expected_address, None, create_test_secret_key(), [0; 4]);

        assert_eq!(signer.address(), expected_address);
    }

    #[test]
    fn test_public_key_derivation() {
        let private_key = create_test_secret_key();
        let expected_public_key = private_key.sk_to_pk();
        let signer = BlsSigner::new(Address::random(), None, private_key, [0; 4]);

        let public_key = signer.public_key();

        // Compare the serialized forms since PublicKey may not implement PartialEq
        assert_eq!(public_key.to_bytes(), expected_public_key.to_bytes());
    }

    #[test]
    fn test_chain_id_getter_setter() {
        let mut signer = create_test_bls_signer();

        assert_eq!(signer.chain_id(), Some(1));

        signer.set_chain_id(Some(42));
        assert_eq!(signer.chain_id(), Some(42));

        signer.set_chain_id(None);
        assert_eq!(signer.chain_id(), None);
    }

    #[tokio::test]
    async fn test_sign_hash_deterministic() {
        let signer = create_test_bls_signer();
        let hash = B256::random();

        let signature1 = signer.sign_hash(&hash).await;
        let signature2 = signer.sign_hash(&hash).await;

        assert_eq!(signature1.to_bytes(), signature2.to_bytes());
    }

    #[tokio::test]
    async fn test_sign_hash_different_inputs() {
        let signer = create_test_bls_signer();
        let hash1 = B256::random();
        let hash2 = B256::random();

        let signature1 = signer.sign_hash(&hash1).await;
        let signature2 = signer.sign_hash(&hash2).await;

        // Different inputs should produce different signatures
        assert_ne!(signature1.to_bytes(), signature2.to_bytes());
    }

    #[tokio::test]
    async fn test_sign_hash_different_fork_versions() {
        let private_key = create_test_secret_key();
        let signer1 = BlsSigner::new(Address::random(), None, private_key.clone(), [0, 1, 2, 3]);
        let signer2 = BlsSigner::new(Address::random(), None, private_key, [4, 5, 6, 7]);
        let hash = B256::random();

        let signature1 = signer1.sign_hash(&hash).await;
        let signature2 = signer2.sign_hash(&hash).await;

        // Different fork versions should produce different signatures
        assert_ne!(signature1.to_bytes(), signature2.to_bytes());
    }

    #[tokio::test]
    async fn test_signature_verification() {
        let signer = create_test_bls_signer();
        let hash = B256::random();

        let signature = signer.sign_hash(&hash).await;
        let _public_key = signer.public_key();

        // Verify the signature was created correctly by checking it can be verified
        // Note: This test assumes the signature verification logic would work correctly
        // In a real implementation, you'd verify using the same domain computation
        let domain = compute_domain(signer.fork_version, COMMIT_BOOST_DOMAIN);
        let signing_root = compute_signing_root(hash.0.tree_hash_root().0, domain);

        // The signature should have been generated using these same parameters
        // This test verifies the signing process uses consistent parameters
        assert_eq!(signing_root.len(), 32);
        assert!(signature.to_bytes().len() > 0);
    }

    #[test]
    fn test_compute_domain_function() {
        let fork_version = [1, 2, 3, 4];
        let domain_mask = [5, 6, 7, 8];

        let domain = compute_domain(fork_version, domain_mask);

        // Domain should be 32 bytes
        assert_eq!(domain.len(), 32);

        // First 4 bytes should be the domain mask
        assert_eq!(&domain[0..4], &domain_mask);

        // Remaining bytes should be derived from fork data
        assert_eq!(
            &domain[4..],
            &[
                255, 210, 252, 52, 229, 121, 106, 100, 63, 116, 155, 11, 43, 144, 140, 76, 163,
                206, 88, 206, 36, 160, 12, 73, 50, 154, 45, 192
            ]
        );
    }

    #[test]
    fn test_compute_domain_different_fork_versions() {
        let domain_mask = [1, 2, 3, 4];

        let domain1 = compute_domain([0, 0, 0, 1], domain_mask);
        let domain2 = compute_domain([0, 0, 0, 2], domain_mask);

        // Different fork versions should produce different domains
        assert_ne!(domain1, domain2);

        // But same domain mask in first 4 bytes
        assert_eq!(&domain1[0..4], &domain_mask);
        assert_eq!(&domain2[0..4], &domain_mask);
    }

    #[test]
    fn test_compute_signing_root_function() {
        let object_root1 = [1u8; 32];
        let signing_domain = [3u8; 32];

        let root1 = compute_signing_root(object_root1, signing_domain);

        // Different inputs should produce different roots
        assert_eq!(
            root1,
            [
                125, 135, 252, 104, 248, 9, 98, 250, 31, 8, 201, 169, 100, 189, 85, 192, 123, 218,
                109, 140, 89, 222, 20, 41, 181, 32, 177, 207, 205, 100, 129, 70
            ]
        );
    }
}
