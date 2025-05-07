#[derive(Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum PrecompileError {
    /// Catch-all variant for other errors
    #[error("bls calculation error: {0}")]
    Other(String),
}
