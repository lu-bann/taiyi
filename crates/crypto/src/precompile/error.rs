#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PrecompileError {
    /// Fatal error with a custom error message
    Fatal(String),
    /// Catch-all variant for other errors
    Other(String),
}
