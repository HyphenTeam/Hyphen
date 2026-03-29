use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("serialisation error: {0}")]
    Serialisation(String),

    #[error("block validation failed: {0}")]
    Validation(String),

    #[error("block not found: {0}")]
    BlockNotFound(String),

    #[error("invalid block height: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },

    #[error("timestamp too far in the future")]
    FutureTimestamp,

    #[error("difficulty check failed")]
    DifficultyFailed,

    #[error("PoW verification failed")]
    PowFailed,

    #[error("transaction root mismatch")]
    TxRootMismatch,

    #[error("commitment root mismatch")]
    CommitmentRootMismatch,

    #[error("nullifier root mismatch")]
    NullifierRootMismatch,

    #[error("duplicate nullifier: {0}")]
    DuplicateNullifier(String),

    #[error("insufficient fee")]
    InsufficientFee,

    #[error("block too large")]
    BlockTooLarge,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("configuration error: {0}")]
    Config(String),
}
