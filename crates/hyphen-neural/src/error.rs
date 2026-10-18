//! Error type shared by the prover, the verifier and the contract.
//!
//! The type is `Copy` and allocation-free so it can cross the WASM boundary as
//! a status code and be formatted by either side.

/// Everything that can make a challenge, a solution or a descriptor invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeuralError {
    /// A dimension is zero or above the compile-time maximum.
    InvalidSpec,
    /// A caller-supplied slice has the wrong length.
    InvalidBuffer,
    /// The flat weight buffer does not match the declared shape.
    InvalidWeights,
    /// The descriptor has an unknown version or an inconsistent field.
    InvalidDescriptor,
    /// The descriptor tolerance is zero or implausibly loose.
    InvalidTolerance,
    /// Encoded bytes are truncated, oversized or contain trailing data.
    InvalidEncoding,
    /// The solution width does not match the challenge shape.
    InvalidSolution,
    /// The solution did not meet the descriptor tolerance.
    NotSolved,
    /// The epoch is already open with a different descriptor.
    EpochConflict,
    /// The solver ran out of its configured budget without meeting tolerance.
    BudgetExhausted,
    /// The requested operation code is unknown.
    UnknownOperation,
    /// A host call failed.
    HostFailure,
}

impl NeuralError {
    /// Stable numeric code, used by the contract and by the CLI exit status.
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidSpec => 1,
            Self::InvalidBuffer => 2,
            Self::InvalidWeights => 3,
            Self::InvalidDescriptor => 4,
            Self::InvalidTolerance => 5,
            Self::InvalidEncoding => 6,
            Self::InvalidSolution => 7,
            Self::NotSolved => 8,
            Self::EpochConflict => 9,
            Self::BudgetExhausted => 10,
            Self::UnknownOperation => 11,
            Self::HostFailure => 12,
        }
    }

    /// Human-readable description.
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidSpec => "network shape is outside the accepted bounds",
            Self::InvalidBuffer => "scratch buffer is too small for the network shape",
            Self::InvalidWeights => "weight buffer does not match the network shape",
            Self::InvalidDescriptor => "challenge descriptor is malformed",
            Self::InvalidTolerance => "challenge tolerance is outside the accepted range",
            Self::InvalidEncoding => "encoding is truncated, oversized or has trailing bytes",
            Self::InvalidSolution => "solution width does not match the challenge",
            Self::NotSolved => "solution does not meet the challenge tolerance",
            Self::EpochConflict => "epoch was already opened with a different descriptor",
            Self::BudgetExhausted => "solver budget was exhausted before meeting tolerance",
            Self::UnknownOperation => "unknown operation code",
            Self::HostFailure => "contract host call failed",
        }
    }
}

impl core::fmt::Display for NeuralError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.message())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NeuralError {}
