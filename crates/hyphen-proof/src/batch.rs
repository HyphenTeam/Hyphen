use crate::range_proof::{AggregatedRangeProof, ProofError, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;

pub fn batch_verify(proofs: &[(RangeProof, RistrettoPoint)]) -> Result<(), ProofError> {
    for (proof, commitment) in proofs {
        proof.verify(commitment)?;
    }
    Ok(())
}

pub fn batch_verify_aggregated(
    proofs: &[(AggregatedRangeProof, Vec<RistrettoPoint>)],
) -> Result<(), ProofError> {
    if proofs.is_empty() {
        return Ok(());
    }

    for (proof, commitments) in proofs {
        proof.verify(commitments)?;
    }
    Ok(())
}

pub fn batch_verify_mixed(
    singles: &[(RangeProof, RistrettoPoint)],
    aggregated: &[(AggregatedRangeProof, Vec<RistrettoPoint>)],
) -> Result<(), ProofError> {
    batch_verify(singles)?;
    batch_verify_aggregated(aggregated)?;
    Ok(())
}
