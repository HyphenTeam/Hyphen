//! Crash-recovery coordination for a validated multi-block reorganisation.
//!
//! The coordinator deliberately contains no consensus or state-validation
//! logic. A backend must make every individual attach/detach atomic and must
//! reject blocks whose state transition is invalid.

use std::collections::HashSet;
use std::fmt::Display;

use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::branch_store::ReorgPlan;

const JOURNAL_KEY: &[u8] = b"active";
const JOURNAL_VERSION: u16 = 1;
pub const MAX_REORG_PATH_BLOCKS: usize = 4_096;
pub const MAX_REJECTION_REASON_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReorgMode {
    ApplyingCandidate,
    RestoringOriginal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgJournal {
    pub version: u16,
    pub common_ancestor: Hash256,
    /// Original canonical blocks, ordered from the old tip backwards.
    pub detach: Vec<Hash256>,
    /// Candidate blocks, ordered from the common ancestor forwards.
    pub attach: Vec<Hash256>,
    pub old_work: u128,
    pub new_work: u128,
    pub mode: ReorgMode,
    pub rejection_reason: Option<String>,
}

impl From<ReorgPlan> for ReorgJournal {
    fn from(plan: ReorgPlan) -> Self {
        Self {
            version: JOURNAL_VERSION,
            common_ancestor: plan.common_ancestor,
            detach: plan.detach,
            attach: plan.attach,
            old_work: plan.old_work,
            new_work: plan.new_work,
            mode: ReorgMode::ApplyingCandidate,
            rejection_reason: None,
        }
    }
}

pub trait ReorgBackend {
    type Error: Display;

    fn tip(&self) -> Result<Hash256, Self::Error>;
    /// Atomically detach `expected`; an error must leave the backend unchanged.
    fn detach_tip(&mut self, expected: Hash256) -> Result<(), Self::Error>;
    /// Atomically attach `block`; an error must leave the backend unchanged.
    fn attach(&mut self, block: Hash256) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReorgOutcome {
    AppliedCandidate { new_tip: Hash256 },
    RestoredOriginal { old_tip: Hash256, reason: String },
}

#[derive(Debug, Error)]
pub enum ReorgCoordinatorError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("reorg journal serialisation error: {0}")]
    Serde(String),
    #[error("unsupported reorg journal version {0}")]
    UnsupportedVersion(u16),
    #[error("a reorg journal is already pending")]
    JournalAlreadyPending,
    #[error("reorg journal changed concurrently")]
    ConcurrentChange,
    #[error("candidate branch must contain at least one block")]
    EmptyCandidate,
    #[error("candidate branch must have strictly more cumulative work")]
    CandidateNotHeavier,
    #[error("reorg path contains {actual} blocks; maximum is {maximum}")]
    PathTooLong { actual: usize, maximum: usize },
    #[error("reorg path contains duplicate block {0}")]
    DuplicateBlock(Hash256),
    #[error("reorg detach and attach paths overlap at block {0}")]
    OverlappingPaths(Hash256),
    #[error("common ancestor appears inside a reorg path")]
    AncestorInPath,
    #[error("restoring journal must include a bounded rejection reason")]
    InvalidRejectionReason,
    #[error("backend tip {actual} is not a valid position in the journal")]
    UnexpectedTip { actual: Hash256 },
    #[error("backend error: {0}")]
    Backend(String),
}

pub struct ReorgCoordinator {
    journal: sled::Tree,
}

impl ReorgCoordinator {
    pub fn open(db: &sled::Db) -> Result<Self, ReorgCoordinatorError> {
        Ok(Self {
            journal: db.open_tree("reorg_journal")?,
        })
    }

    pub fn pending(&self) -> Result<Option<ReorgJournal>, ReorgCoordinatorError> {
        self.journal
            .get(JOURNAL_KEY)?
            .map(|bytes| decode_and_validate(&bytes))
            .transpose()
    }

    pub fn execute<B: ReorgBackend>(
        &self,
        backend: &mut B,
        plan: ReorgPlan,
    ) -> Result<ReorgOutcome, ReorgCoordinatorError> {
        let journal = ReorgJournal::from(plan);
        validate_journal(&journal)?;

        let actual = backend.tip().map_err(backend_error)?;
        let expected = journal
            .detach
            .first()
            .copied()
            .unwrap_or(journal.common_ancestor);
        if actual != expected {
            return Err(ReorgCoordinatorError::UnexpectedTip { actual });
        }

        let encoded = encode(&journal)?;
        match self
            .journal
            .compare_and_swap(JOURNAL_KEY, None as Option<&[u8]>, Some(encoded))?
        {
            Ok(()) => self.flush_journal()?,
            Err(_) => return Err(ReorgCoordinatorError::JournalAlreadyPending),
        }
        self.drive(backend, journal)
    }

    /// Resume an interrupted reorganisation from the durable backend tip.
    ///
    /// Progress is inferred from immutable paths rather than a separate cursor,
    /// so a crash between a backend commit and the next coordinator instruction
    /// cannot make the journal skip a transition.
    pub fn recover<B: ReorgBackend>(
        &self,
        backend: &mut B,
    ) -> Result<Option<ReorgOutcome>, ReorgCoordinatorError> {
        let Some(journal) = self.pending()? else {
            return Ok(None);
        };
        self.drive(backend, journal).map(Some)
    }

    fn drive<B: ReorgBackend>(
        &self,
        backend: &mut B,
        mut journal: ReorgJournal,
    ) -> Result<ReorgOutcome, ReorgCoordinatorError> {
        loop {
            let tip = backend.tip().map_err(backend_error)?;
            match journal.mode {
                ReorgMode::ApplyingCandidate => {
                    if let Some(position) = journal.detach.iter().position(|hash| *hash == tip) {
                        backend.detach_tip(tip).map_err(backend_error)?;
                        backend.flush().map_err(backend_error)?;
                        debug_assert!(position < journal.detach.len());
                        continue;
                    }

                    let next = if tip == journal.common_ancestor {
                        journal.attach.first().copied()
                    } else if let Some(position) =
                        journal.attach.iter().position(|hash| *hash == tip)
                    {
                        journal.attach.get(position + 1).copied()
                    } else {
                        return Err(ReorgCoordinatorError::UnexpectedTip { actual: tip });
                    };

                    if let Some(block) = next {
                        if let Err(error) = backend.attach(block) {
                            let previous = journal.clone();
                            journal.mode = ReorgMode::RestoringOriginal;
                            journal.rejection_reason = Some(bounded_reason(&error.to_string()));
                            self.replace_journal(&previous, &journal)?;
                        } else {
                            backend.flush().map_err(backend_error)?;
                        }
                        continue;
                    }

                    backend.flush().map_err(backend_error)?;
                    self.clear_journal(&journal)?;
                    return Ok(ReorgOutcome::AppliedCandidate { new_tip: tip });
                }
                ReorgMode::RestoringOriginal => {
                    if journal.attach.contains(&tip) {
                        backend.detach_tip(tip).map_err(backend_error)?;
                        backend.flush().map_err(backend_error)?;
                        continue;
                    }

                    let next = if tip == journal.common_ancestor {
                        journal.detach.last().copied()
                    } else if let Some(position) =
                        journal.detach.iter().position(|hash| *hash == tip)
                    {
                        if position == 0 {
                            None
                        } else {
                            journal.detach.get(position - 1).copied()
                        }
                    } else {
                        return Err(ReorgCoordinatorError::UnexpectedTip { actual: tip });
                    };

                    if let Some(block) = next {
                        backend.attach(block).map_err(backend_error)?;
                        backend.flush().map_err(backend_error)?;
                        continue;
                    }

                    backend.flush().map_err(backend_error)?;
                    let reason = journal
                        .rejection_reason
                        .clone()
                        .ok_or(ReorgCoordinatorError::InvalidRejectionReason)?;
                    self.clear_journal(&journal)?;
                    return Ok(ReorgOutcome::RestoredOriginal {
                        old_tip: tip,
                        reason,
                    });
                }
            }
        }
    }

    fn replace_journal(
        &self,
        expected: &ReorgJournal,
        replacement: &ReorgJournal,
    ) -> Result<(), ReorgCoordinatorError> {
        validate_journal(replacement)?;
        let expected = encode(expected)?;
        let replacement = encode(replacement)?;
        match self.journal.compare_and_swap(
            JOURNAL_KEY,
            Some(expected.as_slice()),
            Some(replacement),
        )? {
            Ok(()) => self.flush_journal(),
            Err(_) => Err(ReorgCoordinatorError::ConcurrentChange),
        }
    }

    fn clear_journal(&self, expected: &ReorgJournal) -> Result<(), ReorgCoordinatorError> {
        let encoded = encode(expected)?;
        match self.journal.compare_and_swap(
            JOURNAL_KEY,
            Some(encoded.as_slice()),
            None as Option<&[u8]>,
        )? {
            Ok(()) => self.flush_journal(),
            Err(_) => Err(ReorgCoordinatorError::ConcurrentChange),
        }
    }

    fn flush_journal(&self) -> Result<(), ReorgCoordinatorError> {
        self.journal.flush()?;
        Ok(())
    }
}

fn encode(journal: &ReorgJournal) -> Result<Vec<u8>, ReorgCoordinatorError> {
    hyphen_codec::serialize(journal)
        .map_err(|error| ReorgCoordinatorError::Serde(error.to_string()))
}

fn decode_and_validate(bytes: &[u8]) -> Result<ReorgJournal, ReorgCoordinatorError> {
    let journal: ReorgJournal = hyphen_codec::deserialize(bytes)
        .map_err(|error| ReorgCoordinatorError::Serde(error.to_string()))?;
    validate_journal(&journal)?;
    Ok(journal)
}

fn validate_journal(journal: &ReorgJournal) -> Result<(), ReorgCoordinatorError> {
    if journal.version != JOURNAL_VERSION {
        return Err(ReorgCoordinatorError::UnsupportedVersion(journal.version));
    }
    if journal.attach.is_empty() {
        return Err(ReorgCoordinatorError::EmptyCandidate);
    }
    if journal.new_work <= journal.old_work {
        return Err(ReorgCoordinatorError::CandidateNotHeavier);
    }
    let path_len = journal
        .detach
        .len()
        .checked_add(journal.attach.len())
        .ok_or(ReorgCoordinatorError::PathTooLong {
            actual: usize::MAX,
            maximum: MAX_REORG_PATH_BLOCKS,
        })?;
    if path_len > MAX_REORG_PATH_BLOCKS {
        return Err(ReorgCoordinatorError::PathTooLong {
            actual: path_len,
            maximum: MAX_REORG_PATH_BLOCKS,
        });
    }

    let mut detach = HashSet::with_capacity(journal.detach.len());
    for hash in &journal.detach {
        if *hash == journal.common_ancestor {
            return Err(ReorgCoordinatorError::AncestorInPath);
        }
        if !detach.insert(*hash) {
            return Err(ReorgCoordinatorError::DuplicateBlock(*hash));
        }
    }
    let mut attach = HashSet::with_capacity(journal.attach.len());
    for hash in &journal.attach {
        if *hash == journal.common_ancestor {
            return Err(ReorgCoordinatorError::AncestorInPath);
        }
        if detach.contains(hash) {
            return Err(ReorgCoordinatorError::OverlappingPaths(*hash));
        }
        if !attach.insert(*hash) {
            return Err(ReorgCoordinatorError::DuplicateBlock(*hash));
        }
    }

    match (&journal.mode, &journal.rejection_reason) {
        (ReorgMode::ApplyingCandidate, None) => {}
        (ReorgMode::RestoringOriginal, Some(reason))
            if !reason.is_empty() && reason.len() <= MAX_REJECTION_REASON_BYTES => {}
        _ => return Err(ReorgCoordinatorError::InvalidRejectionReason),
    }
    Ok(())
}

fn bounded_reason(reason: &str) -> String {
    if reason.is_empty() {
        return "candidate attach failed".to_owned();
    }
    if reason.len() <= MAX_REJECTION_REASON_BYTES {
        return reason.to_owned();
    }
    let mut end = MAX_REJECTION_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

fn backend_error(error: impl Display) -> ReorgCoordinatorError {
    ReorgCoordinatorError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn plan() -> ReorgPlan {
        ReorgPlan {
            common_ancestor: hash(1),
            detach: vec![hash(3), hash(2)],
            attach: vec![hash(4), hash(5)],
            old_work: 20,
            new_work: 21,
        }
    }

    struct MemoryBackend {
        chain: Vec<Hash256>,
        operation: usize,
        fail_before: BTreeSet<usize>,
        flushes: usize,
    }

    impl MemoryBackend {
        fn canonical() -> Self {
            Self {
                chain: vec![hash(1), hash(2), hash(3)],
                operation: 0,
                fail_before: BTreeSet::new(),
                flushes: 0,
            }
        }

        fn fail_once_before(&mut self, operation: usize) {
            self.fail_before.insert(operation);
        }

        fn begin_operation(&mut self) -> Result<(), String> {
            self.operation += 1;
            if self.fail_before.remove(&self.operation) {
                Err(format!("injected failure at operation {}", self.operation))
            } else {
                Ok(())
            }
        }
    }

    impl ReorgBackend for MemoryBackend {
        type Error = String;

        fn tip(&self) -> Result<Hash256, Self::Error> {
            self.chain
                .last()
                .copied()
                .ok_or_else(|| "empty chain".to_owned())
        }

        fn detach_tip(&mut self, expected: Hash256) -> Result<(), Self::Error> {
            self.begin_operation()?;
            if self.tip()? != expected || self.chain.len() == 1 {
                return Err("unexpected detach".to_owned());
            }
            self.chain.pop();
            Ok(())
        }

        fn attach(&mut self, block: Hash256) -> Result<(), Self::Error> {
            self.begin_operation()?;
            self.chain.push(block);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn successful_multi_block_reorg_clears_journal() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let coordinator = ReorgCoordinator::open(&db).unwrap();
        let mut backend = MemoryBackend::canonical();

        let outcome = coordinator.execute(&mut backend, plan()).unwrap();

        assert_eq!(outcome, ReorgOutcome::AppliedCandidate { new_tip: hash(5) });
        assert_eq!(backend.chain, vec![hash(1), hash(4), hash(5)]);
        assert!(backend.flushes >= 5);
        assert!(coordinator.pending().unwrap().is_none());
    }

    #[test]
    fn interrupted_detach_resumes_from_persisted_tip() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let coordinator = ReorgCoordinator::open(&db).unwrap();
        let mut backend = MemoryBackend::canonical();
        backend.fail_once_before(2);

        assert!(matches!(
            coordinator.execute(&mut backend, plan()),
            Err(ReorgCoordinatorError::Backend(_))
        ));
        assert_eq!(backend.tip().unwrap(), hash(2));
        assert_eq!(
            coordinator.pending().unwrap().unwrap().mode,
            ReorgMode::ApplyingCandidate
        );

        drop(coordinator);
        let reopened = ReorgCoordinator::open(&db).unwrap();
        assert_eq!(
            reopened.recover(&mut backend).unwrap(),
            Some(ReorgOutcome::AppliedCandidate { new_tip: hash(5) })
        );
        assert_eq!(backend.chain, vec![hash(1), hash(4), hash(5)]);
        assert!(reopened.pending().unwrap().is_none());
    }

    #[test]
    fn failed_candidate_is_removed_and_original_branch_is_restored() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let coordinator = ReorgCoordinator::open(&db).unwrap();
        let mut backend = MemoryBackend::canonical();
        backend.fail_once_before(4);

        let outcome = coordinator.execute(&mut backend, plan()).unwrap();

        assert!(matches!(
            outcome,
            ReorgOutcome::RestoredOriginal { old_tip, ref reason }
                if old_tip == hash(3) && reason.contains("operation 4")
        ));
        assert_eq!(backend.chain, vec![hash(1), hash(2), hash(3)]);
        assert!(coordinator.pending().unwrap().is_none());
    }

    #[test]
    fn interrupted_restoration_resumes_to_original_tip() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let coordinator = ReorgCoordinator::open(&db).unwrap();
        let mut backend = MemoryBackend::canonical();
        backend.fail_once_before(4);
        backend.fail_once_before(6);

        assert!(matches!(
            coordinator.execute(&mut backend, plan()),
            Err(ReorgCoordinatorError::Backend(_))
        ));
        assert_eq!(backend.tip().unwrap(), hash(1));
        assert_eq!(
            coordinator.pending().unwrap().unwrap().mode,
            ReorgMode::RestoringOriginal
        );

        drop(coordinator);
        let reopened = ReorgCoordinator::open(&db).unwrap();
        assert!(matches!(
            reopened.recover(&mut backend).unwrap(),
            Some(ReorgOutcome::RestoredOriginal { old_tip, .. }) if old_tip == hash(3)
        ));
        assert_eq!(backend.chain, vec![hash(1), hash(2), hash(3)]);
        assert!(reopened.pending().unwrap().is_none());
    }

    #[test]
    fn malformed_and_overlapping_plans_are_rejected_before_persistence() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let coordinator = ReorgCoordinator::open(&db).unwrap();
        let mut backend = MemoryBackend::canonical();

        let mut duplicate = plan();
        duplicate.attach.push(hash(4));
        assert!(matches!(
            coordinator.execute(&mut backend, duplicate),
            Err(ReorgCoordinatorError::DuplicateBlock(found)) if found == hash(4)
        ));

        let mut overlap = plan();
        overlap.attach[0] = hash(2);
        assert!(matches!(
            coordinator.execute(&mut backend, overlap),
            Err(ReorgCoordinatorError::OverlappingPaths(found)) if found == hash(2)
        ));
        assert!(coordinator.pending().unwrap().is_none());
        assert_eq!(backend.chain, vec![hash(1), hash(2), hash(3)]);
    }

    #[test]
    fn journal_remains_when_restoration_fails() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let coordinator = ReorgCoordinator::open(&db).unwrap();
        let mut backend = MemoryBackend::canonical();
        backend.fail_once_before(4);
        backend.fail_once_before(5);

        assert!(matches!(
            coordinator.execute(&mut backend, plan()),
            Err(ReorgCoordinatorError::Backend(_))
        ));
        let pending = coordinator.pending().unwrap().unwrap();
        assert_eq!(pending.mode, ReorgMode::RestoringOriginal);
        assert!(pending.rejection_reason.is_some());
        assert_eq!(backend.tip().unwrap(), hash(4));
    }
}
