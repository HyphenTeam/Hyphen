//! Ordered-set adapter for the compact wire profile.
//!
//! The profile ships `CompactEncode`/`CompactDecode` impls for the containers it
//! can encode canonically by itself (`Vec`, `VecDeque`, arrays, `BTreeMap`,
//! `HashMap`). It has no set impl on purpose: a `HashSet` has no stable iteration
//! order, and the length writer a hand-written container impl would need is
//! crate-private, so a third-party collection cannot be encoded through the
//! public API without delegating to one of those.
//!
//! [`CanonicalSet`] is that delegation. It keeps `BTreeSet` semantics in the
//! domain model — ordered iteration, uniqueness, logarithmic lookup — and
//! encodes as the canonical strictly-ascending sequence the profile expects from
//! a `Vec`. Decoding re-checks the ordering, so a set has exactly one valid byte
//! string per value: duplicate or descending elements are malformed input rather
//! than input to be silently normalised into a second encoding of the same set.

use std::collections::BTreeSet;
use std::iter::FromIterator;
use std::ops::{Deref, DerefMut};

use rustbinary::compact::{CompactCursor, CompactDecode, CompactEncode};
use rustbinary::writer::EncodeWriter;
use rustbinary::Error;

/// A set whose wire form is the canonical ascending element sequence.
///
/// The inner `BTreeSet` maintains the ordering invariant, so every mutation
/// performed through [`DerefMut`] keeps the encoding canonical; the only way to
/// observe a non-canonical byte string is to hand-craft one, and decoding
/// rejects it.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CanonicalSet<T: Ord>(BTreeSet<T>);

/// Empty is the only default a set needs, and it must not require `T: Default`:
/// chain keys are not defaultable, and an empty set of them is still valid.
impl<T: Ord> Default for CanonicalSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord> CanonicalSet<T> {
    /// Creates an empty set.
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Consumes the set, yielding the elements in canonical order.
    pub fn into_vec(self) -> Vec<T> {
        self.0.into_iter().collect()
    }
}

impl<T: Ord> Deref for CanonicalSet<T> {
    type Target = BTreeSet<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Ord> DerefMut for CanonicalSet<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Ord> From<BTreeSet<T>> for CanonicalSet<T> {
    fn from(set: BTreeSet<T>) -> Self {
        Self(set)
    }
}

impl<T: Ord> From<CanonicalSet<T>> for BTreeSet<T> {
    fn from(set: CanonicalSet<T>) -> Self {
        set.0
    }
}

impl<T: Ord> FromIterator<T> for CanonicalSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T: Ord> IntoIterator for CanonicalSet<T> {
    type Item = T;
    type IntoIter = std::collections::btree_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T: Ord> IntoIterator for &'a CanonicalSet<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_set::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Ord> Extend<T> for CanonicalSet<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

/// Encodes the ascending element sequence.
///
/// `Clone` is required because the only sequence encoder in the codec's public
/// API takes a slice, and a `BTreeSet` does not expose its nodes as one. The
/// sets on this wire are small — certificates, nonces, expiry buckets — so the
/// temporary is bounded by the set's own size.
impl<T: Ord + Clone + CompactEncode> CompactEncode for CanonicalSet<T> {
    fn encode_compact<W: EncodeWriter + ?Sized>(&self, writer: &mut W) -> Result<(), Error> {
        let ordered: Vec<T> = self.0.iter().cloned().collect();
        ordered.encode_compact(writer)
    }
}

/// Decodes the ascending element sequence, rejecting any other order.
///
/// Duplicates and descending elements are rejected: accepting them would give a
/// single set value more than one valid encoding, which is exactly the
/// malleability a frozen consensus format must not have. Element and byte
/// budgets are enforced by the delegated `Vec` decoder.
impl<'de, T: Ord + CompactDecode<'de>> CompactDecode<'de> for CanonicalSet<T> {
    fn decode_compact(cursor: &mut CompactCursor<'de>) -> Result<Self, Error> {
        let ordered = Vec::<T>::decode_compact(cursor)?;
        let mut previous: Option<&T> = None;
        for element in &ordered {
            if let Some(previous) = previous {
                if previous >= element {
                    return Err(Error::Custom(
                        "canonical set elements must be strictly ascending".into(),
                    ));
                }
            }
            previous = Some(element);
        }
        Ok(Self(ordered.into_iter().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> rustbinary::CompactConfig {
        crate::wire_config(crate::DEFAULT_WIRE_BYTES)
    }

    /// Pins the byte form of a set. Any drift in the delegation target has to
    /// fail here instead of silently changing the chain's wire image.
    #[test]
    fn set_encodes_exactly_like_the_canonical_sequence() {
        let set: CanonicalSet<u32> = [7u32, 3, 9].into_iter().collect();
        let sequence: Vec<u32> = vec![3, 7, 9];

        assert_eq!(
            config().serialize(&set).unwrap(),
            config().serialize(&sequence).unwrap()
        );
    }

    #[test]
    fn duplicates_and_descending_elements_are_rejected() {
        let payload = |values: &[u32]| config().serialize(&values.to_vec()).unwrap();

        let ascending = payload(&[3, 7, 9]);
        assert!(config()
            .deserialize::<CanonicalSet<u32>>(&ascending)
            .is_ok());

        let duplicate = payload(&[3, 7, 7]);
        assert!(config()
            .deserialize::<CanonicalSet<u32>>(&duplicate)
            .is_err());

        let descending = payload(&[9, 7, 3]);
        assert!(config()
            .deserialize::<CanonicalSet<u32>>(&descending)
            .is_err());
    }

    #[test]
    fn round_trip_preserves_elements() {
        let set: CanonicalSet<[u8; 4]> = [[1, 2, 3, 4], [9, 9, 9, 9]].into_iter().collect();
        let bytes = config().serialize(&set).unwrap();
        assert_eq!(
            config()
                .deserialize::<CanonicalSet<[u8; 4]>>(&bytes)
                .unwrap(),
            set
        );
        assert_eq!(set.into_vec(), vec![[1, 2, 3, 4], [9, 9, 9, 9]]);
    }
}
