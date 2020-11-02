use std::fmt;
use std::iter::FromIterator;
use std::ops::{BitAnd, BitOr, BitXor, Not, Sub};

use super::{Cap, CAP_BITMASK, CAP_MAX};

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct CapSet {
    pub(super) bits: u64,
}

impl CapSet {
    #[inline]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.bits = 0;
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.bits.count_ones() as usize
    }

    #[inline]
    pub fn has(&self, cap: Cap) -> bool {
        self.bits & cap.to_single_bitfield() != 0
    }

    #[inline]
    pub fn add(&mut self, cap: Cap) {
        self.bits |= cap.to_single_bitfield();
    }

    #[inline]
    pub fn drop(&mut self, cap: Cap) {
        self.bits &= !cap.to_single_bitfield();
    }

    pub fn set_state(&mut self, cap: Cap, val: bool) {
        if val {
            self.add(cap);
        } else {
            self.drop(cap);
        }
    }

    pub fn add_all<T: IntoIterator<Item = Cap>>(&mut self, t: T) {
        for cap in t.into_iter() {
            self.add(cap);
        }
    }

    pub fn drop_all<T: IntoIterator<Item = Cap>>(&mut self, t: T) {
        for cap in t.into_iter() {
            self.drop(cap);
        }
    }

    #[inline]
    pub fn iter(&self) -> CapSetIterator {
        self.into_iter()
    }

    #[inline]
    pub const fn union(&self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    #[inline]
    pub const fn intersection(&self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn from_bitmask_truncate(bitmask: u64) -> Self {
        Self {
            bits: bitmask & CAP_BITMASK,
        }
    }
}

impl Default for CapSet {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

impl Not for CapSet {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self {
            bits: (!self.bits) & CAP_BITMASK,
        }
    }
}

impl BitAnd for CapSet {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersection(rhs)
    }
}

impl BitOr for CapSet {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl BitXor for CapSet {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            bits: self.bits ^ rhs.bits,
        }
    }
}

impl Sub for CapSet {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            bits: self.bits & (!rhs.bits),
        }
    }
}

impl Extend<Cap> for CapSet {
    #[inline]
    fn extend<I: IntoIterator<Item = Cap>>(&mut self, it: I) {
        self.add_all(it);
    }
}

impl FromIterator<Cap> for CapSet {
    #[inline]
    fn from_iter<I: IntoIterator<Item = Cap>>(it: I) -> Self {
        let mut res = Self::empty();
        res.extend(it);
        res
    }
}

impl IntoIterator for CapSet {
    type Item = Cap;
    type IntoIter = CapSetIterator;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        CapSetIterator { set: self, i: 0 }
    }
}

impl fmt::Debug for CapSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// A helper macro to statically construct a `CapSet` from a list of capabilities.
///
/// Examples:
/// ```
/// use std::iter::FromIterator;
/// use capctl::capset;
/// use capctl::caps::{Cap, CapSet};
///
/// assert_eq!(capset!(), CapSet::empty());
/// assert_eq!(capset!(Cap::CHOWN), CapSet::from_iter(vec![Cap::CHOWN]));
/// assert_eq!(capset!(Cap::CHOWN, Cap::SYSLOG), CapSet::from_iter(vec![Cap::CHOWN, Cap::SYSLOG]));
/// ```
#[macro_export]
macro_rules! capset {
    () => {
        CapSet::empty()
    };
    ($cap:expr$(, $caps:expr)*) => {
        CapSet::from_bitmask_truncate((1 << ($cap as u8)) $(| (1 << ($caps as u8)))*)
    };
    ($cap:expr, $($caps:expr,)*) => {
        capset!($cap$(, $caps)*)
    };
}

#[derive(Clone)]
pub struct CapSetIterator {
    set: CapSet,
    i: u8,
}

impl Iterator for CapSetIterator {
    type Item = Cap;

    fn next(&mut self) -> Option<Cap> {
        while let Some(cap) = Cap::from_u8(self.i) {
            self.i += 1;
            if self.set.has(cap) {
                return Some(cap);
            }
        }

        None
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for CapSetIterator {
    #[inline]
    fn len(&self) -> usize {
        if self.i <= CAP_MAX {
            (self.set.bits >> self.i).count_ones() as usize
        } else {
            0
        }
    }
}

impl std::iter::FusedIterator for CapSetIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capset_empty() {
        let mut set = CapSet::from_iter(Cap::iter());
        for cap in Cap::iter() {
            set.drop(cap);
        }
        assert_eq!(set.bits, 0);
        assert!(set.is_empty());

        set = CapSet::empty();
        assert_eq!(set.bits, 0);
        assert!(set.is_empty());
        assert_eq!(set, CapSet::default());

        set = CapSet::from_iter(Cap::iter());
        set.clear();
        assert_eq!(set.bits, 0);
        assert!(set.is_empty());

        assert!(!Cap::iter().any(|c| set.has(c)));
    }

    #[test]
    fn test_capset_full() {
        let mut set = CapSet::empty();
        for cap in Cap::iter() {
            set.add(cap);
        }
        assert_eq!(set.bits, CAP_BITMASK);
        assert!(!set.is_empty());

        set = CapSet::empty();
        set.extend(Cap::iter());
        assert_eq!(set.bits, CAP_BITMASK);
        assert!(!set.is_empty());

        assert!(Cap::iter().all(|c| set.has(c)));
    }

    #[test]
    fn test_capset_add_drop() {
        let mut set = CapSet::empty();
        set.add(Cap::CHOWN);
        assert!(set.has(Cap::CHOWN));
        assert!(!set.is_empty());

        set.drop(Cap::CHOWN);
        assert!(!set.has(Cap::CHOWN));
        assert!(set.is_empty());

        set.set_state(Cap::CHOWN, true);
        assert!(set.has(Cap::CHOWN));
        assert!(!set.is_empty());

        set.set_state(Cap::CHOWN, false);
        assert!(!set.has(Cap::CHOWN));
        assert!(set.is_empty());
    }

    #[test]
    fn test_capset_add_drop_all() {
        let mut set = CapSet::empty();
        set.add_all(vec![Cap::FOWNER, Cap::CHOWN, Cap::KILL]);

        // Iteration order is not preserved, but it should be consistent.
        assert_eq!(
            set.into_iter().collect::<Vec<Cap>>(),
            vec![Cap::CHOWN, Cap::FOWNER, Cap::KILL]
        );
        assert_eq!(
            set.iter().collect::<Vec<Cap>>(),
            vec![Cap::CHOWN, Cap::FOWNER, Cap::KILL]
        );

        set.drop_all(vec![Cap::FOWNER, Cap::CHOWN]);
        assert_eq!(set.iter().collect::<Vec<Cap>>(), vec![Cap::KILL]);

        set.drop_all(vec![Cap::KILL]);
        assert_eq!(set.iter().collect::<Vec<Cap>>(), vec![]);
    }

    #[test]
    fn test_capset_from_iter() {
        let set = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        assert_eq!(
            set.iter().collect::<Vec<Cap>>(),
            vec![Cap::CHOWN, Cap::FOWNER],
        );
    }

    #[test]
    fn test_capset_iter_full() {
        assert!(Cap::iter().eq(CapSet { bits: CAP_BITMASK }.iter()));
        assert!(Cap::iter().eq(CapSet::from_iter(Cap::iter()).iter()));
    }

    #[test]
    fn test_capset_iter_count() {
        for set in [
            CapSet::from_iter(vec![]),
            CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]),
            CapSet::from_iter(Cap::iter()),
        ]
        .iter()
        {
            let mut count = set.size();

            let mut it = set.iter();
            assert_eq!(it.len(), count);
            assert_eq!(it.clone().count(), count);
            assert_eq!(it.size_hint(), (count, Some(count)));

            while let Some(_cap) = it.next() {
                count -= 1;
                assert_eq!(it.len(), count);
                assert_eq!(it.clone().count(), count);
                assert_eq!(it.size_hint(), (count, Some(count)));
            }

            assert_eq!(count, 0);

            assert_eq!(it.len(), 0);
            assert_eq!(it.clone().count(), 0);
            assert_eq!(it.size_hint(), (0, Some(0)));
        }
    }

    #[test]
    fn test_capset_union() {
        let a = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        let b = CapSet::from_iter(vec![Cap::FOWNER, Cap::KILL]);
        let c = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER, Cap::KILL]);
        assert_eq!(a.union(b), c);
    }

    #[test]
    fn test_capset_intersection() {
        let a = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        let b = CapSet::from_iter(vec![Cap::FOWNER, Cap::KILL]);
        let c = CapSet::from_iter(vec![Cap::FOWNER]);
        assert_eq!(a.intersection(b), c);
    }

    #[test]
    fn test_capset_not() {
        assert_eq!(!CapSet::from_iter(Cap::iter()), CapSet::empty());
        assert_eq!(CapSet::from_iter(Cap::iter()), !CapSet::empty());

        let mut a = CapSet::from_iter(Cap::iter());
        let mut b = CapSet::empty();
        a.add(Cap::CHOWN);
        b.drop(Cap::CHOWN);
        assert_eq!(!a, b);
    }

    #[test]
    fn test_capset_bitor() {
        let a = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        let b = CapSet::from_iter(vec![Cap::FOWNER, Cap::KILL]);
        let c = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER, Cap::KILL]);
        assert_eq!(a | b, c);
    }

    #[test]
    fn test_capset_bitand() {
        let a = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        let b = CapSet::from_iter(vec![Cap::FOWNER, Cap::KILL]);
        let c = CapSet::from_iter(vec![Cap::FOWNER]);
        assert_eq!(a & b, c);
    }

    #[test]
    fn test_capset_bitxor() {
        let a = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        let b = CapSet::from_iter(vec![Cap::FOWNER, Cap::KILL]);
        let c = CapSet::from_iter(vec![Cap::CHOWN, Cap::KILL]);
        assert_eq!(a ^ b, c);
    }

    #[test]
    fn test_capset_sub() {
        let a = CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER]);
        let b = CapSet::from_iter(vec![Cap::FOWNER, Cap::KILL]);
        let c = CapSet::from_iter(vec![Cap::CHOWN]);
        assert_eq!(a - b, c);
    }

    #[test]
    fn test_capset_fmt() {
        assert_eq!(format!("{:?}", CapSet::empty()), "{}");
        assert_eq!(
            format!("{:?}", CapSet::from_iter(vec![Cap::CHOWN])),
            "{CHOWN}"
        );
        assert_eq!(
            format!("{:?}", CapSet::from_iter(vec![Cap::CHOWN, Cap::FOWNER])),
            "{CHOWN, FOWNER}"
        );
    }

    #[test]
    fn test_capset_macro() {
        assert_eq!(capset!(), CapSet::empty());

        assert_eq!(capset!(Cap::CHOWN), CapSet::from_iter(vec![Cap::CHOWN]));
        assert_eq!(capset!(Cap::CHOWN,), CapSet::from_iter(vec![Cap::CHOWN]));

        assert_eq!(
            capset!(Cap::CHOWN, Cap::SYSLOG),
            CapSet::from_iter(vec![Cap::CHOWN, Cap::SYSLOG])
        );
        assert_eq!(
            capset!(Cap::CHOWN, Cap::SYSLOG,),
            CapSet::from_iter(vec![Cap::CHOWN, Cap::SYSLOG])
        );

        assert_eq!(
            capset!(Cap::CHOWN, Cap::SYSLOG, Cap::FOWNER),
            CapSet::from_iter(vec![Cap::CHOWN, Cap::SYSLOG, Cap::FOWNER])
        );
        assert_eq!(
            capset!(Cap::CHOWN, Cap::SYSLOG, Cap::FOWNER,),
            CapSet::from_iter(vec![Cap::CHOWN, Cap::SYSLOG, Cap::FOWNER])
        );
    }
}
