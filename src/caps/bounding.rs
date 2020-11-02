use std::io;

use super::{Cap, CapSet};

#[inline]
pub fn drop(cap: Cap) -> io::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) }?;

    Ok(())
}

#[inline]
pub fn read(cap: Cap) -> Option<bool> {
    Some(
        unsafe { crate::raw_prctl_opt(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0)? } != 0,
    )
}

// Slightly easier to understand than read()
#[inline]
pub fn is_set(cap: Cap) -> Option<bool> {
    read(cap)
}

pub fn probe() -> CapSet {
    let mut set = CapSet::empty();

    for cap in Cap::iter() {
        match read(cap) {
            Some(true) => set.add(cap),
            Some(false) => (),

            // Unsupported capability encountered; none of the remaining ones will be supported
            // either
            _ => break,
        }
    }

    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounding() {
        probe();
        is_set(Cap::CHOWN).unwrap();
    }
}
