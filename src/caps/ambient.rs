use std::io;

use super::{Cap, CapSet};

/// Raise the given capability in the current thread's ambient capability set.
#[inline]
pub fn raise(cap: Cap) -> io::Result<()> {
    unsafe {
        crate::raw_prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
            cap as libc::c_ulong,
            0,
            0,
        )
    }?;

    Ok(())
}

/// Lower the given capability in the current thread's ambient capability set.
#[inline]
pub fn lower(cap: Cap) -> io::Result<()> {
    unsafe {
        crate::raw_prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_LOWER as libc::c_ulong,
            cap as libc::c_ulong,
            0,
            0,
        )
    }?;

    Ok(())
}

/// Check whether the given capability is raised in the current thread's ambient capability set.
///
/// This returns `Some(true)` if the given capability is raised, `Some(false)` if it is lowered,
/// and `None` if it is not supported.
#[inline]
pub fn is_set(cap: Cap) -> Option<bool> {
    Some(
        unsafe {
            crate::raw_prctl_opt(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
                cap as libc::c_ulong,
                0,
                0,
            )?
        } != 0,
    )
}

/// Clear current thread's ambient capability set.
#[inline]
pub fn clear() -> io::Result<()> {
    unsafe {
        crate::raw_prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    }?;

    Ok(())
}

/// Check whether ambient capabilities are supported on the running kernel.
#[inline]
pub fn is_supported() -> bool {
    is_set(Cap::CHOWN).is_some()
}

/// "Probes" the current thread's ambient capability set and returns a `CapSet` representing all
/// the capabilities that are currently raised.
pub fn probe() -> Option<CapSet> {
    let mut set = CapSet::empty();

    for cap in Cap::iter() {
        match is_set(cap) {
            Some(true) => set.add(cap),
            Some(false) => (),

            // Unsupported capability encountered; none of the remaining ones will be supported
            // either
            None => {
                if cap as u8 == 0 {
                    // Ambient capabilities aren't supported at all
                    return None;
                } else {
                    break;
                }
            }
        }
    }

    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ambient() {
        probe().unwrap();
        assert!(is_supported());
    }
}
