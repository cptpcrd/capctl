use super::{Cap, CapSet};

/// Drop the given capability from the current thread's bounding capability set.
#[inline]
pub fn drop(cap: Cap) -> crate::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) }?;

    Ok(())
}

/// Check if the given capability is raised in the current thread's bounding capability set.
///
/// This returns `Some(true)` if the given capability is raised, `Some(false)` if it is lowered, and
/// `None` if it is not supported.
#[inline]
pub fn read(cap: Cap) -> Option<bool> {
    read_raw(cap as _)
}

#[inline]
fn read_raw(cap: libc::c_ulong) -> Option<bool> {
    match unsafe { crate::raw_prctl_opt(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } {
        Some(res) => Some(res != 0),
        None => {
            #[cfg(not(feature = "sc"))]
            debug_assert_eq!(unsafe { *libc::__errno_location() }, libc::EINVAL);
            None
        }
    }
}

/// Check if the given capability is raised in the current thread's bounding capability set.
///
/// This is an alias of [`read()`](./fn.read.html).
#[deprecated(since = "0.2.1", note = "use `read()` instead")]
#[inline]
pub fn is_set(cap: Cap) -> Option<bool> {
    read(cap)
}

/// "Probes" the current thread's bounding capability set and returns a `CapSet` representing all
/// the capabilities that are currently raised.
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

fn clear_from(low: libc::c_ulong) -> crate::Result<()> {
    for cap in low..(super::CAP_MAX as libc::c_ulong * 2) {
        match unsafe { crate::raw_prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } {
            Ok(_) => (),
            Err(e) if e.code() == libc::EINVAL && cap != 0 => return Ok(()),
            Err(e) if e.code() == libc::EPERM && read_raw(cap) == Some(false) => (),
            Err(e) => return Err(e),
        }
    }

    Err(crate::Error::from_code(libc::E2BIG))
}

/// Drop all capabilities supported by the kernel from the current thread's bounding capability set.
///
/// This method is equivalent to the following (though it may be slightly faster):
///
/// ```no_run
/// # use capctl::*;
/// # fn clear() -> Result<()> {
/// for cap in Cap::iter() {
///     bounding::drop(cap)?;
/// }
/// bounding::clear_unknown()?;
/// # Ok(())
/// # }
/// ```
///
/// The intent is to simulate [`crate::caps::ambient::clear()`] (which is a single `prctl()` call).
///
/// See also [`clear_unknown()`].
#[inline]
pub fn clear() -> crate::Result<()> {
    clear_from(0)
}

/// Drop all capabilities that are supported by the kernel but which this library is not aware of
/// from the current thread's bounding capability set.
///
/// For example, this code will drop all bounding capabilities (even ones not supported by the
/// kernel) except for `CAP_SETUID`:
///
/// ```no_run
/// # use capctl::*;
/// // Drop all capabilities that `capctl` knows about (except for CAP_SETUID)
/// for cap in Cap::iter() {
///     if cap != Cap::SETUID {
///         bounding::drop(cap).unwrap();
///     }
/// }
/// // Drop any new capabilities that `capctl` wasn't aware of at compile time
/// bounding::clear_unknown();
/// ```
///
/// See [Handling of newly-added capabilities](../index.html#handling-of-newly-added-capabilities)
/// for the rationale.
#[inline]
pub fn clear_unknown() -> crate::Result<()> {
    clear_from((super::CAP_MAX + 1) as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounding() {
        probe();
        read(Cap::CHOWN).unwrap();
    }

    #[test]
    fn test_bounding_drop() {
        if crate::caps::CapState::get_current()
            .unwrap()
            .effective
            .has(crate::caps::Cap::SETPCAP)
        {
            drop(crate::caps::Cap::SETPCAP).unwrap();
        } else {
            assert_eq!(
                drop(crate::caps::Cap::SETPCAP).unwrap_err().code(),
                libc::EPERM
            );
        }
    }

    #[test]
    fn test_clear() {
        if crate::caps::CapState::get_current()
            .unwrap()
            .effective
            .has(crate::caps::Cap::SETPCAP)
        {
            clear().unwrap();
            assert_eq!(probe(), crate::caps::CapSet::empty());
        }
    }

    #[test]
    fn test_clear_unknown() {
        if crate::caps::CapState::get_current()
            .unwrap()
            .effective
            .has(crate::caps::Cap::SETPCAP)
        {
            let orig_caps = probe();
            clear_unknown().unwrap();
            assert_eq!(probe(), orig_caps);
        }
    }
}
