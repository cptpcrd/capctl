use std::io;

use super::{Cap, CapState};

/// Set the current thread's UID/GID/supplementary groups while preserving permitted capabilities.
///
/// This combines the functionality of ``libcap``'s ``cap_setuid()`` and ``cap_setgroups()``, while
/// providing greater flexibility.
///
/// WARNING: This function only operates on the current **thread**, not the process as a whole. This is
/// because of the way Linux operates. If you call this function from a multithreaded program, you
/// are responsible for synchronizing changes across threads as necessary to ensure proper security.
///
/// This function performs the following actions in order. (Note: If `gid` is not `None` or
/// `groups` is not `None`, CAP_SETGID will first be raised in the thread's effective set, and if
/// `uid` is not `None` then CAP_SETUID will be raised.)
///
/// - If `gid` is not `None`, the thread's real, effective and saved GIDs will be set to `gid`.
/// - If `groups` is not `None`, the thread's supplementary group list will be set to `groups`.
/// - If `uid` is not `None`, the thread's real, effective and saved UIDs will be set to `uid`.
/// - The effective capability set will be emptied.
///
/// Note: If this function fails and returns an error, the thread's UIDs, GIDs, supplementary
/// groups, and capability sets are in an unknown and possibly inconsistent state. This is EXTREMELY
/// DANGEROUS! If you are unable to revert the changes, abort as soon as possible.
pub fn cap_set_ids(
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
    groups: Option<&[libc::gid_t]>,
) -> io::Result<()> {
    let mut capstate = CapState::get_current()?;
    let orig_effective = capstate.effective;

    let orig_keepcaps = crate::prctl::get_keepcaps()?;
    crate::prctl::set_keepcaps(true)?;

    if gid.is_some() || groups.is_some() {
        capstate.effective.add(Cap::SETGID);
    }
    if uid.is_some() {
        capstate.effective.add(Cap::SETUID);
    }

    if capstate.effective != orig_effective {
        if let Err(err) = capstate.set_current() {
            crate::prctl::set_keepcaps(orig_keepcaps)?;
            return Err(err);
        }
    }

    let res = do_set_ids(uid, gid, groups);

    // Now clear the effective capability set (if it wasn't already cleared) and restore the
    // "keepcaps" flag.
    capstate.effective.clear();
    res.and(capstate.set_current())
        .and(crate::prctl::set_keepcaps(orig_keepcaps))
}

macro_rules! attr_group {
    (#![$attr:meta] $($stmts:item)*) => {
        $(
            #[$attr]
            $stmts
        )*
    }
}

attr_group! {
    #![cfg(all(
        target_pointer_width = "32",
        any(target_arch = "arm", target_arch = "sparc", target_arch = "x86")
    ))]

    const SYS_SETRESGID: libc::c_long = libc::SYS_setresgid32;
    const SYS_SETRESUID: libc::c_long = libc::SYS_setresuid32;
    const SYS_SETGROUPS: libc::c_long = libc::SYS_setgroups32;
}

attr_group! {
    #![cfg(not(all(
        target_pointer_width = "32",
        any(target_arch = "arm", target_arch = "sparc", target_arch = "x86")
    )))]

    const SYS_SETRESGID: libc::c_long = libc::SYS_setresgid;
    const SYS_SETRESUID: libc::c_long = libc::SYS_setresuid;
    const SYS_SETGROUPS: libc::c_long = libc::SYS_setgroups;
}

fn do_set_ids(
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
    groups: Option<&[libc::gid_t]>,
) -> io::Result<()> {
    unsafe {
        if let Some(gid) = gid {
            if libc::syscall(SYS_SETRESGID, gid, gid, gid) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if let Some(groups) = groups {
            if libc::syscall(SYS_SETGROUPS, groups.len(), groups.as_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if let Some(uid) = uid {
            if libc::syscall(SYS_SETRESUID, uid, uid, uid) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_ids_none() {
        // All this does is clear the effective capability set
        cap_set_ids(None, None, None).unwrap();

        assert!(crate::caps::CapState::get_current()
            .unwrap()
            .effective
            .is_empty());
    }

    #[test]
    fn test_set_ids_some() {
        let effective_caps = crate::caps::CapState::get_current().unwrap().effective;

        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        if effective_caps.has(crate::caps::Cap::SETUID)
            && effective_caps.has(crate::caps::Cap::SETGID)
        {
            cap_set_ids(Some(uid), Some(gid), None).unwrap();
        } else {
            assert_eq!(
                cap_set_ids(Some(uid), Some(gid), None)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
        }
    }
}
