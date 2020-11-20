use std::io;

use super::CapSet;

/// Represents the permitted, effective, and inheritable capability sets of a thread.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapState {
    pub effective: CapSet,
    pub permitted: CapSet,
    pub inheritable: CapSet,
}

impl CapState {
    /// Construct an empty `CapState` object.
    #[inline]
    pub fn empty() -> Self {
        Self {
            effective: CapSet::empty(),
            permitted: CapSet::empty(),
            inheritable: CapSet::empty(),
        }
    }

    /// Get the capability state of the current thread.
    ///
    /// This is equivalent to `CapState::get_for_pid(0)`.
    #[inline]
    pub fn get_current() -> io::Result<Self> {
        Self::get_for_pid(0)
    }

    /// Get the capability state of the process (or thread) with the given PID (or TID).
    ///
    /// If `pid` is 0, this method gets the capability state of the current thread.
    pub fn get_for_pid(pid: libc::pid_t) -> io::Result<Self> {
        let mut header = crate::externs::cap_user_header_t {
            version: crate::constants::_LINUX_CAPABILITY_VERSION_3,
            pid: pid as libc::c_int,
        };

        let mut raw_dat = [crate::externs::cap_user_data_t {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];

        if unsafe { crate::externs::capget(&mut header, raw_dat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            effective: CapSet::from_bitmasks_u32(raw_dat[0].effective, raw_dat[1].effective),
            permitted: CapSet::from_bitmasks_u32(raw_dat[0].permitted, raw_dat[1].permitted),
            inheritable: CapSet::from_bitmasks_u32(raw_dat[0].inheritable, raw_dat[1].inheritable),
        })
    }

    /// Set the current capability state to the state represented by this object.
    pub fn set_current(&self) -> io::Result<()> {
        let mut header = crate::externs::cap_user_header_t {
            version: crate::constants::_LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };

        let effective = self.effective.bits;
        let permitted = self.permitted.bits;
        let inheritable = self.inheritable.bits;

        let raw_dat = [
            crate::externs::cap_user_data_t {
                effective: effective as u32,
                permitted: permitted as u32,
                inheritable: inheritable as u32,
            },
            crate::externs::cap_user_data_t {
                effective: (effective >> 32) as u32,
                permitted: (permitted >> 32) as u32,
                inheritable: (inheritable >> 32) as u32,
            },
        ];

        if unsafe { crate::externs::capset(&mut header, raw_dat.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capstate_empty() {
        assert_eq!(
            CapState::empty(),
            CapState {
                effective: CapSet::empty(),
                permitted: CapSet::empty(),
                inheritable: CapSet::empty(),
            }
        );
    }

    #[test]
    fn test_capstate_getset_current() {
        let state = CapState::get_current().unwrap();
        assert_eq!(state, CapState::get_for_pid(0).unwrap());
        assert_eq!(
            state,
            CapState::get_for_pid(std::process::id() as libc::pid_t).unwrap()
        );
        state.set_current().unwrap();
    }

    #[test]
    fn test_capstate_get_bad_pid() {
        assert_eq!(
            CapState::get_for_pid(-1).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            CapState::get_for_pid(libc::pid_t::MAX)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
