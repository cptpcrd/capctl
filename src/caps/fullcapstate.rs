use std::fs;
use std::io;
use std::io::prelude::*;

use super::{ambient, bounding, CapSet, CapState};

/// Represents the "full" capability state of a thread (i.e. the contents of all 5 capability
/// sets).
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct FullCapState {
    pub permitted: CapSet,
    pub effective: CapSet,
    pub inheritable: CapSet,
    pub ambient: CapSet,
    pub bounding: CapSet,
}

impl FullCapState {
    /// Construct an empty `FullCapState` object.
    pub fn empty() -> Self {
        Self {
            permitted: CapSet::empty(),
            effective: CapSet::empty(),
            inheritable: CapSet::empty(),
            ambient: CapSet::empty(),
            bounding: CapSet::empty(),
        }
    }

    /// Get the full capability state of the current thread.
    ///
    /// This is equivalent to `FullCapState::get_for_pid(0)`. However,
    pub fn get_current() -> io::Result<Self> {
        let state = CapState::get_current()?;

        Ok(Self {
            permitted: state.permitted,
            effective: state.effective,
            inheritable: state.inheritable,
            ambient: ambient::probe().unwrap_or_default(),
            bounding: bounding::probe(),
        })
    }

    /// Get the full capability state of the process (or thread) with the given PID (or TID) by
    /// examining special files in `/proc`.
    ///
    /// If `pid` is 0, this method gets the capability state of the current thread.
    pub fn get_for_pid(mut pid: libc::pid_t) -> io::Result<Self> {
        match pid.cmp(&0) {
            std::cmp::Ordering::Less => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            std::cmp::Ordering::Equal => {
                pid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t
            }
            std::cmp::Ordering::Greater => (),
        }

        let f = match fs::File::open(format!("/proc/{}/status", pid)) {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                return Err(io::Error::from_raw_os_error(libc::ESRCH))
            }
            Err(e) => return Err(e),
        };

        let mut reader = io::BufReader::new(f);

        let mut line = String::new();

        let mut res = Self {
            permitted: CapSet::empty(),
            effective: CapSet::empty(),
            inheritable: CapSet::empty(),
            ambient: CapSet::empty(),
            bounding: CapSet::empty(),
        };

        while reader.read_line(&mut line)? > 0 {
            if line.ends_with('\n') {
                line.pop();
            }

            if let Some(i) = line.find(":\t") {
                let set = match &line[..i] {
                    "CapPrm" => &mut res.permitted,
                    "CapEff" => &mut res.effective,
                    "CapInh" => &mut res.inheritable,
                    "CapBnd" => &mut res.bounding,
                    "CapAmb" => &mut res.ambient,
                    _ => {
                        line.clear();
                        continue;
                    }
                };

                if line.len() > i + 2 {
                    match u64::from_str_radix(&line[i + 2..], 16) {
                        Ok(bitmask) => *set = CapSet::from_bitmask_truncate(bitmask),
                        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                    }
                }
            }

            line.clear();
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_proc() {
        assert_eq!(
            FullCapState::get_current().unwrap(),
            FullCapState::get_for_pid(0).unwrap(),
        );

        assert_eq!(
            FullCapState::get_current().unwrap(),
            FullCapState::get_for_pid(std::process::id() as libc::pid_t).unwrap(),
        );
    }

    #[test]
    fn test_get_invalid_pid() {
        assert_eq!(
            FullCapState::get_for_pid(-1).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );

        assert_eq!(
            FullCapState::get_for_pid(libc::pid_t::MAX)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
