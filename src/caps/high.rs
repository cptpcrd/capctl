use super::{ambient, bounding, Cap, CapSet, CapState};
use crate::{Error, Result};

#[inline]
fn einval() -> Error {
    Error::from_code(libc::EINVAL)
}

#[inline]
fn enotsup() -> Error {
    Error::from_code(libc::ENOTSUP)
}

/// Helper method that tries to lower the given capability in the ambient set, but ignores errors
/// indicating that the capability is not supported.
#[inline]
fn ambient_lower(cap: Cap) -> Result<()> {
    match ambient::lower(cap) {
        // Unsupported capability -> always succeed
        Err(e) if e.code() == libc::EINVAL => Ok(()),
        // Either successful or encountered a different error
        res => res,
    }
}

/// Helper method that tries to drop the given capability from the bounding set, but will ignore
/// errors if the capability is already lowered or is not supported by the running kernel.
fn bounding_drop(cap: Cap) -> Result<()> {
    match bounding::drop(cap) {
        Err(e) if e.code() == libc::EPERM => match bounding::read(cap) {
            // The capability is currently raised and we don't have permission to lower it.
            // Pass up the error.
            Some(true) => Err(e),

            // Either:
            // 1. The result is `Some(false)`, which means the capability is already lowered.
            //    So the kernel is denying access because we don't have CAP_SETPCAP, but
            //    everything is in the state we want.
            // 2. The result is `None`, which means the capability is not supported by the
            //    running kernel. Since we were told to *lower* it, we can safely ignore that.
            _ => Ok(()),
        },

        // Unsupported capability -> nothing to do
        Err(e) if e.code() == libc::EINVAL => Ok(()),
        // Either successful or a different error
        res => res,
    }
}

/// Represents one of the 5 capability sets that a process has.
///
/// This enum provides a unified, high-level API for manipulating all 5 capability sets. It is only
/// recommended for simple operations (i.e. dropping a single capability from a capability set and
/// then re-adding it); for anything complicated the low-level APIs may be more efficient.
///
/// # Handling of unsupported capabilities
///
/// If a capability is not supported by the kernel:
///
/// - Checking if it is present using [`has()`] or [`has_caps()`] (in any of the sets) will always
///   return `Ok(false)`.
/// - Trying to lower it using [`lower()`], [`lower_caps()`], or [`replace()`] (in any of the sets)
///   will always return `Ok(())` (since it isn't supported, it is effectively *already* lowered).
/// - Trying to raise it in the *ambient* set using [`raise()`], [`raise_caps()`] or [`replace()`]
///   will fail with EINVAL.
/// - Trying to raise it in the permitted, effective, or inheritable sets using [`raise()`],
///   [`raise_caps()`] or [`replace()`] will silently fail (i.e. return `Ok(())` but not actually
///   change anything). This is due to a limitation in the kernel API; if you need to ensure that
///   it's raised then check using [`has()`] or [`has_caps()`] afterwards.
///
/// # Atomicity Notes
///
/// Performing "bulk" operations ([`raise_caps()`], [`lower_caps()`], and [`replace()`]) on the
/// permitted, effective, and inheritable capability sets is atomic. If an error is
/// encountered, the capability set is left in either the original state or the new one.
///
/// However, performing "bulk" operations on the ambient and bounding capability sets is **not**
/// atomic. If an error occurs (for example, attempting to raise a capability that isn't supported
/// by the kernel), the state of the ambient/bounding set after the call is unspecified and possibly
/// inconsistent. If it is not possible to recover from this, the correct action is to immediately
/// terminate the program.
///
/// [`has()`]: ./fn.has.html
/// [`has_caps()`]: ./fn.has_caps.html
/// [`raise()`]: ./fn.raise.html
/// [`raise_caps()`]: ./fn.raise_caps.html
/// [`lower()`]: ./fn.lower.html
/// [`lower_caps()`]: ./fn.lower_caps.html
/// [`replace()`]: ./fn.replace.html
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum CapSetType {
    Permitted,
    Effective,
    Inheritable,
    Bounding,
    Ambient,
}

impl CapSetType {
    fn get_capset(self) -> Result<CapSet> {
        let capstate = CapState::get_current()?;

        Ok(match self {
            Self::Permitted => capstate.permitted,
            Self::Effective => capstate.effective,
            Self::Inheritable => capstate.inheritable,
            _ => unreachable!(),
        })
    }

    #[inline]
    fn get_capset_mut(self, capstate: &mut CapState) -> &mut CapSet {
        match self {
            Self::Permitted => &mut capstate.permitted,
            Self::Effective => &mut capstate.effective,
            Self::Inheritable => &mut capstate.inheritable,
            _ => unreachable!(),
        }
    }

    /// "Probe" the specified capability set and return the set of all currently raised
    /// capabilities.
    pub fn probe(self) -> Result<CapSet> {
        match self {
            Self::Bounding => Ok(bounding::probe()),
            Self::Ambient => ambient::probe().ok_or_else(einval),
            _ => self.get_capset(),
        }
    }

    /// Check if the specified capability is raised in this capability set.
    pub fn has(self, cap: Cap) -> Result<bool> {
        match self {
            Self::Bounding => Ok(bounding::read(cap) == Some(true)),
            Self::Ambient => Ok(ambient::is_set(cap) == Some(true)),
            _ => Ok(self.get_capset()?.has(cap)),
        }
    }

    /// Check if all of the specified capabilities are raised in this capability set.
    pub fn has_caps(self, caps: CapSet) -> Result<bool> {
        match self {
            Self::Bounding => {
                for cap in caps {
                    if bounding::read(cap) != Some(true) {
                        return Ok(false);
                    }
                }

                Ok(true)
            }

            Self::Ambient => {
                for cap in caps {
                    if ambient::is_set(cap) != Some(true) {
                        return Ok(false);
                    }
                }

                Ok(true)
            }

            _ => Ok(self.get_capset()? & caps == caps),
        }
    }

    /// Raise the specified capability in this capability set.
    ///
    /// Important notes:
    ///
    /// 1. This will always fail for the bounding capability set. By design, capabilities cannot be
    ///    added to the bounding capability set.
    /// 2. Capabilities can only be added to the ambient capability set if they are present in both
    ///    the permitted and inheritable sets.
    /// 3. If the given capability is not supported by the kernel, trying to add it to the ambient
    ///    set will raise an error. However, trying to add it to the permitted, effective, or
    ///    inheritable sets will result in it being ignored.
    ///
    ///    This is a limitation of the kernel APIs. If you *need* to make sure that the capability
    ///    was added properly, check afterwards using [`has()`] or [`has_caps()`].
    ///
    /// [`has()`]: ./fn.has.html
    /// [`has_caps()`]: ./fn.has_caps.html
    pub fn raise(self, cap: Cap) -> Result<()> {
        match self {
            Self::Bounding => Err(enotsup()),
            Self::Ambient => ambient::raise(cap),

            _ => {
                let mut capstate = CapState::get_current()?;
                let capset = self.get_capset_mut(&mut capstate);

                if !capset.has(cap) {
                    capset.add(cap);
                    capstate.set_current()?;
                }

                Ok(())
            }
        }
    }

    /// Raise all of the specified capabilities in this capability set.
    ///
    /// This is equivalent to `for cap in caps { <set>.raise(cap) }`, but it may be more efficient.
    ///
    /// See [Atomicity Notes](#atomicity-notes) and the notes in [`raise()`](#method.raise)'s
    /// documentation.
    pub fn raise_caps(self, caps: CapSet) -> Result<()> {
        match self {
            Self::Bounding => Err(enotsup()),

            Self::Ambient => {
                for cap in caps {
                    ambient::raise(cap)?;
                }
                Ok(())
            }

            _ => {
                let mut capstate = CapState::get_current()?;
                let capset = self.get_capset_mut(&mut capstate);

                let orig_capset = *capset;
                *capset |= caps;
                if *capset != orig_capset {
                    capstate.set_current()?;
                }

                Ok(())
            }
        }
    }

    /// Lower the specified capability in this capability set.
    ///
    /// For all 3 capability sets, this method will always return `Ok(())` if **any** of the
    /// following conditions are true:
    ///
    /// 1. The specified capability is not currently raised.
    /// 2. The specified capability is not supported by the running kernel.
    /// 3. This capability **set** is not supported by the running kernel.
    pub fn lower(self, cap: Cap) -> Result<()> {
        match self {
            Self::Bounding => bounding_drop(cap),
            Self::Ambient => ambient_lower(cap),

            _ => {
                let mut capstate = CapState::get_current()?;
                let capset = self.get_capset_mut(&mut capstate);

                if capset.has(cap) {
                    capset.drop(cap);
                    capstate.set_current()?;
                }

                Ok(())
            }
        }
    }

    /// Lower all of the specified capabilities in this capability set.
    ///
    /// This is equivalent to `for cap in caps { <set>.lower(cap) }`, but it may be more efficient.
    ///
    /// See [Atomicity Notes](#atomicity-notes) and the notes in [`lower()`](#method.lower)'s
    /// documentation.
    pub fn lower_caps(self, caps: CapSet) -> Result<()> {
        match self {
            Self::Bounding => {
                for cap in caps {
                    bounding_drop(cap)?;
                }
                Ok(())
            }

            Self::Ambient => {
                for cap in caps {
                    ambient_lower(cap)?;
                }
                Ok(())
            }

            _ => {
                let mut capstate = CapState::get_current()?;
                let capset = self.get_capset_mut(&mut capstate);

                let orig_capset = *capset;
                *capset &= !caps;
                if *capset != orig_capset {
                    capstate.set_current()?;
                }

                Ok(())
            }
        }
    }

    /// Replace this capability set with the given capability set.
    ///
    /// This is equivalent to raising all of the capabilities in `caps` and lowering all of the
    /// capabilities not in `caps`. However, it may be more efficient.
    ///
    /// If the given capability set is identical to the current capability set, this method will
    /// always return `Ok(())`.
    ///
    /// When this method is used to try to add capabilities to this capability set, all of the
    /// notes in [`raise()`](#method.raise)'s documentation apply. When it is used to try to drop
    /// capabilities from this capability set, all of the notes in [`lower()`](#method.lower)
    /// apply.
    ///
    /// See also [Atomicity Notes](#atomicity-notes).
    pub fn replace(self, caps: CapSet) -> Result<()> {
        match self {
            Self::Bounding => {
                for cap in Cap::iter() {
                    if caps.has(cap) {
                        match bounding::read(cap) {
                            Some(true) => (),
                            Some(false) => return Err(enotsup()),
                            None => return Err(einval()),
                        }
                    } else {
                        bounding_drop(cap)?;
                    }
                }

                Ok(())
            }

            Self::Ambient => {
                for cap in Cap::iter() {
                    if caps.has(cap) {
                        ambient::raise(cap)?;
                    } else {
                        ambient_lower(cap)?;
                    }
                }

                Ok(())
            }

            _ => {
                let mut capstate = CapState::get_current()?;
                let capset = self.get_capset_mut(&mut capstate);

                if *capset != caps {
                    *capset = caps;
                    capstate.set_current()?;
                }

                Ok(())
            }
        }
    }

    /// Clear the specified capability set, removing all capabilities.
    pub fn clear(self) -> Result<()> {
        match self {
            Self::Ambient => ambient::clear(),
            _ => self.lower_caps(!CapSet::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::caps::{ambient, bounding, Cap, CapState};
    use crate::capset;

    const SET_TYPES: [CapSetType; 5] = [
        CapSetType::Ambient,
        CapSetType::Bounding,
        CapSetType::Permitted,
        CapSetType::Inheritable,
        CapSetType::Effective,
    ];

    #[test]
    fn test_replace_same() {
        for set in SET_TYPES.iter() {
            set.replace(set.probe().unwrap()).unwrap();
        }
    }

    #[test]
    fn test_probe_consistent() {
        assert_eq!(
            CapSetType::Ambient.probe().unwrap(),
            ambient::probe().unwrap(),
        );
        assert_eq!(CapSetType::Bounding.probe().unwrap(), bounding::probe());

        let capstate = CapState::get_current().unwrap();

        assert_eq!(CapSetType::Permitted.probe().unwrap(), capstate.permitted);
        assert_eq!(
            CapSetType::Inheritable.probe().unwrap(),
            capstate.inheritable,
        );
        assert_eq!(CapSetType::Effective.probe().unwrap(), capstate.effective);
    }

    #[test]
    fn test_has_consistent() {
        let capstate = CapState::get_current().unwrap();

        for cap in Cap::iter() {
            match ambient::is_set(cap) {
                Some(res) => {
                    assert_eq!(res, CapSetType::Ambient.has(cap).unwrap());
                    assert_eq!(res, CapSetType::Ambient.has_caps(capset!(cap)).unwrap());
                }
                None => {
                    assert!(!CapSetType::Ambient.has(cap).unwrap());
                    assert!(!CapSetType::Ambient.has_caps(capset!(cap)).unwrap());
                }
            }

            match bounding::read(cap) {
                Some(res) => {
                    assert_eq!(res, CapSetType::Bounding.has(cap).unwrap());
                    assert_eq!(res, CapSetType::Bounding.has_caps(capset!(cap)).unwrap());
                }
                None => {
                    assert!(!CapSetType::Bounding.has(cap).unwrap());
                    assert!(!CapSetType::Bounding.has_caps(capset!(cap)).unwrap());
                }
            }

            assert_eq!(
                capstate.effective.has(cap),
                CapSetType::Effective.has(cap).unwrap()
            );
            assert_eq!(
                capstate.effective.has(cap),
                CapSetType::Effective.has_caps(capset!(cap)).unwrap()
            );

            assert_eq!(
                capstate.inheritable.has(cap),
                CapSetType::Inheritable.has(cap).unwrap()
            );
            assert_eq!(
                capstate.inheritable.has(cap),
                CapSetType::Inheritable.has_caps(capset!(cap)).unwrap()
            );

            assert_eq!(
                capstate.permitted.has(cap),
                CapSetType::Permitted.has(cap).unwrap()
            );
            assert_eq!(
                capstate.permitted.has(cap),
                CapSetType::Permitted.has_caps(capset!(cap)).unwrap()
            );
        }
    }

    #[test]
    fn test_alter_ambient() {
        CapSetType::Ambient.raise_caps(capset!()).unwrap();
    }

    #[test]
    fn test_clear() {
        for set in [
            CapSetType::Ambient,
            CapSetType::Permitted,
            CapSetType::Inheritable,
            CapSetType::Effective,
        ]
        .iter()
        {
            set.clear().unwrap();
            assert!(set.probe().unwrap().is_empty());
        }
    }

    #[test]
    fn test_raise_bounding() {
        // Trying to raise a capability in the bounding set will raise ENOTSUP
        assert_eq!(
            CapSetType::Bounding.raise(Cap::CHOWN).unwrap_err().code(),
            libc::ENOTSUP,
        );

        assert_eq!(
            CapSetType::Bounding
                .raise_caps(capset!(Cap::CHOWN))
                .unwrap_err()
                .code(),
            libc::ENOTSUP,
        );
    }

    #[test]
    fn test_not_supported() {
        for cap in !Cap::probe_supported() {
            // Trying to raise an unsupported capability in the ambient set will
            // raise an error

            assert_eq!(
                CapSetType::Ambient.raise(cap).unwrap_err().code(),
                libc::EINVAL,
            );

            assert_eq!(
                CapSetType::Ambient
                    .raise_caps(capset!(cap))
                    .unwrap_err()
                    .code(),
                libc::EINVAL,
            );

            // Try adding it to the ambient set multiple ways

            let mut caps = CapSetType::Ambient.probe().unwrap();
            caps.add(cap);
            assert_eq!(
                CapSetType::Ambient.replace(caps).unwrap_err().code(),
                libc::EINVAL,
            );

            // Trying to "raise" an unsupported capability in the bounding set using replace() will
            // raise an error
            caps = CapSetType::Bounding.probe().unwrap();
            caps.add(cap);
            assert_eq!(
                CapSetType::Bounding.replace(caps).unwrap_err().code(),
                libc::EINVAL,
            );

            // Trying to raise an unknown capability in the permitted/effective/inheritable sets
            // will silently fail
            CapSetType::Permitted.raise(cap).unwrap();
            CapSetType::Permitted.raise_caps(capset!(cap)).unwrap();
            CapSetType::Effective.raise(cap).unwrap();
            CapSetType::Effective.raise_caps(capset!(cap)).unwrap();
            CapSetType::Inheritable.raise(cap).unwrap();
            CapSetType::Inheritable.raise_caps(capset!(cap)).unwrap();

            for set in SET_TYPES.iter() {
                // Trying to lower an unsupported capability is a no-op
                set.lower(cap).unwrap();
                set.lower_caps(capset!(cap)).unwrap();
            }
        }
    }

    #[test]
    fn test_drop_bounding() {
        CapSetType::Effective.lower(Cap::SETPCAP).unwrap();

        for cap in CapSetType::Bounding.probe().unwrap() {
            assert_eq!(
                CapSetType::Bounding.lower(cap).unwrap_err().code(),
                libc::EPERM
            );
        }
    }
}
