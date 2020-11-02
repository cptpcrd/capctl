use std::convert::TryInto;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::io;
use std::iter::FromIterator;
use std::ops::{BitAnd, BitOr, BitXor, Not, Sub};
use std::os::unix::prelude::*;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum Cap {
    CHOWN = 0,
    DAC_OVERRIDE = 1,
    DAC_READ_SEARCH = 2,
    FOWNER = 3,
    FSETID = 4,
    KILL = 5,
    SETGID = 6,
    SETUID = 7,
    SETPCAP = 8,
    LINUX_IMMUTABLE = 9,
    NET_BIND_SERVICE = 10,
    NET_BROADCAST = 11,
    NET_ADMIN = 12,
    NET_RAW = 13,
    IPC_LOCK = 14,
    IPC_OWNER = 15,
    SYS_MODULE = 16,
    SYS_RAWIO = 17,
    SYS_CHROOT = 18,
    SYS_PTRACE = 19,
    SYS_PACCT = 20,
    SYS_ADMIN = 21,
    SYS_BOOT = 22,
    SYS_NICE = 23,
    SYS_RESOURCE = 24,
    SYS_TIME = 25,
    SYS_TTY_CONFIG = 26,
    MKNOD = 27,
    LEASE = 28,
    AUDIT_WRITE = 29,
    AUDIT_CONTROL = 30,
    SETFCAP = 31,
    MAC_OVERRIDE = 32,
    MAC_ADMIN = 33,
    SYSLOG = 34,
    WAKE_ALARM = 35,
    BLOCK_SUSPEND = 36,
    AUDIT_READ = 37,
    PERFMON = 38,
    BPF = 39,
    CHECKPOINT_RESTORE = 40,
    // Note: When adding a new capability, make sure to update LAST_CAP and CAPS_BY_NAME
}

// *** WARNING WARNING WARNING ***
// This MUST be set to the last capability from the above list!
// This assumption is used by unsafe code to speed up checks.
const LAST_CAP: Cap = Cap::CHECKPOINT_RESTORE;

// Some other useful values derived from LAST_CAP
const CAP_MAX: u8 = LAST_CAP as u8;
const NUM_CAPS: u8 = CAP_MAX + 1;
// Shift to the left, then subtract one to get the lower bits filled with ones.
const CAP_BITMASK: u64 = ((1 as u64) << NUM_CAPS) - 1;

static CAPS_BY_NAME: [(&str, Cap); NUM_CAPS as usize] = [
    ("CHOWN", Cap::CHOWN),
    ("DAC_OVERRIDE", Cap::DAC_OVERRIDE),
    ("DAC_READ_SEARCH", Cap::DAC_READ_SEARCH),
    ("FOWNER", Cap::FOWNER),
    ("FSETID", Cap::FSETID),
    ("KILL", Cap::KILL),
    ("SETGID", Cap::SETGID),
    ("SETUID", Cap::SETUID),
    ("SETPCAP", Cap::SETPCAP),
    ("LINUX_IMMUTABLE", Cap::LINUX_IMMUTABLE),
    ("NET_BIND_SERVICE", Cap::NET_BIND_SERVICE),
    ("NET_BROADCAST", Cap::NET_BROADCAST),
    ("NET_ADMIN", Cap::NET_ADMIN),
    ("NET_RAW", Cap::NET_RAW),
    ("IPC_LOCK", Cap::IPC_LOCK),
    ("IPC_OWNER", Cap::IPC_OWNER),
    ("SYS_MODULE", Cap::SYS_MODULE),
    ("SYS_RAWIO", Cap::SYS_RAWIO),
    ("SYS_CHROOT", Cap::SYS_CHROOT),
    ("SYS_PTRACE", Cap::SYS_PTRACE),
    ("SYS_PACCT", Cap::SYS_PACCT),
    ("SYS_ADMIN", Cap::SYS_ADMIN),
    ("SYS_BOOT", Cap::SYS_BOOT),
    ("SYS_NICE", Cap::SYS_NICE),
    ("SYS_RESOURCE", Cap::SYS_RESOURCE),
    ("SYS_TIME", Cap::SYS_TIME),
    ("SYS_TTY_CONFIG", Cap::SYS_TTY_CONFIG),
    ("MKNOD", Cap::MKNOD),
    ("LEASE", Cap::LEASE),
    ("AUDIT_WRITE", Cap::AUDIT_WRITE),
    ("AUDIT_CONTROL", Cap::AUDIT_CONTROL),
    ("SETFCAP", Cap::SETFCAP),
    ("MAC_OVERRIDE", Cap::MAC_OVERRIDE),
    ("MAC_ADMIN", Cap::MAC_ADMIN),
    ("SYSLOG", Cap::SYSLOG),
    ("WAKE_ALARM", Cap::WAKE_ALARM),
    ("BLOCK_SUSPEND", Cap::BLOCK_SUSPEND),
    ("AUDIT_READ", Cap::AUDIT_READ),
    ("PERFMON", Cap::PERFMON),
    ("BPF", Cap::BPF),
    ("CHECKPOINT_RESTORE", Cap::CHECKPOINT_RESTORE),
];

impl Cap {
    #[inline]
    pub fn iter() -> CapIter {
        CapIter { i: 0 }
    }

    #[inline]
    fn from_u8(val: u8) -> Option<Self> {
        if val <= CAP_MAX {
            Some(unsafe { std::mem::transmute(val) })
        } else {
            None
        }
    }

    #[inline]
    fn to_single_bitfield(self) -> u64 {
        // Sanity check in case CAP_MAX gets set incorrectly
        // Note that this still won't catch certain cases
        debug_assert!((self as u8) <= CAP_MAX);

        (1 as u64) << (self as u8)
    }

    /// Checks whether the specified capability is supported on the current kernel.
    pub fn is_supported(self) -> bool {
        bounding::read(self).is_some()
    }

    /// Determines the set of capabilities supported by the running kernel.
    ///
    /// This uses a binary search combined with [`Cap::is_supported()`] to determine the supported
    /// capabilities. It is more efficient than a simple `Cap::iter()`/`Cap::is_supported()` loop.
    ///
    /// [`Cap::is_supported()`]: #method.is_supported
    pub fn probe_supported() -> CapSet {
        // Do a binary search

        let mut min = 0;
        let mut max = CAP_MAX;

        while min != max {
            // This basically does `mid = ceil((min + max) / 2)`.
            // If we don't do ceiling division, the way binary search works, we'll get stuck at
            // `max = min + 1` forever.
            let sum = min + max;
            let mid = (sum >> 1) + (sum & 1);

            if Self::from_u8(mid).unwrap().is_supported() {
                min = mid;
            } else {
                max = mid - 1;
            }
        }

        CapSet::from_bitmask_truncate((1 << (min + 1)) - 1)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ParseCapError(());

impl fmt::Debug for ParseCapError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unknown capability")
    }
}

impl fmt::Display for ParseCapError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::str::FromStr for Cap {
    type Err = ParseCapError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 4 && s[..4].eq_ignore_ascii_case("CAP_") {
            let s = &s[4..];

            for (cap_name, cap) in CAPS_BY_NAME.iter() {
                if cap_name.eq_ignore_ascii_case(s) {
                    return Ok(*cap);
                }
            }
        }

        Err(ParseCapError(()))
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CAP_")?;
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone)]
pub struct CapIter {
    i: u8,
}

impl Iterator for CapIter {
    type Item = Cap;

    fn next(&mut self) -> Option<Cap> {
        debug_assert!(self.i <= NUM_CAPS);

        let res = Cap::from_u8(self.i);
        if res.is_some() {
            self.i += 1;
        }
        res
    }

    fn nth(&mut self, n: usize) -> Option<Cap> {
        if n < self.len() {
            self.i += n as u8;
            self.next()
        } else {
            // The specified index would exhaust the iterator
            self.i = NUM_CAPS;
            None
        }
    }

    #[inline]
    fn last(self) -> Option<Cap> {
        if self.i < NUM_CAPS {
            Some(LAST_CAP)
        } else {
            None
        }
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

impl ExactSizeIterator for CapIter {
    #[inline]
    fn len(&self) -> usize {
        debug_assert!(self.i <= NUM_CAPS);
        (NUM_CAPS - self.i) as usize
    }
}

impl std::iter::FusedIterator for CapIter {}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct CapSet {
    bits: u64,
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

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapState {
    pub effective: CapSet,
    pub permitted: CapSet,
    pub inheritable: CapSet,
}

impl CapState {
    #[inline]
    pub fn get_current() -> io::Result<Self> {
        Self::get_for_pid(0)
    }

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

        if unsafe { crate::externs::capget(&mut header, &mut raw_dat[0]) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            effective: CapSet::from_bitmask_truncate(combine_raw_u32s(
                raw_dat[0].effective,
                raw_dat[1].effective,
            )),
            permitted: CapSet::from_bitmask_truncate(combine_raw_u32s(
                raw_dat[0].permitted,
                raw_dat[1].permitted,
            )),
            inheritable: CapSet::from_bitmask_truncate(combine_raw_u32s(
                raw_dat[0].inheritable,
                raw_dat[1].inheritable,
            )),
        })
    }

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

        if unsafe { crate::externs::capset(&mut header, &raw_dat[0]) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

#[inline]
const fn combine_raw_u32s(lower: u32, upper: u32) -> u64 {
    ((upper as u64) << 32) + (lower as u64)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileCaps {
    pub effective: bool,
    pub permitted: CapSet,
    pub inheritable: CapSet,
    pub rootid: Option<libc::uid_t>,
}

impl FileCaps {
    pub fn empty() -> Self {
        Self {
            effective: false,
            permitted: CapSet::empty(),
            inheritable: CapSet::empty(),
            rootid: None,
        }
    }

    pub fn get_for_file<P: AsRef<OsStr>>(path: P) -> io::Result<Option<Self>> {
        let mut data = [0; crate::constants::XATTR_CAPS_MAX_SIZE];

        let path = CString::new(path.as_ref().as_bytes())?;

        let ret = unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                crate::constants::XATTR_NAME_CAPS.as_ptr() as *const libc::c_char,
                data.as_mut_ptr() as *mut libc::c_void,
                data.len(),
            )
        };

        Self::extract_attr_or_error(&data, ret)
    }

    pub fn get_for_fd(fd: RawFd) -> io::Result<Option<Self>> {
        let mut data = [0; crate::constants::XATTR_CAPS_MAX_SIZE];

        let ret = unsafe {
            libc::fgetxattr(
                fd,
                crate::constants::XATTR_NAME_CAPS.as_ptr() as *const libc::c_char,
                data.as_mut_ptr() as *mut libc::c_void,
                data.len(),
            )
        };

        Self::extract_attr_or_error(&data, ret)
    }

    fn extract_attr_or_error(data: &[u8], attr_res: isize) -> io::Result<Option<Self>> {
        if attr_res >= 0 {
            Ok(Some(Self::unpack_attrs(&data[..(attr_res as usize)])?))
        } else {
            let err = io::Error::last_os_error();

            if err.raw_os_error() == Some(libc::ENODATA) {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }

    pub fn unpack_attrs(attrs: &[u8]) -> io::Result<Self> {
        let len = attrs.len();

        if len < 4 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let magic = u32::from_le_bytes(attrs[0..4].try_into().unwrap());
        let version = magic & crate::constants::VFS_CAP_REVISION_MASK;
        let flags = magic & crate::constants::VFS_CAP_FLAGS_MASK;

        let effective = (flags & crate::constants::VFS_CAP_FLAGS_EFFECTIVE) != 0;

        if version == crate::constants::VFS_CAP_REVISION_2
            && len == crate::constants::XATTR_CAPS_SZ_2
        {
            Ok(FileCaps {
                effective,
                permitted: CapSet::from_bitmask_truncate(combine_raw_u32s(
                    u32::from_le_bytes(attrs[4..8].try_into().unwrap()),
                    u32::from_le_bytes(attrs[12..16].try_into().unwrap()),
                )),
                inheritable: CapSet::from_bitmask_truncate(combine_raw_u32s(
                    u32::from_le_bytes(attrs[8..12].try_into().unwrap()),
                    u32::from_le_bytes(attrs[16..20].try_into().unwrap()),
                )),
                rootid: None,
            })
        } else if version == crate::constants::VFS_CAP_REVISION_3
            && len == crate::constants::XATTR_CAPS_SZ_3
        {
            Ok(FileCaps {
                effective,
                permitted: CapSet::from_bitmask_truncate(combine_raw_u32s(
                    u32::from_le_bytes(attrs[4..8].try_into().unwrap()),
                    u32::from_le_bytes(attrs[12..16].try_into().unwrap()),
                )),
                inheritable: CapSet::from_bitmask_truncate(combine_raw_u32s(
                    u32::from_le_bytes(attrs[8..12].try_into().unwrap()),
                    u32::from_le_bytes(attrs[16..20].try_into().unwrap()),
                )),
                rootid: Some(u32::from_le_bytes(attrs[20..24].try_into().unwrap())),
            })
        } else if version == crate::constants::VFS_CAP_REVISION_1
            && len == crate::constants::XATTR_CAPS_SZ_1
        {
            Ok(FileCaps {
                effective,
                permitted: CapSet::from_bitmask_truncate(u32::from_le_bytes(
                    attrs[4..8].try_into().unwrap(),
                ) as u64),
                inheritable: CapSet::from_bitmask_truncate(u32::from_le_bytes(
                    attrs[8..12].try_into().unwrap(),
                ) as u64),
                rootid: None,
            })
        } else {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
    }
}

pub mod ambient {
    use std::io;

    use super::{Cap, CapSet};

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

    #[inline]
    pub fn is_set(cap: Cap) -> Option<bool> {
        match unsafe {
            crate::raw_prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
                cap as libc::c_ulong,
                0,
                0,
            )
        } {
            Ok(x) => Some(x != 0),
            Err(_) => None,
        }
    }

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

    #[inline]
    pub fn is_supported() -> bool {
        is_set(Cap::CHOWN).is_some()
    }

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
}

pub mod bounding {
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
            unsafe { crate::raw_prctl_opt(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0)? }
                != 0,
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
}

#[cfg(test)]
mod tests {
    use std::os::unix::prelude::*;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_cap_string() {
        assert_eq!(Cap::from_str("CAP_CHOWN"), Ok(Cap::CHOWN));
        assert_eq!(Cap::from_str("cap_CHOWN"), Ok(Cap::CHOWN));
        assert_eq!(Cap::from_str("Cap_CHOWN"), Ok(Cap::CHOWN));

        assert_eq!(Cap::from_str("CAP_sys_chroot"), Ok(Cap::SYS_CHROOT));
        assert_eq!(Cap::from_str("cap_sys_chroot"), Ok(Cap::SYS_CHROOT));
        assert_eq!(Cap::from_str("Cap_Sys_chroot"), Ok(Cap::SYS_CHROOT));

        assert!(Cap::from_str("").is_err());
        assert!(Cap::from_str("CAP_").is_err());
        assert!(Cap::from_str("CHOWN").is_err());
        assert!(Cap::from_str("CAP_NOEXIST").is_err());

        assert_eq!(Cap::CHOWN.to_string(), "CAP_CHOWN");

        for cap in Cap::iter() {
            assert_eq!(Cap::from_str(&cap.to_string()), Ok(cap));
        }
    }

    #[test]
    fn test_cap_string_error() {
        let err = ParseCapError(());

        // Make sure clone() and eq() work
        // This will probably be optimized away because it's zero-sized, but it checks that the
        // struct derives Clone and Eq.
        assert_eq!(err, err.clone());

        // Make sure the string representations match
        assert_eq!(err.to_string(), "Unknown capability");
        assert_eq!(format!("{:?}", err), "Unknown capability");
    }

    #[test]
    fn test_cap_iter_last() {
        assert_eq!(Cap::iter().last(), Some(LAST_CAP));

        let mut last = None;
        for cap in Cap::iter() {
            last = Some(cap);
        }
        assert_eq!(last, Some(LAST_CAP));

        let mut it = Cap::iter();
        for _ in it.by_ref() {}
        assert_eq!(it.len(), 0);
        assert_eq!(it.last(), None);
    }

    #[allow(clippy::iter_nth_zero)]
    #[test]
    fn test_cap_iter_nth() {
        let mut it = Cap::iter();
        while let Some(cap) = it.clone().next() {
            assert_eq!(cap, it.nth(0).unwrap());
        }
        assert_eq!(it.nth(0), None);

        assert_eq!(Cap::iter().nth(0), Some(Cap::CHOWN));
        assert_eq!(Cap::iter().nth(1), Some(Cap::DAC_OVERRIDE));
        assert_eq!(Cap::iter().nth(NUM_CAPS as usize - 1), Some(LAST_CAP));
    }

    #[allow(clippy::iter_nth_zero)]
    #[test]
    fn test_cap_iter_fused() {
        let mut it = Cap::iter();
        for _ in it.by_ref() {}

        for _ in 0..256 {
            assert_eq!(it.next(), None);
            assert_eq!(it.nth(0), None);
        }
    }

    #[test]
    fn test_cap_iter_count() {
        let mut it = Cap::iter();

        let mut count = it.len();

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

    #[test]
    fn test_cap_bits() {
        let mut mask: u64 = 0;

        for cap in Cap::iter() {
            let cap_bits = cap.to_single_bitfield();
            assert_eq!(2u64.pow(cap as u32), cap_bits);
            mask |= cap_bits;
        }

        assert_eq!(mask, CAP_BITMASK);
    }

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

    #[test]
    fn test_ambient() {
        ambient::probe().unwrap();
        assert!(ambient::is_supported());
    }

    #[test]
    fn test_bounding() {
        bounding::probe();
        bounding::is_set(Cap::CHOWN).unwrap();
    }

    #[test]
    fn test_probe_supported_caps() {
        let supported_caps = Cap::probe_supported();

        // Check that the binary search worked properly
        for cap in Cap::iter() {
            if supported_caps.has(cap) {
                assert!(cap.is_supported());
            } else {
                assert!(!cap.is_supported());
            }
        }
    }

    #[test]
    fn test_filecaps_empty() {
        let empty_caps = FileCaps::empty();
        assert!(!empty_caps.effective);
        assert!(empty_caps.permitted.is_empty());
        assert!(empty_caps.inheritable.is_empty());
        assert!(empty_caps.rootid.is_none());
    }

    #[test]
    fn test_filecaps_get() {
        let current_exe = std::env::current_exe().unwrap();

        FileCaps::get_for_file(&current_exe).unwrap();

        let f = std::fs::File::open(&current_exe).unwrap();
        FileCaps::get_for_fd(f.as_raw_fd()).unwrap();
    }

    #[test]
    fn test_filecaps_unpack() {
        assert_eq!(
            FileCaps::unpack_attrs(b"").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            FileCaps::unpack_attrs(b"\x00\x00\x00")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            FileCaps::unpack_attrs(b"\x00\x00\x00\x00")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );

        // Version 1
        assert_eq!(
            FileCaps::unpack_attrs(b"\x00\x00\x00\x01\x01\x00\x00\x00\x01\x00\x00\x00").unwrap(),
            FileCaps {
                effective: false,
                permitted: CapSet::from_iter(vec![Cap::CHOWN]),
                inheritable: CapSet::from_iter(vec![Cap::CHOWN]),
                rootid: None,
            },
        );

        // Version 2 (real example, from Wireshark's /usr/bin/dumpcap)
        assert_eq!(
            FileCaps::unpack_attrs(
                b"\x01\x00\x00\x02\x020\x00\x00\x020\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            .unwrap(),
            FileCaps {
                effective: true,
                permitted: CapSet::from_iter(vec![Cap::DAC_OVERRIDE, Cap::NET_ADMIN, Cap::NET_RAW]),
                inheritable: CapSet::from_iter(vec![
                    Cap::DAC_OVERRIDE,
                    Cap::NET_ADMIN,
                    Cap::NET_RAW
                ]),
                rootid: None,
            },
        );

        // Version 3
        assert_eq!(
            FileCaps::unpack_attrs(b"\x01\x00\x00\x03\x020\x00\x00\x020\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00\x00").unwrap(),
            FileCaps {
                effective: true,
                permitted: CapSet::from_iter(vec![Cap::DAC_OVERRIDE, Cap::NET_ADMIN, Cap::NET_RAW]),
                inheritable: CapSet::from_iter(vec![Cap::DAC_OVERRIDE, Cap::NET_ADMIN, Cap::NET_RAW]),
                rootid: Some(1000),
            },
        );
    }
}
