use std::convert::TryInto;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::prelude::*;

use super::util::combine_raw_u32s;
use super::CapSet;

/// Represents the capabilities attached to a file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileCaps {
    pub effective: bool,
    pub permitted: CapSet,
    pub inheritable: CapSet,
    pub rootid: Option<libc::uid_t>,
}

impl FileCaps {
    /// Construct an empty `FileCaps` object.
    pub fn empty() -> Self {
        Self {
            effective: false,
            permitted: CapSet::empty(),
            inheritable: CapSet::empty(),
            rootid: None,
        }
    }

    /// Get the file capabilities attached to the file identified by `path`.
    ///
    /// If an error occurs while retrieving information on the capabilities from the given file,
    /// this method returns `Err(<error>)`. Otherwise, if the given file has no file capabilities
    /// attached, this method returns `Ok(None)`. Otherwise, this method returns
    /// `Ok(Some(<capabilities>))`.
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

    /// Get the file capabilities attached to the open file identified by the file descriptor `fd`.
    ///
    /// See [`get_for_file()`](#method.get_for_file) for more information.
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

    /// From the raw data from the `security.capability` extended attribute of a file, construct a
    /// new `FileCaps` object representing the same data.
    ///
    /// Most users should call [`get_for_file()`] or [`get_for_fd()`]; those methods call this
    /// method internally.
    ///
    /// [`get_for_file()`]: #method.get_for_file
    /// [`get_for_fd()`]: #method.get_for_fd
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

#[cfg(test)]
mod tests {
    use std::iter::FromIterator;

    use super::super::Cap;

    use super::*;

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
