#[cfg(not(feature = "sc"))]
extern "C" {
    pub fn capget(hdrp: *mut cap_user_header_t, datap: *mut cap_user_data_t) -> libc::c_int;

    pub fn capset(hdrp: *mut cap_user_header_t, datap: *const cap_user_data_t) -> libc::c_int;
}

#[repr(C)]
pub struct cap_user_header_t {
    pub version: u32,
    pub pid: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct cap_user_data_t {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

// WARNING: Updating to newer versions may require significant
// code changes to caps/capstate.rs
pub const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

pub const PR_SET_PTRACER_ANY: libc::c_ulong = -1i32 as libc::c_ulong;

pub const PR_GET_SPECULATION_CTRL: libc::c_int = 52;
pub const PR_SET_SPECULATION_CTRL: libc::c_int = 53;

pub const PR_SPEC_STORE_BYPASS: libc::c_int = 0;
pub const PR_SPEC_INDIRECT_BRANCH: libc::c_int = 1;
pub const PR_SPEC_L1D_FLUSH: libc::c_int = 2;

pub const PR_SPEC_PRCTL: libc::c_int = 1 << 0;
pub const PR_SPEC_ENABLE: libc::c_int = 1 << 1;
pub const PR_SPEC_DISABLE: libc::c_int = 1 << 2;
pub const PR_SPEC_FORCE_DISABLE: libc::c_int = 1 << 3;
pub const PR_SPEC_DISABLE_NOEXEC: libc::c_int = 1 << 4;

pub const PR_SET_IO_FLUSHER: libc::c_int = 57;
pub const PR_GET_IO_FLUSHER: libc::c_int = 58;

pub const PR_SET_MDWE: libc::c_int = 65;
pub const PR_GET_MDWE: libc::c_int = 66;

pub const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_int = 1;

// File capabilities constants
#[cfg(feature = "std")]
mod file {
    pub const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x00_0001;

    pub const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
    pub const VFS_CAP_FLAGS_MASK: u32 = !VFS_CAP_REVISION_MASK;

    pub const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
    pub const XATTR_CAPS_SZ_1: usize = 12;
    pub const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
    pub const XATTR_CAPS_SZ_2: usize = 20;
    pub const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
    pub const XATTR_CAPS_SZ_3: usize = 24;

    pub const XATTR_CAPS_MAX_SIZE: usize = XATTR_CAPS_SZ_3;

    pub const XATTR_NAME_CAPS: &[u8] = b"security.capability\0";
}

#[cfg(feature = "std")]
pub use file::*;
