// WARNING: Updating to newer versions may require significant
// code changes to caps/capstate.rs
pub const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

// File capabilities constants
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
